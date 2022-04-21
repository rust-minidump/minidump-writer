//! All of these tests are specific to the MacOS task dumper
#![cfg(target_os = "macos")]

use minidump_writer::{mach::LoadCommand, task_dumper::TaskDumper};
use std::fmt::Write;

fn call_otool(args: &[&str]) -> String {
    let mut cmd = std::process::Command::new("otool");
    cmd.args(args);

    let exe_path = std::env::current_exe().expect("unable to retrieve test executable path");
    cmd.arg(exe_path);

    let output = cmd.output().expect("failed to spawn otool");

    assert!(output.status.success());

    String::from_utf8(output.stdout).expect("stdout was invalid utf-8")
}

/// Validates we can iterate the load commands for all of the images in the task
#[test]
fn iterates_load_commands() {
    let lc_str = call_otool(&["-l"]);

    let mut expected = String::new();
    let mut lc_index = 0;

    while let Some(nlc) = lc_str[lc_index..].find("Load command ") {
        lc_index += nlc;

        let block = match lc_str[lc_index + 13..].find("Load command ") {
            Some(ind) => &lc_str[lc_index + 13..lc_index + 13 + ind],
            None => &lc_str[lc_index..],
        };

        let cmd = block
            .find("cmd ")
            .expect("load commnd didn't specify cmd kind");
        let cmd_end = block[cmd + 4..]
            .find('\n')
            .expect("load cmd didn't end with newline");
        if matches!(
            &block[cmd + 4..cmd_end],
            "LC_SEGMENT_64" | "LC_UUID" | "LC_ID_DYLIB"
        ) {
            expected.push_str(block);
        }
    }

    let task_dumper = TaskDumper::new(
        // SAFETY: syscall
        unsafe { mach2::traps::mach_task_self() },
    );

    let mut actual = String::new();
    let images = task_dumper.read_images().expect("failed to read images");

    for img in images {
        let lcmds = task_dumper
            .read_load_commands(&img)
            .expect("failed to read load commands");

        for lc in lcmds.iter() {
            match lc {
                LoadCommand::Segment(seg) => {
                    write!(
                        &mut actual,
                        "
      cmd LC_SEGMENT_64
  cmdsize {}
  segname {}
   vmaddr 0x{:x}
   vmsize 0x{:x}
  fileoff {}
 filesize {}
  maxprot 0x{:x}
 initprot 0x{:x}
   nsects {}
    flags 0x{:x}
",
                        seg.cmd_size,
                        std::str::from_utf8(&seg.segment_name).unwrap(),
                        seg.vm_addr,
                        seg.vm_size,
                        seg.file_off,
                        seg.file_size,
                        seg.max_prot,
                        seg.init_prot,
                        seg.num_sections,
                        seg.flags,
                    )
                    .unwrap();
                }
                LoadCommand::Dylib(_dylib) => {
                    unreachable!()
                }
                LoadCommand::Uuid(uuid) => {
                    let id = uuid::Uuid::from_bytes(uuid.uuid);
                    let mut uuid_buf = [0u8; uuid::fmt::Hyphenated::LENGTH];
                    let uuid_str = id.hyphenated().encode_upper(&mut uuid_buf);

                    write!(
                        &mut actual,
                        "
     cmd LC_UUID
 cmdsize {}
    uuid {uuid_str}
",
                        uuid.cmd_size,
                    )
                    .unwrap();
                }
            }
        }
    }

    similar_asserts::assert_str_eq!(expected, actual);
}
