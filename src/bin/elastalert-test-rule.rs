//! `elastalert-test-rule ARGS` is `elastalert test-rule ARGS` (the name ElastAlert 2 users know).
use std::os::unix::process::CommandExt;
use std::process::{Command, exit};

fn main() {
    let exe = std::env::current_exe().expect("own path").with_file_name("elastalert");
    let err = Command::new(&exe).arg("test-rule").args(std::env::args_os().skip(1)).exec();
    eprintln!("elastalert-test-rule: cannot run {}: {err}", exe.display());
    exit(1);
}
