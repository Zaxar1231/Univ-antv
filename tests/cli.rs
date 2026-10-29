//! Проверки собранного бинарника antv.

use std::process::Command;

fn antv() -> Command {
    Command::new(env!("CARGO_BIN_EXE_antv"))
}

#[test]
fn version_flag_prints_version() {
    let output = antv().arg("--version").output().unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn no_arguments_prints_help_and_succeeds() {
    let output = antv().output().unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Usage"));
}

#[test]
fn scanning_missing_path_is_an_error() {
    let output = antv()
        .args(["scan", "/definitely/not/here-antv"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
}

#[cfg(not(windows))]
#[test]
fn programs_is_unsupported_outside_windows() {
    let output = antv().arg("programs").output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Windows"));
}
