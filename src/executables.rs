//! Проверка запускаемых файлов перед запуском.

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::process::Command;

use thiserror::Error;

use crate::clam::{FileScanner, ScanStatus};

const EXECUTABLE_SUFFIXES: &[&str] = &[
    "exe", "dll", "msi", "com", "scr", "bat", "cmd", "ps1", "vbs", "js", "jar", "appimage", "sh",
    "py", "pl", "rb",
];

/// Заголовки: PE (MZ), скрипты с шебангом, ELF, Mach-O (оба порядка байт и fat) и Java class.
const EXECUTABLE_MAGIC: &[&[u8]] = &[
    b"MZ",
    b"#!",
    b"\x7fELF",
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
];
const JAVA_CLASS_MAGIC: &[u8] = b"\xca\xfe\xba\xbe";

#[derive(Debug, Error)]
pub enum LaunchError {
    #[error("запуск {path} запрещён: {reason}")]
    Blocked { path: String, reason: String },
    #[error("не удалось запустить программу: {0}")]
    Spawn(#[from] std::io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchVerdict {
    pub allowed: bool,
    pub reason: String,
}

/// Определяет программу по расширению или по заголовку файла.
pub fn is_executable(path: &Path) -> bool {
    let by_suffix = path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| EXECUTABLE_SUFFIXES.contains(&ext.to_ascii_lowercase().as_str()))
        .unwrap_or(false);
    if by_suffix {
        return true;
    }

    let mut header = [0u8; 4];
    let Ok(mut file) = File::open(path) else {
        return false;
    };
    let Ok(read) = file.read(&mut header) else {
        return false;
    };
    let header = &header[..read];
    EXECUTABLE_MAGIC
        .iter()
        .any(|magic| header.starts_with(magic))
        || header.starts_with(JAVA_CLASS_MAGIC)
}

pub fn check_before_launch(path: &Path, clam: &impl FileScanner) -> LaunchVerdict {
    if !path.is_file() {
        return verdict(false, "файл не найден");
    }
    if !is_executable(path) {
        return verdict(false, "файл не похож на программу");
    }

    let results = match clam.scan_files(&[path.to_path_buf()]) {
        Ok(results) => results,
        Err(error) => return verdict(false, &format!("не удалось проверить: {error}")),
    };
    match results.first().map(|result| &result.status) {
        Some(ScanStatus::Clean) => verdict(true, "угроз не найдено"),
        Some(ScanStatus::Infected { signature }) => {
            verdict(false, &format!("обнаружена угроза: {signature}"))
        }
        Some(ScanStatus::Error { message }) => {
            verdict(false, &format!("не удалось проверить: {message}"))
        }
        None => verdict(false, "не удалось проверить: нет результата"),
    }
}

fn verdict(allowed: bool, reason: &str) -> LaunchVerdict {
    LaunchVerdict {
        allowed,
        reason: reason.to_string(),
    }
}

/// Проверяет файл и запускает его только при чистом результате. Возвращает код выхода программы.
pub fn run_checked(
    path: &Path,
    args: &[String],
    clam: &impl FileScanner,
) -> Result<i32, LaunchError> {
    let verdict = check_before_launch(path, clam);
    if !verdict.allowed {
        return Err(LaunchError::Blocked {
            path: path.display().to_string(),
            reason: verdict.reason,
        });
    }
    let status = Command::new(path).args(args).status()?;
    Ok(status.code().unwrap_or(-1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clam::{ClamError, ScanResult, ScanStatus};
    use std::fs;

    struct FixedClam(ScanStatus);

    impl FileScanner for FixedClam {
        fn scan_files(&self, files: &[std::path::PathBuf]) -> Result<Vec<ScanResult>, ClamError> {
            Ok(files
                .iter()
                .map(|path| ScanResult {
                    path: path.clone(),
                    status: self.0.clone(),
                })
                .collect())
        }
    }

    fn temp_file(name: &str, content: &[u8]) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("antv-test-exe-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn detects_executables_by_suffix_and_header() {
        assert!(is_executable(&temp_file("setup.EXE", b"text")));
        assert!(is_executable(&temp_file(
            "renamed.bin",
            b"\x7fELF\x02\x01\x01"
        )));
        assert!(is_executable(&temp_file("renamed.dat", b"MZ\x00\x00")));
        assert!(is_executable(&temp_file("script", b"#!/bin/sh\necho hi\n")));
        assert!(!is_executable(&temp_file("notes.txt", b"hello")));
    }

    #[test]
    fn clean_program_is_allowed() {
        let path = temp_file("app.exe", b"MZ\x00\x00");
        assert!(check_before_launch(&path, &FixedClam(ScanStatus::Clean)).allowed);
    }

    #[test]
    fn infected_or_failed_program_is_blocked() {
        let path = temp_file("app.exe", b"MZ\x00\x00");
        let infected = check_before_launch(
            &path,
            &FixedClam(ScanStatus::Infected {
                signature: "Win.Trojan".to_string(),
            }),
        );
        assert!(!infected.allowed);
        assert!(infected.reason.contains("Win.Trojan"));

        let failed = check_before_launch(
            &path,
            &FixedClam(ScanStatus::Error {
                message: "Access denied".to_string(),
            }),
        );
        assert!(!failed.allowed);
    }

    #[test]
    fn non_executable_is_refused_without_scanning() {
        let path = temp_file("readme.txt", b"hi");
        let verdict = check_before_launch(&path, &FixedClam(ScanStatus::Clean));
        assert!(!verdict.allowed);
        assert!(verdict.reason.contains("не похож на программу"));
    }

    #[test]
    fn run_checked_refuses_blocked_program() {
        let path = temp_file("app.exe", b"MZ\x00\x00");
        let result = run_checked(
            &path,
            &[],
            &FixedClam(ScanStatus::Infected {
                signature: "X".to_string(),
            }),
        );
        assert!(matches!(result, Err(LaunchError::Blocked { .. })));
    }

    #[cfg(unix)]
    #[test]
    fn run_checked_returns_exit_code_of_clean_script() {
        use std::os::unix::fs::PermissionsExt;

        let path = temp_file("ok.sh", b"#!/bin/sh\nexit 3\n");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            run_checked(&path, &[], &FixedClam(ScanStatus::Clean)).unwrap(),
            3
        );
    }
}
