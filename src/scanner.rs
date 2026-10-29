//! Сбор файлов из путей и их проверка через ClamAV.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::clam::{FileScanner, ScanResult, ScanStatus};
use crate::quarantine::{Quarantine, QuarantineError};

/// Возвращает файлы из путей; папки обходятся рекурсивно. Символические ссылки пропускаются.
pub fn collect_files(paths: &[PathBuf]) -> io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for path in paths {
        if path.is_dir() {
            walk(path, &mut files)?;
        } else if path.is_file() {
            files.push(path.clone());
        } else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("нет такого файла или папки: {}", path.display()),
            ));
        }
    }
    Ok(files)
}

fn walk(dir: &Path, files: &mut Vec<PathBuf>) -> io::Result<()> {
    let mut children: Vec<PathBuf> = fs::read_dir(dir)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<io::Result<_>>()?;
    children.sort();

    for child in children {
        // symlink_metadata не следует по ссылкам, поэтому ссылки не попадают в обход.
        let metadata = fs::symlink_metadata(&child)?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            walk(&child, files)?;
        } else if metadata.is_file() {
            files.push(child);
        }
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Clam(#[from] crate::clam::ClamError),
    #[error(transparent)]
    Quarantine(#[from] QuarantineError),
}

/// Проверяет пути и, если передан карантин, помещает заражённые файлы в него.
pub fn scan_paths(
    paths: &[PathBuf],
    clam: &impl FileScanner,
    quarantine: Option<&Quarantine>,
) -> Result<Vec<ScanResult>, ScanError> {
    let results = clam.scan_files(&collect_files(paths)?)?;
    if let Some(quarantine) = quarantine {
        for result in &results {
            if let ScanStatus::Infected { signature } = &result.status {
                quarantine.add(&result.path, signature)?;
            }
        }
    }
    Ok(results)
}
