//! Сквозные проверки на настоящем ClamAV. Запускаются, если заданы ANTV_DATABASE_DIR и установлен clamscan.

use std::fs;
use std::path::PathBuf;

use antv::clam::{ClamAV, ScanStatus, find_tool};
use antv::config::database_dir;

const EICAR: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

/// Возвращает базы ClamAV, если окружение готово. Иначе тест пропускается.
fn ready_database() -> Option<PathBuf> {
    find_tool("clamscan").ok()?;
    let database = database_dir()?;
    Some(database)
}

#[test]
fn detects_eicar_and_passes_clean_file() {
    let Some(database) = ready_database() else {
        eprintln!("пропущено: нужны clamscan и ANTV_DATABASE_DIR");
        return;
    };
    let dir = std::env::temp_dir().join(format!("antv-e2e-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&dir).unwrap();
    let infected = dir.join("eicar.txt");
    let clean = dir.join("clean.txt");
    fs::write(&infected, EICAR).unwrap();
    fs::write(&clean, "hello").unwrap();

    let results = ClamAV::new(Some(database))
        .scan_files(&[infected, clean])
        .unwrap();

    assert_eq!(
        results[0].status,
        ScanStatus::Infected {
            signature: "Eicar-Test-Signature".to_string()
        }
    );
    assert_eq!(results[1].status, ScanStatus::Clean);
    fs::remove_dir_all(dir).unwrap();
}
