//! Пути к данным программы. Значения можно переопределить переменными окружения.

use std::env;
use std::path::PathBuf;

/// Папка с данными программы: карантин и журналы.
pub fn data_dir() -> PathBuf {
    if cfg!(windows)
        && let Some(program_data) = env::var_os("ProgramData")
    {
        return PathBuf::from(program_data).join("antv");
    }
    let home = env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".antv")
}

pub fn quarantine_dir() -> PathBuf {
    env::var_os("ANTV_QUARANTINE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| data_dir().join("quarantine"))
}

/// Папка с базами ClamAV. None означает базы по умолчанию, заданные при сборке ClamAV.
pub fn database_dir() -> Option<PathBuf> {
    env::var_os("ANTV_DATABASE_DIR").map(PathBuf::from)
}
