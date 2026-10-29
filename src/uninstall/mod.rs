//! Полное удаление программ: деинсталлятор, поиск и очистка остатков.

pub mod engine;
pub mod leftovers;
pub mod registry;
pub mod silent;

use std::path::PathBuf;

use thiserror::Error;

/// Установленная программа из реестра Windows.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InstalledProgram {
    pub name: String,
    pub version: String,
    pub publisher: String,
    pub uninstall_command: String,
    pub quiet_uninstall_command: String,
    pub install_location: Option<PathBuf>,
    /// Путь к записи реестра, например `HKLM\SOFTWARE\...\Uninstall\{GUID}`.
    pub registry_key: String,
}

#[derive(Debug, Error)]
pub enum UninstallError {
    #[error("эта функция доступна только в Windows")]
    UnsupportedPlatform,
    #[error("у программы {0} нет команды удаления")]
    NoCommand(String),
    #[error("ключ реестра нельзя удалить: {0}")]
    UnsafeRegistryKey(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
