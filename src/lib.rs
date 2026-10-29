//! Univ-antv — бесплатный антивирус с автоматической проверкой обновлений.
//!
//! Проверка сигнатур выполняется через ClamAV; эта библиотека оркестрирует проверку,
//! фоновый мониторинг, карантин и удаление программ.

pub mod background;
pub mod clam;
pub mod config;
pub mod executables;
pub mod quarantine;
pub mod scanner;
pub mod uninstall;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
