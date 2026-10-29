//! Запуск деинсталлятора программы.

use std::process::Command;

use super::silent::{InstallerKind, silent_arguments, split_command};
use super::{InstalledProgram, UninstallError};

/// 0 — успех; 1641 и 3010 — успех, но нужна перезагрузка (коды MSI).
const SUCCESS_CODES: [i32; 3] = [0, 1641, 3010];

/// Способ, которым получены аргументы удаления.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UninstallMode {
    /// Готовая тихая команда из реестра.
    QuietString,
    /// Тихий режим подобран автоматически для указанного типа деинсталлятора.
    Silent(InstallerKind),
    /// Обычное удаление с окнами.
    Interactive,
}

/// Возвращает аргументы для запуска и способ их получения.
pub fn prepare_uninstall(program: &InstalledProgram, quiet: bool) -> (Vec<String>, UninstallMode) {
    if quiet && !program.quiet_uninstall_command.is_empty() {
        return (
            split_command(&program.quiet_uninstall_command),
            UninstallMode::QuietString,
        );
    }
    if quiet {
        let (args, kind) = silent_arguments(&program.uninstall_command);
        return (args, UninstallMode::Silent(kind));
    }
    (
        split_command(&program.uninstall_command),
        UninstallMode::Interactive,
    )
}

/// Запускает деинсталлятор. Возвращает код выхода.
pub fn run_uninstaller(program: &InstalledProgram, quiet: bool) -> Result<i32, UninstallError> {
    run_with(program, quiet, |args| {
        let (program, rest) = args
            .split_first()
            .ok_or_else(|| UninstallError::NoCommand(String::new()))?;
        let status = Command::new(program).args(rest).status()?;
        Ok(status.code().unwrap_or(-1))
    })
}

/// Вариант с подменяемым запуском процесса: позволяет проверить аргументы без реального удаления.
pub fn run_with(
    program: &InstalledProgram,
    quiet: bool,
    runner: impl FnOnce(&[String]) -> Result<i32, UninstallError>,
) -> Result<i32, UninstallError> {
    let (args, _) = prepare_uninstall(program, quiet);
    if args.is_empty() {
        return Err(UninstallError::NoCommand(program.name.clone()));
    }
    runner(&args)
}

pub fn is_success(return_code: i32) -> bool {
    SUCCESS_CODES.contains(&return_code)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn program(quiet: &str) -> InstalledProgram {
        InstalledProgram {
            name: "App".to_string(),
            uninstall_command: r#""C:\App\unins000.exe""#.to_string(),
            quiet_uninstall_command: quiet.to_string(),
            ..InstalledProgram::default()
        }
    }

    #[test]
    fn vendor_quiet_string_is_preferred() {
        let (args, mode) = prepare_uninstall(&program(r#""C:\App\unins000.exe" /SILENT"#), true);
        assert_eq!(mode, UninstallMode::QuietString);
        assert_eq!(args.last().map(String::as_str), Some("/SILENT"));
    }

    #[test]
    fn falls_back_to_detected_silent_mode() {
        let (args, mode) = prepare_uninstall(&program(""), true);
        assert_eq!(mode, UninstallMode::Silent(InstallerKind::Inno));
        assert!(args.contains(&"/VERYSILENT".to_string()));
    }

    #[test]
    fn interactive_uses_original_command() {
        let (args, mode) = prepare_uninstall(&program(""), false);
        assert_eq!(mode, UninstallMode::Interactive);
        assert_eq!(args, vec![r"C:\App\unins000.exe"]);
    }

    #[test]
    fn runner_receives_prepared_arguments() {
        let mut seen = Vec::new();
        let code = run_with(&program(""), true, |args| {
            seen = args.to_vec();
            Ok(3010)
        })
        .unwrap();
        assert_eq!(seen[0], r"C:\App\unins000.exe");
        assert!(is_success(code));
    }

    #[test]
    fn empty_command_is_rejected() {
        let empty = InstalledProgram {
            name: "Empty".to_string(),
            ..InstalledProgram::default()
        };
        assert!(matches!(
            run_with(&empty, true, |_| Ok(0)),
            Err(UninstallError::NoCommand(_))
        ));
    }
}
