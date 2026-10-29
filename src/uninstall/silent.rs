//! Тихое удаление: приводит команду деинсталлятора к беззвучному виду для MSI, Inno Setup и NSIS.

/// Inno Setup: без окон, без подтверждений, без перезагрузки.
const INNO_SILENT: &[&str] = &["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"];
/// MSI: /qn — без интерфейса, /norestart — без перезагрузки.
const MSI_SILENT: &[&str] = &["/qn", "/norestart"];
/// NSIS: /S — тихий режим.
const NSIS_SILENT: &[&str] = &["/S"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallerKind {
    Msi,
    Inno,
    Nsis,
    Unknown,
}

impl InstallerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Msi => "msi",
            Self::Inno => "inno",
            Self::Nsis => "nsis",
            Self::Unknown => "unknown",
        }
    }
}

/// Делит строку команды на аргументы. Кавычки снимаются, пути с пробелами сохраняются.
pub fn split_command(command: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut has_token = false;

    for ch in command.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
                has_token = true;
            }
            c if c.is_whitespace() && !in_quotes => {
                if has_token {
                    args.push(std::mem::take(&mut current));
                    has_token = false;
                }
            }
            c => {
                current.push(c);
                has_token = true;
            }
        }
    }
    if has_token {
        args.push(current);
    }
    args
}

/// Возвращает аргументы для тихого удаления и тип деинсталлятора.
///
/// Для неизвестного деинсталлятора аргументы возвращаются без изменений.
pub fn silent_arguments(command: &str) -> (Vec<String>, InstallerKind) {
    let parts = split_command(command);
    let Some((program, args)) = parts.split_first() else {
        return (parts, InstallerKind::Unknown);
    };
    let file_name = file_name_of(program).to_ascii_lowercase();

    if file_name == "msiexec" || file_name == "msiexec.exe" {
        return (msi(program, args), InstallerKind::Msi);
    }
    if is_inno_uninstaller(&file_name) {
        return (with_flags(program, args, INNO_SILENT), InstallerKind::Inno);
    }
    if file_name == "uninstall.exe" || file_name == "uninst.exe" {
        return (with_flags(program, args, NSIS_SILENT), InstallerKind::Nsis);
    }
    (parts, InstallerKind::Unknown)
}

/// Имя файла из Windows-пути. Разделители `\` и `/` понимаются на любой ОС.
fn file_name_of(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

/// Шаблон `unins000.exe`, `unins001.exe` и т.п.
fn is_inno_uninstaller(file_name: &str) -> bool {
    file_name
        .strip_prefix("unins")
        .and_then(|rest| rest.strip_suffix(".exe"))
        .is_some_and(|digits| digits.chars().all(|ch| ch.is_ascii_digit()))
}

fn msi(program: &str, args: &[String]) -> Vec<String> {
    let Some(product) = args.iter().find_map(|arg| msi_product_code(arg)) else {
        let mut unchanged = vec![program.to_string()];
        unchanged.extend(args.iter().cloned());
        return unchanged;
    };

    // Если уровень интерфейса уже задан (/qb, /quiet и т.п.), сохраняем его, иначе ставим /qn.
    let ui_level: Vec<String> = args
        .iter()
        .filter(|arg| arg.to_ascii_lowercase().starts_with("/q"))
        .cloned()
        .collect();
    let extra: Vec<String> = if ui_level.is_empty() {
        MSI_SILENT.iter().map(|flag| flag.to_string()).collect()
    } else {
        ui_level
    };

    // /I (установка) заменяем на /X (удаление), чтобы MSI удалил продукт.
    let mut result = vec![program.to_string(), format!("/X{product}")];
    result.extend(extra);
    result
}

/// Возвращает код продукта `{GUID}` из аргумента `/I{GUID}` или `/X{GUID}`.
fn msi_product_code(arg: &str) -> Option<&str> {
    let lower = arg.to_ascii_lowercase();
    if !(lower.starts_with("/i{") || lower.starts_with("/x{")) || !lower.ends_with('}') {
        return None;
    }
    let guid = &arg[2..];
    let inner = &guid[1..guid.len() - 1];
    let valid = !inner.is_empty() && inner.chars().all(|ch| ch.is_ascii_hexdigit() || ch == '-');
    valid.then_some(guid)
}

fn with_flags(program: &str, args: &[String], flags: &[&str]) -> Vec<String> {
    let mut result = vec![program.to_string()];
    result.extend(args.iter().cloned());
    for flag in flags {
        if !args.iter().any(|arg| arg.eq_ignore_ascii_case(flag)) {
            result.push(flag.to_string());
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_keeps_quoted_paths_together() {
        assert_eq!(
            split_command(r#""C:\Program Files\App\unins.exe" /S"#),
            vec![r"C:\Program Files\App\unins.exe", "/S"]
        );
    }

    #[test]
    fn msi_install_becomes_silent_removal() {
        let (args, kind) = silent_arguments("MsiExec.exe /I{12345678-AAAA-BBBB-CCCC-123456789ABC}");
        assert_eq!(kind, InstallerKind::Msi);
        assert_eq!(
            args,
            vec![
                "MsiExec.exe",
                "/X{12345678-AAAA-BBBB-CCCC-123456789ABC}",
                "/qn",
                "/norestart"
            ]
        );
    }

    #[test]
    fn msi_keeps_user_ui_level() {
        let (args, _) =
            silent_arguments("MsiExec.exe /X{12345678-AAAA-BBBB-CCCC-123456789ABC} /qb");
        assert_eq!(args.last().map(String::as_str), Some("/qb"));
        assert!(!args.iter().any(|arg| arg == "/qn"));
    }

    #[test]
    fn inno_setup_gets_silent_flags() {
        let (args, kind) = silent_arguments(r#""C:\App\unins000.exe""#);
        assert_eq!(kind, InstallerKind::Inno);
        assert_eq!(
            &args[1..],
            ["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"]
        );
    }

    #[test]
    fn nsis_gets_s_flag_once() {
        let (args, kind) = silent_arguments(r#""C:\App\uninstall.exe" /S"#);
        assert_eq!(kind, InstallerKind::Nsis);
        assert_eq!(args.iter().filter(|arg| arg.as_str() == "/S").count(), 1);
    }

    #[test]
    fn unknown_uninstaller_is_unchanged() {
        let (args, kind) = silent_arguments(r#""C:\App\remove.exe" --all"#);
        assert_eq!(kind, InstallerKind::Unknown);
        assert_eq!(args, vec![r"C:\App\remove.exe", "--all"]);
    }
}
