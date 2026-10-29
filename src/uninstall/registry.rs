//! Список установленных программ из реестра Windows.
//!
//! Разбор записей (`parse_entry`) работает на любой ОС. Обращение к реестру есть только в Windows.

use std::path::PathBuf;

use super::{InstalledProgram, UninstallError};

pub const UNINSTALL_SUBKEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
pub const UNINSTALL_SUBKEY_32: &str =
    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall";

/// Значения записи реестра, которые нужны для удаления. Отсутствующие поля равны None.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RawEntry {
    pub display_name: Option<String>,
    pub display_version: Option<String>,
    pub publisher: Option<String>,
    pub uninstall_string: Option<String>,
    pub quiet_uninstall_string: Option<String>,
    pub install_location: Option<String>,
    pub system_component: Option<u32>,
    pub parent_key_name: Option<String>,
}

fn text(value: &Option<String>) -> String {
    value.as_deref().unwrap_or_default().trim().to_string()
}

/// Превращает значения записи в программу. Возвращает None для записей, которые не нужны.
pub fn parse_entry(raw: &RawEntry, registry_key: &str) -> Option<InstalledProgram> {
    let name = text(&raw.display_name);
    let uninstall = text(&raw.uninstall_string);
    if name.is_empty() || uninstall.is_empty() {
        return None;
    }
    // Системные компоненты и обновления удаляются через основную программу, поэтому их пропускаем.
    if raw.system_component == Some(1) || raw.parent_key_name.is_some() {
        return None;
    }

    let location = text(&raw.install_location);
    Some(InstalledProgram {
        name,
        version: text(&raw.display_version),
        publisher: text(&raw.publisher),
        uninstall_command: uninstall,
        quiet_uninstall_command: text(&raw.quiet_uninstall_string),
        install_location: (!location.is_empty()).then(|| PathBuf::from(location)),
        registry_key: registry_key.to_string(),
    })
}

/// Проверяет, что имя программы достаточно длинное для поиска по совпадению.
pub fn is_searchable_name(name: &str) -> bool {
    normalized_len(name) >= 3
}

fn normalized_len(name: &str) -> usize {
    name.chars().filter(|ch| ch.is_alphanumeric()).count()
}

#[cfg(windows)]
pub fn list_installed_programs() -> Result<Vec<InstalledProgram>, UninstallError> {
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;

    let sources = [
        (HKEY_LOCAL_MACHINE, "HKLM", UNINSTALL_SUBKEY),
        (HKEY_LOCAL_MACHINE, "HKLM", UNINSTALL_SUBKEY_32),
        (HKEY_CURRENT_USER, "HKCU", UNINSTALL_SUBKEY),
    ];

    let mut programs = Vec::new();
    for (hive, hive_name, subkey) in sources {
        let Ok(root) = RegKey::predef(hive).open_subkey_with_flags(subkey, KEY_READ) else {
            continue;
        };
        for child in root.enum_keys().flatten() {
            let Ok(key) = root.open_subkey_with_flags(&child, KEY_READ) else {
                continue;
            };
            let raw = RawEntry {
                display_name: key.get_value("DisplayName").ok(),
                display_version: key.get_value("DisplayVersion").ok(),
                publisher: key.get_value("Publisher").ok(),
                uninstall_string: key.get_value("UninstallString").ok(),
                quiet_uninstall_string: key.get_value("QuietUninstallString").ok(),
                install_location: key.get_value("InstallLocation").ok(),
                system_component: key.get_value("SystemComponent").ok(),
                parent_key_name: key.get_value("ParentKeyName").ok(),
            };
            let registry_key = format!("{hive_name}\\{subkey}\\{child}");
            if let Some(program) = parse_entry(&raw, &registry_key) {
                programs.push(program);
            }
        }
    }
    programs.sort_by_key(|program| program.name.to_lowercase());
    Ok(programs)
}

#[cfg(not(windows))]
pub fn list_installed_programs() -> Result<Vec<InstalledProgram>, UninstallError> {
    Err(UninstallError::UnsupportedPlatform)
}

/// Ищет ключи `SOFTWARE\<издатель>\<программа>` и `SOFTWARE\<программа>`, которые могли остаться.
#[cfg(windows)]
pub fn find_registry_leftovers(name: &str, publisher: &str) -> Vec<String> {
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;

    if !is_searchable_name(name) {
        return Vec::new();
    }
    let mut relatives = Vec::new();
    if !publisher.trim().is_empty() {
        relatives.push(format!("{publisher}\\{name}"));
    }
    relatives.push(name.to_string());

    let mut found = Vec::new();
    for (hive, hive_name) in [(HKEY_LOCAL_MACHINE, "HKLM"), (HKEY_CURRENT_USER, "HKCU")] {
        for relative in &relatives {
            let subkey = format!("SOFTWARE\\{relative}");
            if RegKey::predef(hive)
                .open_subkey_with_flags(&subkey, KEY_READ)
                .is_ok()
            {
                found.push(format!("{hive_name}\\{subkey}"));
            }
        }
    }
    found
}

#[cfg(not(windows))]
pub fn find_registry_leftovers(_name: &str, _publisher: &str) -> Vec<String> {
    Vec::new()
}

/// Удаляет ключ реестра вместе со вложенными. Принимает строку вида `HKLM\SOFTWARE\...`.
///
/// Удалять можно только ключи внутри `SOFTWARE`, на два уровня и глубже: сам раздел не трогаем.
#[cfg(windows)]
pub fn delete_registry_tree(full_key: &str) -> Result<(), UninstallError> {
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS};
    use winreg::RegKey;

    let (hive_name, subkey) = full_key
        .split_once('\\')
        .ok_or_else(|| UninstallError::UnsafeRegistryKey(full_key.to_string()))?;
    let hive = match hive_name {
        "HKLM" => HKEY_LOCAL_MACHINE,
        "HKCU" => HKEY_CURRENT_USER,
        _ => return Err(UninstallError::UnsafeRegistryKey(full_key.to_string())),
    };
    let (parent_path, leaf) = subkey
        .rsplit_once('\\')
        .filter(|(parent, _)| parent.starts_with("SOFTWARE\\") && parent.len() > "SOFTWARE\\".len())
        .ok_or_else(|| UninstallError::UnsafeRegistryKey(full_key.to_string()))?;

    let parent = RegKey::predef(hive).open_subkey_with_flags(parent_path, KEY_ALL_ACCESS)?;
    parent.delete_subkey_all(leaf)?;
    Ok(())
}

#[cfg(not(windows))]
pub fn delete_registry_tree(_full_key: &str) -> Result<(), UninstallError> {
    Err(UninstallError::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(name: &str, uninstall: &str) -> RawEntry {
        RawEntry {
            display_name: Some(name.to_string()),
            uninstall_string: Some(uninstall.to_string()),
            ..RawEntry::default()
        }
    }

    #[test]
    fn parses_fields_and_trims_text() {
        let entry = RawEntry {
            display_name: Some("  Example Tool ".to_string()),
            display_version: Some("1.2.3".to_string()),
            publisher: Some("Example Corp".to_string()),
            uninstall_string: Some(r#""C:\Example\unins000.exe""#.to_string()),
            quiet_uninstall_string: Some(r#""C:\Example\unins000.exe" /SILENT"#.to_string()),
            install_location: Some(r"C:\Example".to_string()),
            ..RawEntry::default()
        };

        let program = parse_entry(&entry, r"HKLM\SOFTWARE\...\Uninstall\Example").unwrap();

        assert_eq!(program.name, "Example Tool");
        assert_eq!(program.version, "1.2.3");
        assert_eq!(program.install_location, Some(PathBuf::from(r"C:\Example")));
        assert!(program.quiet_uninstall_command.ends_with("/SILENT"));
    }

    #[test]
    fn skips_records_that_cannot_be_uninstalled() {
        assert!(parse_entry(&raw("", "x.exe"), "k").is_none());
        assert!(parse_entry(&RawEntry::default(), "k").is_none());
        assert!(parse_entry(&raw("No Command", ""), "k").is_none());

        let system = RawEntry {
            system_component: Some(1),
            ..raw("Runtime", "x.exe")
        };
        assert!(parse_entry(&system, "k").is_none());

        let patch = RawEntry {
            parent_key_name: Some("Office".to_string()),
            ..raw("Patch", "x.exe")
        };
        assert!(parse_entry(&patch, "k").is_none());
    }

    #[test]
    fn short_names_are_not_searchable() {
        assert!(!is_searchable_name("R"));
        assert!(!is_searchable_name(" - "));
        assert!(is_searchable_name("Ahk"));
    }
}
