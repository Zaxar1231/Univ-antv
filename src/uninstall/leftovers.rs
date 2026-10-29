//! Остатки программы после удаления: папки, ярлыки и ключи реестра.
//!
//! Поиск осторожный: совпадение по точному имени, короткие имена не используются,
//! а удалять можно только внутри известных корневых папок.

use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use super::registry::{delete_registry_tree, is_searchable_name};
use super::{InstalledProgram, UninstallError};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Leftovers {
    pub directories: Vec<PathBuf>,
    pub shortcuts: Vec<PathBuf>,
    pub registry_keys: Vec<String>,
}

impl Leftovers {
    pub fn is_empty(&self) -> bool {
        self.directories.is_empty() && self.shortcuts.is_empty() && self.registry_keys.is_empty()
    }
}

/// Сравнение имён без регистра и без знаков: «Example Tool» и «example-tool» совпадают.
fn normalize(text: &str) -> String {
    text.chars()
        .filter(|ch| ch.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

/// Папки, где программы обычно оставляют файлы (только Windows).
pub fn default_search_roots() -> Vec<PathBuf> {
    if !cfg!(windows) {
        return Vec::new();
    }
    [
        "ProgramFiles",
        "ProgramFiles(x86)",
        "ProgramData",
        "APPDATA",
        "LOCALAPPDATA",
    ]
    .iter()
    .filter_map(env::var_os)
    .map(PathBuf::from)
    .collect()
}

/// Папки меню «Пуск», где лежат ярлыки (только Windows).
pub fn default_shortcut_roots() -> Vec<PathBuf> {
    if !cfg!(windows) {
        return Vec::new();
    }
    ["ProgramData", "APPDATA"]
        .iter()
        .filter_map(env::var_os)
        .map(|base| {
            PathBuf::from(base)
                .join("Microsoft")
                .join("Windows")
                .join("Start Menu")
                .join("Programs")
        })
        .collect()
}

/// Папки с точным совпадением имени, плюс папка установки, если она указана в реестре.
pub fn find_leftover_directories(
    program: &InstalledProgram,
    search_roots: &[PathBuf],
) -> Vec<PathBuf> {
    let mut found = Vec::new();
    if let Some(location) = &program.install_location
        && location.is_dir()
    {
        found.push(location.clone());
    }

    let wanted = normalize(&program.name);
    if !is_searchable_name(&program.name) {
        return found;
    }

    for root in search_roots {
        let Ok(children) = fs::read_dir(root) else {
            continue;
        };
        for child in children.flatten() {
            let path = child.path();
            let is_plain_dir = fs::symlink_metadata(&path).is_ok_and(|meta| meta.is_dir());
            if is_plain_dir
                && normalize(&child.file_name().to_string_lossy()) == wanted
                && !found.contains(&path)
            {
                found.push(path);
            }
        }
    }
    found
}

/// Ярлыки `.lnk` в меню «Пуск» с тем же именем, что и программа.
pub fn find_leftover_shortcuts(
    program: &InstalledProgram,
    shortcut_roots: &[PathBuf],
) -> Vec<PathBuf> {
    if !is_searchable_name(&program.name) {
        return Vec::new();
    }
    let wanted = normalize(&program.name);
    let mut found = Vec::new();
    for root in shortcut_roots {
        collect_shortcuts(root, &wanted, &mut found);
    }
    found
}

fn collect_shortcuts(dir: &Path, wanted: &str, found: &mut Vec<PathBuf>) {
    let Ok(children) = fs::read_dir(dir) else {
        return;
    };
    for child in children.flatten() {
        let path = child.path();
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.is_dir() {
            collect_shortcuts(&path, wanted, found);
        } else if path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("lnk"))
        {
            let stem = path
                .file_stem()
                .map(|stem| stem.to_string_lossy().into_owned())
                .unwrap_or_default();
            if normalize(&stem) == wanted {
                found.push(path);
            }
        }
    }
}

/// Разрешает удалять только то, что лежит внутри корневой папки, но не сами корни и не диски.
pub fn is_safe_to_delete(path: &Path, roots: &[PathBuf]) -> bool {
    let Ok(target) = fs::canonicalize(path) else {
        return false;
    };
    if target.parent().is_none() {
        return false; // корень диска
    }
    roots
        .iter()
        .filter_map(|root| fs::canonicalize(root).ok())
        .any(|root| target != root && target.starts_with(&root))
}

pub fn find_leftovers(
    program: &InstalledProgram,
    search_roots: &[PathBuf],
    shortcut_roots: &[PathBuf],
    registry_keys: Vec<String>,
) -> Leftovers {
    Leftovers {
        directories: find_leftover_directories(program, search_roots),
        shortcuts: find_leftover_shortcuts(program, shortcut_roots),
        registry_keys,
    }
}

/// Удаляет найденные остатки. Возвращает список выполненных действий.
///
/// Пути вне разрешённых корней пропускаются с пометкой: ничего не удаляется «на всякий случай».
pub fn delete_leftovers(
    leftovers: &Leftovers,
    directory_roots: &[PathBuf],
    shortcut_roots: &[PathBuf],
) -> io::Result<Vec<String>> {
    let mut actions = Vec::new();

    for directory in &leftovers.directories {
        if !is_safe_to_delete(directory, directory_roots) {
            actions.push(format!(
                "пропущено (вне разрешённых папок): {}",
                directory.display()
            ));
            continue;
        }
        fs::remove_dir_all(directory)?;
        actions.push(format!("удалена папка: {}", directory.display()));
    }

    for shortcut in &leftovers.shortcuts {
        if !is_safe_to_delete(shortcut, shortcut_roots) {
            actions.push(format!(
                "пропущено (вне меню «Пуск»): {}",
                shortcut.display()
            ));
            continue;
        }
        fs::remove_file(shortcut)?;
        actions.push(format!("удалён ярлык: {}", shortcut.display()));
    }

    for key in &leftovers.registry_keys {
        delete_registry_tree(key).map_err(|error| match error {
            UninstallError::Io(io_error) => io_error,
            other => io::Error::other(other.to_string()),
        })?;
        actions.push(format!("удалён ключ реестра: {key}"));
    }

    Ok(actions)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(name: &str) -> PathBuf {
        let dir = env::temp_dir().join(format!("antv-test-{name}-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn program(name: &str) -> InstalledProgram {
        InstalledProgram {
            name: name.to_string(),
            ..InstalledProgram::default()
        }
    }

    #[test]
    fn directories_match_exact_name_only() {
        let root = temp_root("exact");
        fs::create_dir_all(root.join("Example Tool")).unwrap();
        fs::create_dir_all(root.join("Example Tool Pro")).unwrap();
        fs::create_dir_all(root.join("Other")).unwrap();

        let found =
            find_leftover_directories(&program("Example Tool"), std::slice::from_ref(&root));

        assert_eq!(found, vec![root.join("Example Tool")]);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn short_names_match_nothing() {
        let root = temp_root("short");
        fs::create_dir_all(root.join("R")).unwrap();

        assert!(find_leftover_directories(&program("R"), std::slice::from_ref(&root)).is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn safety_protects_roots_and_outsiders() {
        let root = temp_root("safety");
        let inside = root.join("Programs").join("App");
        let outside = root.join("Documents");
        fs::create_dir_all(&inside).unwrap();
        fs::create_dir_all(&outside).unwrap();
        let roots = vec![root.join("Programs")];

        assert!(is_safe_to_delete(&inside, &roots));
        assert!(!is_safe_to_delete(&root.join("Programs"), &roots));
        assert!(!is_safe_to_delete(&outside, &roots));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn delete_removes_allowed_and_skips_outsiders() {
        let root = temp_root("delete");
        let app = root.join("Programs").join("Example Tool");
        let outside = root.join("Documents").join("Example Tool");
        fs::create_dir_all(&app).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(app.join("data.bin"), "x").unwrap();

        let leftovers = Leftovers {
            directories: vec![app.clone(), outside.clone()],
            ..Leftovers::default()
        };
        let actions = delete_leftovers(&leftovers, &[root.join("Programs")], &[]).unwrap();

        assert!(!app.exists());
        assert!(outside.exists());
        assert!(actions.iter().any(|action| action.starts_with("пропущено")));
        fs::remove_dir_all(root).unwrap();
    }
}
