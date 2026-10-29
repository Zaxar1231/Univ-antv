//! Карантин: изолированное хранение заражённых файлов с возможностью восстановления.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

const INDEX_NAME: &str = "index.json";
const STORED_SUFFIX: &str = ".quar";

#[derive(Debug, Error)]
pub enum QuarantineError {
    #[error("нет записи в карантине: {0}")]
    NotFound(String),
    #[error("файл уже существует: {0}")]
    AlreadyExists(PathBuf),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("повреждён индекс карантина: {0}")]
    Index(#[from] serde_json::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: String,
    pub original_path: PathBuf,
    pub signature: String,
    /// Время помещения в карантин, секунды от начала эпохи Unix.
    pub quarantined_at: u64,
}

pub struct Quarantine {
    directory: PathBuf,
}

impl Quarantine {
    pub fn open(directory: impl Into<PathBuf>) -> Result<Self, QuarantineError> {
        let directory = directory.into();
        fs::create_dir_all(&directory)?;
        Ok(Self { directory })
    }

    /// Перемещает файл в карантин и записывает его в индекс.
    pub fn add(&self, path: &Path, signature: &str) -> Result<QuarantineEntry, QuarantineError> {
        let entry = QuarantineEntry {
            id: uuid::Uuid::new_v4().simple().to_string(),
            original_path: fs::canonicalize(path)?,
            signature: signature.to_string(),
            quarantined_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|elapsed| elapsed.as_secs())
                .unwrap_or(0),
        };
        move_file(path, &self.stored_path(&entry.id))?;

        let mut entries = self.load()?;
        entries.insert(entry.id.clone(), entry.clone());
        self.save(&entries)?;
        Ok(entry)
    }

    /// Записи карантина, от самых старых к новым.
    pub fn list(&self) -> Result<Vec<QuarantineEntry>, QuarantineError> {
        let mut entries: Vec<QuarantineEntry> = self.load()?.into_values().collect();
        entries.sort_by_key(|entry| entry.quarantined_at);
        Ok(entries)
    }

    /// Возвращает файл на исходное место. Существующий файл не перезаписывается.
    pub fn restore(&self, id: &str) -> Result<PathBuf, QuarantineError> {
        let mut entries = self.load()?;
        let entry = get(&entries, id)?.clone();
        if entry.original_path.exists() {
            return Err(QuarantineError::AlreadyExists(entry.original_path));
        }
        if let Some(parent) = entry.original_path.parent() {
            fs::create_dir_all(parent)?;
        }
        move_file(&self.stored_path(id), &entry.original_path)?;

        entries.remove(id);
        self.save(&entries)?;
        Ok(entry.original_path)
    }

    /// Безвозвратно удаляет файл из карантина.
    pub fn delete(&self, id: &str) -> Result<(), QuarantineError> {
        let mut entries = self.load()?;
        get(&entries, id)?;
        match fs::remove_file(self.stored_path(id)) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        entries.remove(id);
        self.save(&entries)
    }

    fn stored_path(&self, id: &str) -> PathBuf {
        self.directory.join(format!("{id}{STORED_SUFFIX}"))
    }

    fn index_path(&self) -> PathBuf {
        self.directory.join(INDEX_NAME)
    }

    fn load(&self) -> Result<BTreeMap<String, QuarantineEntry>, QuarantineError> {
        match fs::read_to_string(self.index_path()) {
            Ok(text) => Ok(serde_json::from_str(&text)?),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(BTreeMap::new()),
            Err(error) => Err(error.into()),
        }
    }

    fn save(&self, entries: &BTreeMap<String, QuarantineEntry>) -> Result<(), QuarantineError> {
        let text = serde_json::to_string_pretty(entries)?;
        fs::write(self.index_path(), text)?;
        Ok(())
    }
}

fn get<'a>(
    entries: &'a BTreeMap<String, QuarantineEntry>,
    id: &str,
) -> Result<&'a QuarantineEntry, QuarantineError> {
    entries
        .get(id)
        .ok_or_else(|| QuarantineError::NotFound(id.to_string()))
}

/// Перемещает файл. Если переименование невозможно (другой диск), копирует и удаляет исходный.
fn move_file(from: &Path, to: &Path) -> io::Result<()> {
    match fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(_) => {
            fs::copy(from, to)?;
            fs::remove_file(from)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("antv-test-{name}-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn add_list_restore_round_trip() {
        let dir = temp_dir("roundtrip");
        let source = dir.join("virus.exe");
        fs::write(&source, b"MZ payload").unwrap();
        let quarantine = Quarantine::open(dir.join("q")).unwrap();

        let entry = quarantine.add(&source, "Fake.Virus").unwrap();
        assert!(!source.exists());
        assert_eq!(quarantine.list().unwrap()[0].id, entry.id);

        let restored = quarantine.restore(&entry.id).unwrap();
        assert_eq!(restored, fs::canonicalize(&source).unwrap());
        assert_eq!(fs::read(&source).unwrap(), b"MZ payload");
        assert!(quarantine.list().unwrap().is_empty());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn restore_does_not_overwrite() {
        let dir = temp_dir("no-overwrite");
        let source = dir.join("file.bin");
        fs::write(&source, "1").unwrap();
        let quarantine = Quarantine::open(dir.join("q")).unwrap();
        let entry = quarantine.add(&source, "Fake.Virus").unwrap();
        fs::write(&source, "someone else's file").unwrap();

        assert!(matches!(
            quarantine.restore(&entry.id),
            Err(QuarantineError::AlreadyExists(_))
        ));
        assert_eq!(fs::read_to_string(&source).unwrap(), "someone else's file");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn delete_removes_stored_file() {
        let dir = temp_dir("delete");
        let source = dir.join("file.bin");
        fs::write(&source, "1").unwrap();
        let quarantine = Quarantine::open(dir.join("q")).unwrap();
        let entry = quarantine.add(&source, "Fake.Virus").unwrap();

        quarantine.delete(&entry.id).unwrap();

        assert!(quarantine.list().unwrap().is_empty());
        assert!(!quarantine.stored_path(&entry.id).exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn unknown_id_is_not_found() {
        let dir = temp_dir("unknown");
        let quarantine = Quarantine::open(dir.join("q")).unwrap();
        assert!(matches!(
            quarantine.restore("missing"),
            Err(QuarantineError::NotFound(_))
        ));
        fs::remove_dir_all(dir).unwrap();
    }
}
