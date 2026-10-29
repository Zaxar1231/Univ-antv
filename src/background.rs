//! Фоновая проверка: следит за изменениями файлов в выбранных папках и проверяет их.

use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use log::{error, info, warn};

use crate::clam::{ClamError, FileScanner, ScanResult, ScanStatus};
use crate::quarantine::{Quarantine, QuarantineError};
use crate::scanner::collect_files;

/// Файл считается изменённым, если поменялись время изменения (нс) или размер.
pub type FileState = (u128, u64);
pub type Snapshot = BTreeMap<PathBuf, FileState>;

/// Шаг, с которым цикл проверяет флаг остановки во время ожидания.
const STOP_POLL: Duration = Duration::from_millis(200);

#[derive(Debug, thiserror::Error)]
pub enum BackgroundError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Clam(#[from] ClamError),
}

pub fn take_snapshot(roots: &[PathBuf]) -> io::Result<Snapshot> {
    let mut snapshot = Snapshot::new();
    for path in collect_files(roots)? {
        // Файл могли удалить во время обхода — такие пропускаем.
        let Ok(metadata) = path.metadata() else {
            continue;
        };
        let modified = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0);
        snapshot.insert(path, (modified, metadata.len()));
    }
    Ok(snapshot)
}

pub fn changed_files(previous: &Snapshot, current: &Snapshot) -> Vec<PathBuf> {
    current
        .iter()
        .filter(|(path, state)| previous.get(*path) != Some(*state))
        .map(|(path, _)| path.clone())
        .collect()
}

/// Проверяет новые и изменённые файлы в отслеживаемых папках.
///
/// При первом цикле проверяются все файлы, дальше только изменившиеся.
pub struct BackgroundScanner<S: FileScanner> {
    roots: Vec<PathBuf>,
    clam: S,
    quarantine: Option<Quarantine>,
    interval: Duration,
    previous: Snapshot,
}

impl<S: FileScanner> BackgroundScanner<S> {
    pub fn new(
        roots: Vec<PathBuf>,
        clam: S,
        quarantine: Option<Quarantine>,
        interval: Duration,
    ) -> Self {
        Self {
            roots,
            clam,
            quarantine,
            interval,
            previous: Snapshot::new(),
        }
    }

    /// Один цикл: находит изменения, проверяет их и помещает угрозы в карантин.
    pub fn scan_changes(&mut self) -> Result<Vec<ScanResult>, BackgroundError> {
        let existing: Vec<PathBuf> = self
            .roots
            .iter()
            .filter(|root| {
                let exists = root.exists();
                if !exists {
                    warn!("папка не найдена, пропускаем: {}", root.display());
                }
                exists
            })
            .cloned()
            .collect();

        let current = take_snapshot(&existing)?;
        let pending = changed_files(&self.previous, &current);
        if pending.is_empty() {
            self.previous = current;
            return Ok(Vec::new());
        }

        let results = self.clam.scan_files(&pending)?;
        for result in &results {
            match &result.status {
                ScanStatus::Infected { signature } => {
                    warn!("угроза: {} ({signature})", result.path.display());
                    self.quarantine_file(result, signature);
                }
                ScanStatus::Error { message } => {
                    error!("не удалось проверить {}: {message}", result.path.display());
                }
                ScanStatus::Clean => {}
            }
        }

        // Состояние сохраняем только после успешной проверки: при сбое файлы проверим в следующем цикле.
        self.previous = current;
        Ok(results)
    }

    fn quarantine_file(&self, result: &ScanResult, signature: &str) {
        let Some(quarantine) = &self.quarantine else {
            return;
        };
        if let Err(error) = quarantine.add(&result.path, signature) {
            report_quarantine_error(&result.path, error);
        }
    }

    /// Работает, пока `stop` не станет true. Ошибка одного цикла не останавливает наблюдение.
    pub fn run(&mut self, stop: &AtomicBool) {
        info!("фоновая проверка запущена, интервал {:?}", self.interval);
        while !stop.load(Ordering::Relaxed) {
            if let Err(error) = self.scan_changes() {
                error!("цикл фоновой проверки завершился с ошибкой: {error}");
            }
            sleep_unless_stopped(self.interval, stop);
        }
        info!("фоновая проверка остановлена");
    }
}

fn report_quarantine_error(path: &std::path::Path, error: QuarantineError) {
    error!(
        "не удалось поместить в карантин {}: {error}",
        path.display()
    );
}

fn sleep_unless_stopped(duration: Duration, stop: &AtomicBool) {
    let deadline = Instant::now() + duration;
    while !stop.load(Ordering::Relaxed) && Instant::now() < deadline {
        thread::sleep(STOP_POLL.min(deadline.saturating_duration_since(Instant::now())));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clam::ClamError;
    use std::cell::RefCell;
    use std::fs;

    struct FakeClam {
        infected: Vec<PathBuf>,
        calls: RefCell<Vec<Vec<PathBuf>>>,
    }

    impl FileScanner for FakeClam {
        fn scan_files(&self, files: &[PathBuf]) -> Result<Vec<ScanResult>, ClamError> {
            self.calls.borrow_mut().push(files.to_vec());
            Ok(files
                .iter()
                .map(|file| ScanResult {
                    path: file.clone(),
                    status: if self.infected.contains(file) {
                        ScanStatus::Infected {
                            signature: "Fake.Virus".to_string(),
                        }
                    } else {
                        ScanStatus::Clean
                    },
                })
                .collect())
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("antv-test-{name}-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn fake(infected: Vec<PathBuf>) -> FakeClam {
        FakeClam {
            infected,
            calls: RefCell::new(Vec::new()),
        }
    }

    #[test]
    fn first_cycle_scans_everything_then_only_changes() {
        let dir = temp_dir("first");
        fs::write(dir.join("a.txt"), "a").unwrap();
        fs::write(dir.join("b.txt"), "b").unwrap();
        let mut scanner =
            BackgroundScanner::new(vec![dir.clone()], fake(vec![]), None, Duration::ZERO);

        scanner.scan_changes().unwrap();
        assert_eq!(scanner.clam.calls.borrow()[0].len(), 2);

        scanner.scan_changes().unwrap();
        assert_eq!(scanner.clam.calls.borrow().len(), 1);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn modified_file_is_rescanned() {
        let dir = temp_dir("modified");
        let target = dir.join("a.txt");
        fs::write(&target, "a").unwrap();
        let mut scanner =
            BackgroundScanner::new(vec![dir.clone()], fake(vec![]), None, Duration::ZERO);
        scanner.scan_changes().unwrap();

        fs::write(&target, "changed content with a different size").unwrap();
        scanner.scan_changes().unwrap();

        assert_eq!(scanner.clam.calls.borrow().last().unwrap(), &vec![target]);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn infected_file_goes_to_quarantine() {
        let dir = temp_dir("quarantine");
        let target = dir.join("bad.exe");
        fs::write(&target, b"MZ-bad").unwrap();
        let quarantine = Quarantine::open(dir.join("q")).unwrap();
        let mut scanner = BackgroundScanner::new(
            vec![dir.clone()],
            fake(vec![target.clone()]),
            Some(quarantine),
            Duration::ZERO,
        );

        let results = scanner.scan_changes().unwrap();

        assert!(results.iter().any(ScanResult::is_infected));
        assert!(!target.exists());
        let stored = Quarantine::open(dir.join("q")).unwrap().list().unwrap();
        assert_eq!(stored[0].signature, "Fake.Virus");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn missing_root_is_skipped() {
        let mut scanner = BackgroundScanner::new(
            vec![PathBuf::from("/definitely/not/here-antv")],
            fake(vec![]),
            None,
            Duration::ZERO,
        );
        assert!(scanner.scan_changes().unwrap().is_empty());
    }

    #[test]
    fn stop_flag_ends_run_loop() {
        let dir = temp_dir("stop");
        let stop = AtomicBool::new(true);
        let mut scanner = BackgroundScanner::new(
            vec![dir.clone()],
            fake(vec![]),
            None,
            Duration::from_secs(60),
        );
        scanner.run(&stop);
        assert!(scanner.clam.calls.borrow().is_empty());
        fs::remove_dir_all(dir).unwrap();
    }
}
