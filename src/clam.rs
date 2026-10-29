//! Обёртка над ClamAV: `clamscan` и `freshclam` запускаются как внешние программы.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use thiserror::Error;

/// Коды возврата clamscan: 0 — угроз нет, 1 — найдены угрозы, 2 — ошибка.
const SCAN_OK_CODES: [i32; 3] = [0, 1, 2];

#[derive(Debug, Error)]
pub enum ClamError {
    #[error("{0} не найден. Установите ClamAV или укажите папку в ANTV_CLAMAV_DIR")]
    NotFound(String),
    #[error("{tool} завершился с кодом {code}: {output}")]
    Failed {
        tool: String,
        code: i32,
        output: String,
    },
    #[error("превышено время ожидания")]
    Timeout,
    #[error("ошибка запуска программы: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanStatus {
    Clean,
    Infected { signature: String },
    Error { message: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanResult {
    pub path: PathBuf,
    pub status: ScanStatus,
}

impl ScanResult {
    pub fn is_infected(&self) -> bool {
        matches!(self.status, ScanStatus::Infected { .. })
    }

    pub fn is_error(&self) -> bool {
        matches!(self.status, ScanStatus::Error { .. })
    }
}

/// Находит исполняемый файл ClamAV: сначала в ANTV_CLAMAV_DIR, затем в Program Files и PATH.
pub fn find_tool(name: &str) -> Result<PathBuf, ClamError> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Some(dir) = std::env::var_os("ANTV_CLAMAV_DIR") {
        dirs.push(PathBuf::from(dir));
    }
    if let Some(program_files) = std::env::var_os("ProgramFiles") {
        dirs.push(PathBuf::from(program_files).join("ClamAV"));
    }
    if let Some(path) = std::env::var_os("PATH") {
        dirs.extend(std::env::split_paths(&path));
    }

    let names = executable_names(name);
    dirs.iter()
        .flat_map(|dir| names.iter().map(move |file| dir.join(file)))
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| ClamError::NotFound(name.to_string()))
}

fn executable_names(name: &str) -> Vec<String> {
    if cfg!(windows) {
        vec![format!("{name}.exe"), name.to_string()]
    } else {
        vec![name.to_string()]
    }
}

/// Разбирает вывод `clamscan --no-summary --file-list` в результаты для каждого переданного файла.
///
/// Пути из вывода сверяются с известными файлами, поэтому двоеточия внутри путей
/// и сообщений об ошибках не ломают разбор.
pub fn parse_output(stdout: &str, files: &[PathBuf]) -> Vec<ScanResult> {
    let known: HashMap<String, usize> = files
        .iter()
        .enumerate()
        .map(|(index, path)| (path.to_string_lossy().into_owned(), index))
        .collect();
    let mut parsed: HashMap<usize, ScanStatus> = HashMap::new();

    for line in stdout.lines() {
        let Some((index, status)) = split_line(line, &known) else {
            continue;
        };
        parsed.insert(index, parse_status(status));
    }

    files
        .iter()
        .enumerate()
        .map(|(index, path)| ScanResult {
            path: path.clone(),
            status: parsed.remove(&index).unwrap_or(ScanStatus::Error {
                message: "нет результата проверки".to_string(),
            }),
        })
        .collect()
}

fn split_line<'a>(line: &'a str, known: &HashMap<String, usize>) -> Option<(usize, &'a str)> {
    line.match_indices(": ").find_map(|(position, _)| {
        known
            .get(&line[..position])
            .map(|&index| (index, &line[position + 2..]))
    })
}

fn parse_status(status: &str) -> ScanStatus {
    if let Some(signature) = status.strip_suffix(" FOUND") {
        return ScanStatus::Infected {
            signature: signature.to_string(),
        };
    }
    if status == "OK" {
        return ScanStatus::Clean;
    }
    ScanStatus::Error {
        message: status.to_string(),
    }
}

/// Результат внешней программы: код возврата и текст вывода.
struct Output {
    code: i32,
    stdout: String,
    stderr: String,
}

/// Запускает программу с ограничением по времени. Вывод читается параллельно,
/// иначе переполнение буфера канала приведёт к зависанию.
fn run_with_timeout(mut command: Command, timeout: Duration) -> Result<Output, ClamError> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn()?;

    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();
    let stdout_reader = thread::spawn(move || read_pipe(stdout_pipe));
    let stderr_reader = thread::spawn(move || read_pipe(stderr_pipe));

    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ClamError::Timeout);
        }
        thread::sleep(Duration::from_millis(50));
    };

    Ok(Output {
        code: status.code().unwrap_or(-1),
        stdout: stdout_reader.join().unwrap_or_default(),
        stderr: stderr_reader.join().unwrap_or_default(),
    })
}

fn read_pipe<R: Read>(pipe: Option<R>) -> String {
    let mut bytes = Vec::new();
    if let Some(mut pipe) = pipe {
        let _ = pipe.read_to_end(&mut bytes);
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Проверка файлов и обновление баз через установленный ClamAV.
#[derive(Debug, Clone)]
pub struct ClamAV {
    pub database_dir: Option<PathBuf>,
    pub timeout: Duration,
}

impl Default for ClamAV {
    fn default() -> Self {
        Self {
            database_dir: None,
            timeout: Duration::from_secs(3600),
        }
    }
}

impl ClamAV {
    pub fn new(database_dir: Option<PathBuf>) -> Self {
        Self {
            database_dir,
            ..Self::default()
        }
    }

    /// Проверяет список файлов одним запуском clamscan.
    pub fn scan_files(&self, files: &[PathBuf]) -> Result<Vec<ScanResult>, ClamError> {
        if files.is_empty() {
            return Ok(Vec::new());
        }

        // Список передаётся через файл, чтобы не упереться в лимит длины командной строки.
        let mut listing = tempfile::NamedTempFile::new()?;
        let content = files
            .iter()
            .map(|path| path.to_string_lossy())
            .collect::<Vec<_>>()
            .join("\n");
        listing.write_all(content.as_bytes())?;
        listing.flush()?;

        let clamscan = find_tool("clamscan")?;
        let mut command = Command::new(clamscan);
        command
            .arg("--no-summary")
            .arg(format!("--file-list={}", listing.path().display()));
        if let Some(database) = &self.database_dir {
            command.arg(format!("--database={}", database.display()));
        }

        let output = run_with_timeout(command, self.timeout)?;
        if !SCAN_OK_CODES.contains(&output.code) {
            return Err(ClamError::Failed {
                tool: "clamscan".to_string(),
                code: output.code,
                output: output.stderr.trim().to_string(),
            });
        }
        Ok(parse_output(&output.stdout, files))
    }

    /// Обновляет базы сигнатур через freshclam.
    pub fn update(&self) -> Result<(), ClamError> {
        let freshclam = find_tool("freshclam")?;
        let mut command = Command::new(freshclam);
        if let Some(database) = &self.database_dir {
            command.arg(format!("--datadir={}", database.display()));
        }

        let output = run_with_timeout(command, self.timeout)?;
        if output.code != 0 {
            return Err(ClamError::Failed {
                tool: "freshclam".to_string(),
                code: output.code,
                output: format!("{}{}", output.stdout, output.stderr)
                    .trim()
                    .to_string(),
            });
        }
        Ok(())
    }
}

/// Нужен фоновой проверке и проверке перед запуском: позволяет подменять ClamAV в тестах.
pub trait FileScanner {
    fn scan_files(&self, files: &[PathBuf]) -> Result<Vec<ScanResult>, ClamError>;
}

impl FileScanner for ClamAV {
    fn scan_files(&self, files: &[PathBuf]) -> Result<Vec<ScanResult>, ClamError> {
        ClamAV::scan_files(self, files)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_clean_infected_and_error_lines() {
        let files = vec![
            PathBuf::from("/data/a.txt"),
            PathBuf::from("/data/b.exe"),
            PathBuf::from("/data/c.bin"),
        ];
        let stdout = "/data/a.txt: OK\n/data/b.exe: Eicar-Test-Signature FOUND\n/data/c.bin: No such file or directory\n";

        let results = parse_output(stdout, &files);

        assert_eq!(results[0].status, ScanStatus::Clean);
        assert_eq!(
            results[1].status,
            ScanStatus::Infected {
                signature: "Eicar-Test-Signature".to_string()
            }
        );
        assert_eq!(
            results[2].status,
            ScanStatus::Error {
                message: "No such file or directory".to_string()
            }
        );
    }

    #[test]
    fn colons_inside_paths_and_messages_do_not_break_parsing() {
        let files = vec![PathBuf::from("/data/my: file.txt")];

        let results = parse_output("/data/my: file.txt: Can't open: denied\n", &files);

        assert_eq!(
            results[0].status,
            ScanStatus::Error {
                message: "Can't open: denied".to_string()
            }
        );
    }

    #[test]
    fn missing_result_is_an_error() {
        let files = vec![PathBuf::from("/data/a.txt")];
        let results = parse_output("", &files);
        assert!(results[0].is_error());
    }

    #[test]
    fn empty_file_list_skips_clamscan() {
        let results = ClamAV::default().scan_files(&[]).unwrap();
        assert!(results.is_empty());
    }
}
