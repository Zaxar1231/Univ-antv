//! Командная строка Univ-antv.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use antv::background::BackgroundScanner;
use antv::clam::{ClamAV, ScanStatus};
use antv::config::{database_dir, quarantine_dir};
use antv::executables::{run_checked, LaunchError};
use antv::quarantine::Quarantine;
use antv::scanner::scan_paths;
use antv::uninstall::engine::{is_success, run_uninstaller};
use antv::uninstall::leftovers::{
    default_search_roots, default_shortcut_roots, delete_leftovers, find_leftovers,
};
use antv::uninstall::registry::{find_registry_leftovers, list_installed_programs};
use antv::uninstall::InstalledProgram;

const EXIT_CLEAN: u8 = 0;
const EXIT_INFECTED: u8 = 1;
const EXIT_ERROR: u8 = 2;

#[derive(Parser)]
#[command(
    name = "antv",
    version,
    about = "Univ-antv — бесплатный антивирус с автоматической проверкой обновлений"
)]
struct Cli {
    /// Подробный журнал в stderr.
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Обновить базы сигнатур ClamAV.
    Update,
    /// Проверить файлы и папки.
    Scan {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Заражённые файлы перемещать в карантин.
        #[arg(long)]
        quarantine: bool,
    },
    /// Фоновая проверка новых и изменённых файлов.
    Watch {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Пауза между циклами, секунды.
        #[arg(long, default_value_t = 300.0)]
        interval: f64,
        /// Заражённые файлы перемещать в карантин.
        #[arg(long)]
        quarantine: bool,
    },
    /// Проверить программу и запустить её, если угроз не найдено.
    Run {
        program: PathBuf,
        /// Аргументы программы; передаются как есть.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Список установленных программ (Windows).
    Programs,
    /// Удалить программу вместе с остатками (Windows).
    Uninstall {
        /// Часть названия программы.
        name: String,
        /// Запустить деинсталлятор с окнами.
        #[arg(long)]
        interactive: bool,
        /// Удалить найденные остатки (нужен также --yes).
        #[arg(long)]
        delete_leftovers: bool,
        /// Подтвердить удаление остатков.
        #[arg(long)]
        yes: bool,
    },
    /// Управление карантином.
    Quarantine {
        #[command(subcommand)]
        action: QuarantineAction,
    },
}

#[derive(Subcommand)]
enum QuarantineAction {
    /// Показать файлы в карантине.
    List,
    /// Вернуть файл на исходное место.
    Restore { id: String },
    /// Удалить файл из карантина навсегда.
    Delete { id: String },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_logging(cli.verbose);

    let Some(command) = cli.command else {
        let mut help = <Cli as clap::CommandFactory>::command();
        let _ = help.print_help();
        println!();
        return ExitCode::from(EXIT_CLEAN);
    };

    let code = match dispatch(command) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("Ошибка: {error:#}");
            EXIT_ERROR
        }
    };
    ExitCode::from(code)
}

fn init_logging(verbose: bool) {
    let level = if verbose { "debug" } else { "info" };
    env_logger::Builder::new()
        .parse_filters(level)
        .format_target(false)
        .init();
}

fn dispatch(command: Command) -> Result<u8> {
    match command {
        Command::Update => cmd_update(),
        Command::Scan { paths, quarantine } => cmd_scan(&paths, quarantine),
        Command::Watch {
            paths,
            interval,
            quarantine,
        } => cmd_watch(paths, interval, quarantine),
        Command::Run { program, args } => cmd_run(&program, &args),
        Command::Programs => cmd_programs(),
        Command::Uninstall {
            name,
            interactive,
            delete_leftovers,
            yes,
        } => cmd_uninstall(&name, interactive, delete_leftovers, yes),
        Command::Quarantine { action } => cmd_quarantine(action),
    }
}

fn clam() -> ClamAV {
    ClamAV::new(database_dir())
}

fn open_quarantine() -> Result<Quarantine> {
    Quarantine::open(quarantine_dir()).context("не удалось открыть карантин")
}

fn cmd_update() -> Result<u8> {
    clam().update()?;
    println!("Базы сигнатур обновлены.");
    Ok(EXIT_CLEAN)
}

fn cmd_scan(paths: &[PathBuf], quarantine: bool) -> Result<u8> {
    let quarantine = if quarantine {
        Some(open_quarantine()?)
    } else {
        None
    };
    let results = scan_paths(paths, &clam(), quarantine.as_ref())?;

    let mut infected = 0;
    let mut errors = 0;
    for result in &results {
        match &result.status {
            ScanStatus::Infected { signature } => {
                infected += 1;
                println!("ЗАРАЖЁН  {}  ({signature})", result.path.display());
            }
            ScanStatus::Error { message } => {
                errors += 1;
                println!("ОШИБКА   {}  ({message})", result.path.display());
            }
            ScanStatus::Clean => {}
        }
    }
    println!(
        "Проверено файлов: {}, угроз: {infected}, ошибок: {errors}",
        results.len()
    );

    Ok(if infected > 0 {
        EXIT_INFECTED
    } else if errors > 0 {
        EXIT_ERROR
    } else {
        EXIT_CLEAN
    })
}

fn cmd_watch(paths: Vec<PathBuf>, interval: f64, quarantine: bool) -> Result<u8> {
    let quarantine = if quarantine {
        Some(open_quarantine()?)
    } else {
        None
    };
    let interval = Duration::try_from_secs_f64(interval)
        .context("интервал должен быть положительным числом")?;
    let stop = AtomicBool::new(false);
    let mut scanner = BackgroundScanner::new(paths, clam(), quarantine, interval);
    scanner.run(&stop);
    Ok(EXIT_CLEAN)
}

fn cmd_run(program: &Path, args: &[String]) -> Result<u8> {
    match run_checked(program, args, &clam()) {
        // Код выхода программы передаём как есть; отрицательные значения (сигнал) считаем ошибкой.
        Ok(code) => Ok(u8::try_from(code).unwrap_or(EXIT_ERROR)),
        Err(error @ LaunchError::Blocked { .. }) => {
            eprintln!("{error}");
            Ok(EXIT_INFECTED)
        }
        Err(error) => Err(error.into()),
    }
}

fn cmd_programs() -> Result<u8> {
    let programs = list_installed_programs()?;
    for program in &programs {
        println!(
            "{}  {}  [{}]",
            program.name, program.version, program.publisher
        );
    }
    println!("Всего: {}", programs.len());
    Ok(EXIT_CLEAN)
}

fn cmd_uninstall(name: &str, interactive: bool, delete: bool, confirmed: bool) -> Result<u8> {
    let programs = list_installed_programs()?;
    let needle = name.to_lowercase();
    let matches: Vec<&InstalledProgram> = programs
        .iter()
        .filter(|program| program.name.to_lowercase().contains(&needle))
        .collect();

    let program = match matches.as_slice() {
        [single] => *single,
        _ => {
            eprintln!("Найдено программ: {}. Уточните название.", matches.len());
            for program in matches {
                eprintln!("  {}", program.name);
            }
            return Ok(EXIT_ERROR);
        }
    };

    println!("Удаляем: {} {}", program.name, program.version);
    let return_code = run_uninstaller(program, !interactive)?;
    if !is_success(return_code) {
        eprintln!("Деинсталлятор завершился с кодом {return_code}.");
        return Ok(EXIT_ERROR);
    }
    println!("Деинсталлятор отработал.");

    let leftovers = find_leftovers(
        program,
        &default_search_roots(),
        &default_shortcut_roots(),
        find_registry_leftovers(&program.name, &program.publisher),
    );
    if leftovers.is_empty() {
        println!("Остатков не найдено.");
        return Ok(EXIT_CLEAN);
    }

    println!("Найдены остатки:");
    for directory in &leftovers.directories {
        println!("  папка:   {}", directory.display());
    }
    for shortcut in &leftovers.shortcuts {
        println!("  ярлык:   {}", shortcut.display());
    }
    for key in &leftovers.registry_keys {
        println!("  реестр:  {key}");
    }

    if !delete {
        println!("Чтобы удалить остатки, запустите команду с --delete-leftovers --yes.");
        return Ok(EXIT_CLEAN);
    }
    if !confirmed {
        eprintln!("Удаление не выполнено: добавьте --yes, чтобы подтвердить удаление остатков.");
        return Ok(EXIT_ERROR);
    }

    for action in delete_leftovers(
        &leftovers,
        &default_search_roots(),
        &default_shortcut_roots(),
    )? {
        println!("{action}");
    }
    Ok(EXIT_CLEAN)
}

fn cmd_quarantine(action: QuarantineAction) -> Result<u8> {
    let quarantine = open_quarantine()?;
    match action {
        QuarantineAction::List => {
            for entry in quarantine.list()? {
                println!(
                    "{}  {}  {}",
                    entry.id,
                    entry.signature,
                    entry.original_path.display()
                );
            }
        }
        QuarantineAction::Restore { id } => {
            let path = quarantine.restore(&id)?;
            println!("Восстановлено: {}", path.display());
        }
        QuarantineAction::Delete { id } => {
            quarantine.delete(&id)?;
            println!("Файл удалён из карантина.");
        }
    }
    Ok(EXIT_CLEAN)
}
