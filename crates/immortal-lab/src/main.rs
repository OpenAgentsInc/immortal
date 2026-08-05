//! Dev-only lab harness binary (immortal#32). Never deployed.

use immortal_lab::{
    cli::{self, Command, Step},
    relay::relay_url_from_env,
    state::LabPaths,
    steps,
};

fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let command = match cli::parse(&arguments) {
        Ok(command) => command,
        Err(error) => {
            eprintln!("immortal-lab: {error}");
            std::process::exit(1);
        }
    };
    match execute(command) {
        Ok(()) => {}
        Err(Exit::Failure(error)) => {
            eprintln!("immortal-lab: {error}");
            std::process::exit(1);
        }
        Err(Exit::Blocked(message)) => {
            eprintln!("{message}");
            std::process::exit(steps::BLOCKED_EXIT_CODE);
        }
    }
}

enum Exit {
    Failure(String),
    Blocked(String),
}

fn execute(command: Command) -> Result<(), Exit> {
    let paths = LabPaths::from_env();
    let relay_url = relay_url_from_env();
    match command {
        Command::Help => {
            println!("{}", cli::USAGE);
            Ok(())
        }
        Command::Discover => emit(steps::discover(&paths, &relay_url)),
        Command::Rfq { swap_type } => emit(steps::rfq(&paths, &relay_url, swap_type)),
        Command::Quote => emit(steps::quote(&paths, &relay_url)),
        Command::Verify => emit(steps::verify(&paths)),
        Command::Status => emit(steps::status(&paths)),
        Command::Fund => Err(Exit::Blocked(steps::blocked_message("fund"))),
        Command::Claim => Err(Exit::Blocked(steps::blocked_message("claim"))),
        Command::Refund => Err(Exit::Blocked(steps::blocked_message("refund"))),
        Command::Run { to } => {
            emit(steps::discover(&paths, &relay_url))?;
            if to >= Step::Rfq {
                emit(steps::rfq(&paths, &relay_url, cli::SwapShape::Submarine))?;
            }
            if to >= Step::Quote {
                emit(steps::quote(&paths, &relay_url))?;
            }
            if to >= Step::Verify {
                emit(steps::verify(&paths))?;
            }
            Ok(())
        }
    }
}

fn emit(result: Result<serde_json::Value, String>) -> Result<(), Exit> {
    match result {
        Ok(value) => {
            println!("{value}");
            Ok(())
        }
        Err(error) => Err(Exit::Failure(error)),
    }
}
