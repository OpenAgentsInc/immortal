//! Dev-only lab harness binary (immortal#32). Never deployed.

use immortal_lab::{
    cli::{self, Command, Step},
    funded::{self, FundedJourney},
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
    }
}

enum Exit {
    Failure(String),
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
        Command::Fund => emit(funded::run_funded_journey(FundedJourney::Submarine)),
        Command::Claim => emit(funded::run_funded_journey(FundedJourney::ReverseClaim)),
        Command::Refund => emit(funded::run_funded_journey(FundedJourney::ReverseRefund)),
        Command::FundedSmoke => funded::run_funded_smoke().map_err(Exit::Failure),
        Command::BoltzAdapter => emit(funded::run_boltz_adapter_session()),
        Command::Run { to } => {
            if to >= Step::Fund {
                emit(funded::run_funded_journey(FundedJourney::Submarine))?;
                if to >= Step::Claim {
                    emit(funded::run_funded_journey(FundedJourney::ReverseClaim))?;
                }
                if to >= Step::Refund {
                    emit(funded::run_funded_journey(FundedJourney::ReverseRefund))?;
                }
                return Ok(());
            }
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
