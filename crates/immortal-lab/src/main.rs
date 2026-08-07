//! Dev-only lab harness binary (immortal#32). Never deployed.

use immortal_lab::{
    adversarial, browser_demo,
    cli::{self, Command, Step},
    funded::{self, DoomsdayCase, FundedJourney},
    relay::{relay_url_from_env, topology_relay_urls_from_env},
    state::LabPaths,
    steps,
};
use immortal_public_regtest_gateway as public_regtest_gateway;

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
        Command::TopologyQuotes => {
            let relay_urls = topology_relay_urls_from_env().map_err(Exit::Failure)?;
            emit(steps::topology_quotes(&paths, &relay_urls))
        }
        Command::Verify => emit(steps::verify(&paths)),
        Command::Status => emit(steps::status(&paths)),
        Command::Fund => emit(funded::run_funded_journey(FundedJourney::Submarine)),
        Command::Claim => emit(funded::run_funded_journey(FundedJourney::ReverseClaim)),
        Command::Refund => emit(funded::run_funded_journey(FundedJourney::ReverseRefund)),
        Command::FundedSmoke => funded::run_funded_smoke().map_err(Exit::Failure),
        Command::FundedTopology => emit(funded::run_funded_topology()),
        Command::DynamicFundedTopology => emit(funded::run_dynamic_funded_topology()),
        Command::AdversarialCase => emit(adversarial::run_from_env()),
        Command::DoomsdayPrepare => {
            let selected = std::env::var("IMMORTAL_LAB_ADVERSARIAL_CASE_ID").map_err(|_| {
                Exit::Failure("doomsday preparation requires the selected case".to_owned())
            })?;
            let case = DoomsdayCase::parse(&selected).map_err(Exit::Failure)?;
            emit(funded::prepare_doomsday_case(case))
        }
        Command::DoomsdayKeylessRequest => emit(funded::prepare_doomsday_keyless_request()),
        Command::DoomsdayKeylessExecutor => emit(funded::run_doomsday_keyless_executor()),
        Command::BoltzAdapter => emit(funded::run_boltz_adapter_session()),
        Command::BrowserDemoAdapter => emit(browser_demo::run_server()),
        Command::PublicRegtestGateway => emit(public_regtest_gateway::run_server()),
        Command::PublicRegtestWorkerOnce => emit(public_regtest_gateway::run_fixture_worker_once()),
        Command::PublicRegtestBindFixture => {
            emit(public_regtest_gateway::bind_fixture_authorization())
        }
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
