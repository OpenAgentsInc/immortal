//! Hand-rolled argument parsing. The workspace dependency allowlist has no
//! CLI crate, and the lab surface is small enough not to need one.

pub const USAGE: &str = "\
immortal-lab — dev-only wallet-side lab harness (immortal#32; never deployed)

USAGE:
    immortal-lab <COMMAND> [OPTIONS]

COMMANDS:
    discover            Query the relay for Provider Profiles and Offerings
    rfq [--swap-type submarine|reverse|chain]
                        Open a session and send a wrapped MKT-SWP RFQ
    quote               Wait for the provider's Quote and persist it
    topology-quotes     Discover two relays, collect two provider Quotes, and
                        select one with the fixture-pinned deterministic policy
    verify              Run the verify-before-fund gate over RFQ + Quote
    fund                Run the funded submarine journey through settlement
    claim               Run the reverse journey through requester claim
    refund              Run the reverse noncooperative-refund journey
    funded-smoke        Run fund, claim, and refund; write conformance evidence
    funded-topology     Compare two funded providers, execute rank one, and
                        cancel rank two before any selected funding broadcast
    adversarial-case    Execute the manifest-selected #18 process proof
    boltz-adapter       Run the process-gated transaction-first adapter callback
    status              Print persisted lab state
    run [--to STEP]     Run through STEP (discover, rfq, quote, verify, fund,
                        claim, or refund; defaults to verify)
    help                Print this text

ENVIRONMENT:
    IMMORTAL_LAB_RELAY_URL      ws:// loopback relay; falls back to
                                IMMORTAL_DEV_RELAY_URL, then ws://127.0.0.1:18080
    IMMORTAL_LAB_RELAY_URLS     exactly two distinct comma-separated loopback
                                relay URLs for topology-quotes
    IMMORTAL_LAB_STATE_DIR      session store directory (default target/lab-state)
    IMMORTAL_LAB_SESSION        act on this session id instead of the current one
    IMMORTAL_LAB_PROVIDER_PUBKEY
    IMMORTAL_LAB_OFFERING_ADDRESS
                                pin the discovery selection used by rfq

FUNDED ENVIRONMENT:
    The funded commands require the loopback bitcoind, peer CLN socket,
    provider health URL, client wallet seed, and evidence variables emitted
    by scripts/test-provider-funded.sh.
";

/// Lab steps in execution order. Each funded rail outcome uses its own swap
/// session so claim and refund cannot share custody state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Step {
    Discover,
    Rfq,
    Quote,
    Verify,
    Fund,
    Claim,
    Refund,
}

impl Step {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "discover" => Ok(Self::Discover),
            "rfq" => Ok(Self::Rfq),
            "quote" => Ok(Self::Quote),
            "verify" => Ok(Self::Verify),
            "fund" => Ok(Self::Fund),
            "claim" => Ok(Self::Claim),
            "refund" => Ok(Self::Refund),
            other => Err(format!("unknown step: {other}")),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Discover => "discover",
            Self::Rfq => "rfq",
            Self::Quote => "quote",
            Self::Verify => "verify",
            Self::Fund => "fund",
            Self::Claim => "claim",
            Self::Refund => "refund",
        }
    }
}

/// Supported swap shapes; the RFQ profile body is loaded from the pinned
/// full-session fixture for the chosen shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapShape {
    Submarine,
    Reverse,
    Chain,
}

impl SwapShape {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "submarine" => Ok(Self::Submarine),
            "reverse" => Ok(Self::Reverse),
            "chain" => Ok(Self::Chain),
            other => Err(format!(
                "unknown swap type: {other} (expected submarine, reverse, or chain)"
            )),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Submarine => "submarine",
            Self::Reverse => "reverse",
            Self::Chain => "chain",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Discover,
    Rfq { swap_type: SwapShape },
    Quote,
    TopologyQuotes,
    Verify,
    Fund,
    Claim,
    Refund,
    FundedSmoke,
    FundedTopology,
    AdversarialCase,
    BoltzAdapter,
    Status,
    Run { to: Step },
    Help,
}

pub fn parse(arguments: &[String]) -> Result<Command, String> {
    let mut arguments = arguments.iter();
    let command = arguments
        .next()
        .ok_or_else(|| "a command is required; run `immortal-lab help`".to_owned())?;
    let command = match command.as_str() {
        "discover" => Command::Discover,
        "rfq" => {
            let mut swap_type = SwapShape::Submarine;
            let mut rest = arguments.clone();
            while let Some(option) = rest.next() {
                match option.as_str() {
                    "--swap-type" => {
                        let value = rest
                            .next()
                            .ok_or_else(|| "--swap-type requires a value".to_owned())?;
                        swap_type = SwapShape::parse(value)?;
                    }
                    other => return Err(format!("unknown rfq option: {other}")),
                }
            }
            return Ok(Command::Rfq { swap_type });
        }
        "quote" => Command::Quote,
        "topology-quotes" => Command::TopologyQuotes,
        "verify" => Command::Verify,
        "fund" => Command::Fund,
        "claim" => Command::Claim,
        "refund" => Command::Refund,
        "funded-smoke" => Command::FundedSmoke,
        "funded-topology" => Command::FundedTopology,
        "adversarial-case" => Command::AdversarialCase,
        "boltz-adapter" => Command::BoltzAdapter,
        "status" => Command::Status,
        "run" => {
            let mut to = Step::Verify;
            let mut rest = arguments.clone();
            while let Some(option) = rest.next() {
                match option.as_str() {
                    "--to" => {
                        let value = rest
                            .next()
                            .ok_or_else(|| "--to requires a step name".to_owned())?;
                        to = Step::parse(value)?;
                    }
                    other => return Err(format!("unknown run option: {other}")),
                }
            }
            return Ok(Command::Run { to });
        }
        "help" | "--help" | "-h" => Command::Help,
        other => return Err(format!("unknown command: {other}; run `immortal-lab help`")),
    };
    if let Some(extra) = arguments.next() {
        return Err(format!("unexpected argument: {extra}"));
    }
    Ok(command)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn parses_every_bare_command() {
        assert_eq!(parse(&args(&["discover"])), Ok(Command::Discover));
        assert_eq!(parse(&args(&["quote"])), Ok(Command::Quote));
        assert_eq!(
            parse(&args(&["topology-quotes"])),
            Ok(Command::TopologyQuotes)
        );
        assert_eq!(parse(&args(&["verify"])), Ok(Command::Verify));
        assert_eq!(parse(&args(&["fund"])), Ok(Command::Fund));
        assert_eq!(parse(&args(&["claim"])), Ok(Command::Claim));
        assert_eq!(parse(&args(&["refund"])), Ok(Command::Refund));
        assert_eq!(parse(&args(&["funded-smoke"])), Ok(Command::FundedSmoke));
        assert_eq!(
            parse(&args(&["funded-topology"])),
            Ok(Command::FundedTopology)
        );
        assert_eq!(
            parse(&args(&["adversarial-case"])),
            Ok(Command::AdversarialCase)
        );
        assert_eq!(parse(&args(&["boltz-adapter"])), Ok(Command::BoltzAdapter));
        assert_eq!(parse(&args(&["status"])), Ok(Command::Status));
        assert_eq!(parse(&args(&["help"])), Ok(Command::Help));
    }

    #[test]
    fn rfq_defaults_to_submarine_and_accepts_each_shape() {
        assert_eq!(
            parse(&args(&["rfq"])),
            Ok(Command::Rfq {
                swap_type: SwapShape::Submarine
            })
        );
        for (name, shape) in [
            ("submarine", SwapShape::Submarine),
            ("reverse", SwapShape::Reverse),
            ("chain", SwapShape::Chain),
        ] {
            assert_eq!(
                parse(&args(&["rfq", "--swap-type", name])),
                Ok(Command::Rfq { swap_type: shape })
            );
        }
    }

    #[test]
    fn run_defaults_to_verify_and_accepts_funded_steps() {
        assert_eq!(
            parse(&args(&["run"])),
            Ok(Command::Run { to: Step::Verify })
        );
        assert_eq!(
            parse(&args(&["run", "--to", "quote"])),
            Ok(Command::Run { to: Step::Quote })
        );
        assert_eq!(
            parse(&args(&["run", "--to", "fund"])),
            Ok(Command::Run { to: Step::Fund })
        );
    }

    #[test]
    fn step_order_matches_execution_order() {
        assert!(Step::Discover < Step::Rfq);
        assert!(Step::Rfq < Step::Quote);
        assert!(Step::Quote < Step::Verify);
        assert!(Step::Verify < Step::Fund);
        assert!(Step::Fund < Step::Claim);
        assert!(Step::Claim < Step::Refund);
    }

    #[test]
    fn rejects_unknown_input() {
        assert!(parse(&args(&[])).is_err());
        assert!(parse(&args(&["swap"])).is_err());
        assert!(parse(&args(&["rfq", "--swap-type"])).is_err());
        assert!(parse(&args(&["rfq", "--swap-type", "atomic"])).is_err());
        assert!(parse(&args(&["discover", "extra"])).is_err());
        assert!(parse(&args(&["run", "--to", "teleport"])).is_err());
    }
}
