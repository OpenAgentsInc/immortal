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
    verify              Run the verify-before-fund gate over RFQ + Quote
    fund                BLOCKED on immortal#25 (provider rails) — stub
    claim               BLOCKED on immortal#25 (provider rails) — stub
    refund              BLOCKED on immortal#25 (provider rails) — stub
    status              Print persisted lab state
    run [--to STEP]     Run discover -> rfq -> quote -> verify up to STEP
                        (STEP defaults to verify)
    help                Print this text

ENVIRONMENT:
    IMMORTAL_LAB_RELAY_URL      ws:// loopback relay; falls back to
                                IMMORTAL_DEV_RELAY_URL, then ws://127.0.0.1:18080
    IMMORTAL_LAB_STATE_DIR      session store directory (default target/lab-state)
    IMMORTAL_LAB_SESSION        act on this session id instead of the current one
    IMMORTAL_LAB_PROVIDER_PUBKEY
    IMMORTAL_LAB_OFFERING_ADDRESS
                                pin the discovery selection used by rfq
";

/// The four implemented lab steps, in execution order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Step {
    Discover,
    Rfq,
    Quote,
    Verify,
}

impl Step {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "discover" => Ok(Self::Discover),
            "rfq" => Ok(Self::Rfq),
            "quote" => Ok(Self::Quote),
            "verify" => Ok(Self::Verify),
            "fund" | "claim" | "refund" => Err(format!(
                "step {value} is blocked on immortal#25 (provider rails); \
                 run stops at verify"
            )),
            other => Err(format!("unknown step: {other}")),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Discover => "discover",
            Self::Rfq => "rfq",
            Self::Quote => "quote",
            Self::Verify => "verify",
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
    Verify,
    Fund,
    Claim,
    Refund,
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
        "verify" => Command::Verify,
        "fund" => Command::Fund,
        "claim" => Command::Claim,
        "refund" => Command::Refund,
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
        assert_eq!(parse(&args(&["verify"])), Ok(Command::Verify));
        assert_eq!(parse(&args(&["fund"])), Ok(Command::Fund));
        assert_eq!(parse(&args(&["claim"])), Ok(Command::Claim));
        assert_eq!(parse(&args(&["refund"])), Ok(Command::Refund));
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
    fn run_defaults_to_verify_and_bounds_at_verify() {
        assert_eq!(
            parse(&args(&["run"])),
            Ok(Command::Run { to: Step::Verify })
        );
        assert_eq!(
            parse(&args(&["run", "--to", "quote"])),
            Ok(Command::Run { to: Step::Quote })
        );
        let blocked = parse(&args(&["run", "--to", "fund"]));
        assert!(blocked.is_err());
        assert!(blocked.unwrap_err().contains("immortal#25"));
    }

    #[test]
    fn step_order_matches_execution_order() {
        assert!(Step::Discover < Step::Rfq);
        assert!(Step::Rfq < Step::Quote);
        assert!(Step::Quote < Step::Verify);
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
