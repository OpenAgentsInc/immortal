use std::{error::Error, process::Command};

use serde_json::Value;

const ADVERSARIAL_LAB_FIXTURE: &str =
    include_str!("../../../tests/fixtures/lab/adversarial-v1.json");

#[test]
fn adversarial_lab_profile_fails_startup_outside_regtest() -> Result<(), Box<dyn Error>> {
    let fixture: Value = serde_json::from_str(ADVERSARIAL_LAB_FIXTURE)?;
    let profile = fixture
        .get("lab_profile")
        .and_then(Value::as_object)
        .ok_or("adversarial lab fixture has no lab profile")?;
    let environment = profile
        .get("environment")
        .and_then(Value::as_str)
        .ok_or("adversarial lab profile has no environment")?;
    let value = profile
        .get("value")
        .and_then(Value::as_str)
        .ok_or("adversarial lab profile has no value")?;

    for network in ["mainnet", "testnet", "signet"] {
        let output = provider_startup(network, environment, value)?;
        if output.status.success() {
            return Err(format!("{network} accepted the adversarial lab profile").into());
        }
        let stderr = String::from_utf8(output.stderr)?;
        if stderr.trim()
            != "provider configuration failed: provider setting IMMORTAL_PROVIDER_LAB_PROFILE is invalid"
        {
            return Err(format!("{network} failed for another reason: {stderr}").into());
        }
    }

    let regtest = provider_startup("regtest", environment, value)?;
    if regtest.status.success() {
        return Err("incomplete regtest configuration unexpectedly started".into());
    }
    let stderr = String::from_utf8(regtest.stderr)?;
    if stderr.trim()
        != "provider configuration failed: required provider setting IMMORTAL_PROVIDER_BITCOIND_HOST is missing"
    {
        return Err(format!("regtest rejected the lab profile: {stderr}").into());
    }
    Ok(())
}

fn provider_startup(
    network: &str,
    profile_environment: &str,
    profile_value: &str,
) -> Result<std::process::Output, std::io::Error> {
    Command::new(env!("CARGO_BIN_EXE_immortal-provider"))
        .arg("run")
        .env_clear()
        .env(
            "IMMORTAL_PROVIDER_DATABASE_URL",
            "postgresql://127.0.0.1/immortal_lab_profile",
        )
        .env("IMMORTAL_PROVIDER_RELAY_URL", "ws://127.0.0.1:17777")
        .env("IMMORTAL_PROVIDER_BITCOIN_NETWORK", network)
        .env(profile_environment, profile_value)
        .output()
}
