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
        let output = provider_startup(network, environment, value, None)?;
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

    let regtest = provider_startup("regtest", environment, value, None)?;
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

#[test]
fn cooperative_signing_gate_requires_the_exact_adversarial_profile() -> Result<(), Box<dyn Error>> {
    let without_profile = provider_startup("regtest", "", "", Some("true"))?;
    if without_profile.status.success() {
        return Err("cooperative signing started without the lab profile".into());
    }
    let stderr = String::from_utf8(without_profile.stderr)?;
    if stderr.trim()
        != "provider configuration failed: provider setting IMMORTAL_PROVIDER_LAB_COOPERATIVE_SIGNING is invalid"
    {
        return Err(format!("cooperative signing failed for another reason: {stderr}").into());
    }

    let with_profile = provider_startup(
        "regtest",
        "IMMORTAL_PROVIDER_LAB_PROFILE",
        "regtest_adversarial",
        Some("true"),
    )?;
    if with_profile.status.success() {
        return Err("incomplete cooperative lab configuration unexpectedly started".into());
    }
    let stderr = String::from_utf8(with_profile.stderr)?;
    if stderr.trim()
        != "provider configuration failed: required provider setting IMMORTAL_PROVIDER_BITCOIND_HOST is missing"
    {
        return Err(format!("cooperative lab gate was rejected: {stderr}").into());
    }
    let refused_value = "false";
    let refused = provider_startup(
        "regtest",
        "IMMORTAL_PROVIDER_LAB_PROFILE",
        "regtest_adversarial",
        Some(refused_value),
    )?;
    if refused.status.success() {
        return Err(format!("cooperative signing accepted {refused_value:?}").into());
    }
    let stderr = String::from_utf8(refused.stderr)?;
    if stderr.trim()
        != "provider configuration failed: provider setting IMMORTAL_PROVIDER_LAB_COOPERATIVE_SIGNING is invalid"
    {
        return Err(format!(
            "cooperative value {refused_value:?} failed for another reason: {stderr}"
        )
        .into());
    }

    let mainnet = provider_startup(
        "mainnet",
        "IMMORTAL_PROVIDER_LAB_PROFILE",
        "regtest_adversarial",
        Some("true"),
    )?;
    if mainnet.status.success() {
        return Err("mainnet accepted the cooperative adversarial profile".into());
    }
    let stderr = String::from_utf8(mainnet.stderr)?;
    if stderr.trim()
        != "provider configuration failed: provider setting IMMORTAL_PROVIDER_LAB_PROFILE is invalid"
    {
        return Err(
            format!("mainnet cooperative profile failed for another reason: {stderr}").into(),
        );
    }

    for disabled_value in [None, Some("")] {
        let profile_without_gate = provider_startup(
            "regtest",
            "IMMORTAL_PROVIDER_LAB_PROFILE",
            "regtest_adversarial",
            disabled_value,
        )?;
        if profile_without_gate.status.success() {
            return Err("incomplete profile-only lab configuration unexpectedly started".into());
        }
        let stderr = String::from_utf8(profile_without_gate.stderr)?;
        if stderr.trim()
            != "provider configuration failed: required provider setting IMMORTAL_PROVIDER_BITCOIND_HOST is missing"
        {
            return Err(format!("profile-only lab configuration was rejected: {stderr}").into());
        }
    }
    Ok(())
}

#[test]
fn production_cooperative_signing_gate_is_explicit() -> Result<(), Box<dyn Error>> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_immortal-provider"));
    let output = command
        .arg("run")
        .env_clear()
        .env(
            "IMMORTAL_PROVIDER_DATABASE_URL",
            "postgresql://127.0.0.1/immortal_cooperative_profile",
        )
        .env("IMMORTAL_PROVIDER_RELAY_URL", "ws://127.0.0.1:17777")
        .env("IMMORTAL_PROVIDER_BITCOIN_NETWORK", "mainnet")
        .env("IMMORTAL_PROVIDER_COOPERATIVE_SIGNING", "true")
        .output()?;
    if output.status.success() {
        return Err("incomplete cooperative production configuration unexpectedly started".into());
    }
    let stderr = String::from_utf8(output.stderr)?;
    if stderr.trim()
        != "provider configuration failed: required provider setting IMMORTAL_PROVIDER_BITCOIND_HOST is missing"
    {
        return Err(format!("production cooperative gate was rejected: {stderr}").into());
    }
    Ok(())
}

fn provider_startup(
    network: &str,
    profile_environment: &str,
    profile_value: &str,
    cooperative_signing: Option<&str>,
) -> Result<std::process::Output, std::io::Error> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_immortal-provider"));
    command
        .arg("run")
        .env_clear()
        .env(
            "IMMORTAL_PROVIDER_DATABASE_URL",
            "postgresql://127.0.0.1/immortal_lab_profile",
        )
        .env("IMMORTAL_PROVIDER_RELAY_URL", "ws://127.0.0.1:17777")
        .env("IMMORTAL_PROVIDER_BITCOIN_NETWORK", network);
    if !profile_environment.is_empty() {
        command.env(profile_environment, profile_value);
    }
    if let Some(cooperative_signing) = cooperative_signing {
        command.env(
            "IMMORTAL_PROVIDER_LAB_COOPERATIVE_SIGNING",
            cooperative_signing,
        );
    }
    command.output()
}
