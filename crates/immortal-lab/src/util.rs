//! Small shared helpers: randomness, hashing, clock.

use std::{
    fs::File,
    io::Read,
    time::{SystemTime, UNIX_EPOCH},
};

use immortal_client::market::MarketSigner;
use sha2::{Digest, Sha256};

pub fn random_32() -> Result<[u8; 32], String> {
    let mut bytes = [0_u8; 32];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|error| format!("could not read operating-system randomness: {error}"))?;
    Ok(bytes)
}

pub fn random_secret() -> Result<[u8; 32], String> {
    for _ in 0..32 {
        let bytes = random_32()?;
        if MarketSigner::from_secret_bytes(bytes).is_ok() {
            return Ok(bytes);
        }
    }
    Err("could not generate a valid throwaway lab key".to_owned())
}

pub fn digest(value: &str) -> String {
    lower_hex(&Sha256::digest(value.as_bytes()))
}

pub fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn parse_hex_32(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("expected 64 hex characters".to_owned());
    }
    let mut bytes = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks(2).enumerate() {
        let text = std::str::from_utf8(chunk).map_err(|error| error.to_string())?;
        bytes[index] =
            u8::from_str_radix(text, 16).map_err(|error| format!("invalid hex: {error}"))?;
    }
    Ok(bytes)
}

pub fn unix_now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| format!("system clock is before the Unix epoch: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip() {
        let bytes = [7_u8; 32];
        let hex = lower_hex(&bytes);
        assert_eq!(parse_hex_32(&hex), Ok(bytes));
        assert!(parse_hex_32("zz").is_err());
        assert!(parse_hex_32(&"a".repeat(63)).is_err());
    }
}
