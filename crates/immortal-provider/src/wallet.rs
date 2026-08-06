//! Provider-owned deterministic wallet and signing boundary.

use immortal_core::liquid::{
    LiquidGenesisHash, LiquidPrevout, LiquidTransaction, liquid_taproot_script_spend_sighash,
    sign_liquid_taproot_sighash, verify_liquid_taproot_sighash_signature,
};
use immortal_core::mkt_swp_verify::{
    Musig2SecretNonce, Musig2Tweak, musig2_nonce_gen, musig2_partial_sign,
    musig2_tweaked_aggregate_key,
};
use secp256k1::{Keypair, Parity, PublicKey, Scalar, Secp256k1, SecretKey};
use sha2::{Digest, Sha256, Sha512};
use std::{
    env, fmt,
    fs::{self, File},
    io::Read,
    path::Path,
};

const SEED_HEX_LENGTH: usize = 64;
const HMAC_SHA512_BLOCK_LENGTH: usize = 128;
const HARDENED_INDEX: u32 = 1 << 31;
const TAPROOT_PURPOSE: u32 = 86;
const MAX_ACCOUNT_INDEX: u32 = HARDENED_INDEX - 1;
const SEED_FILE_ENV: &str = "IMMORTAL_PROVIDER_WALLET_SEED_FILE";
const MAX_SEED_PATH_BYTES: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletError {
    MissingSeedPath,
    SeedPathEncoding,
    SeedMetadata,
    SeedSymlink,
    SeedFileType,
    SeedPermissions,
    SeedRead,
    SeedEncoding,
    DerivationIndex,
    DerivationKey,
    AddressEncoding,
    Randomness,
    CooperativeSigning,
    LiquidSigning,
}

impl fmt::Display for WalletError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::MissingSeedPath => "wallet seed path is not configured",
            Self::SeedPathEncoding => "wallet seed path must be a bounded absolute UTF-8 path",
            Self::SeedMetadata => "wallet seed metadata could not be read",
            Self::SeedSymlink => "wallet seed path must not be a symbolic link",
            Self::SeedFileType => "wallet seed path must be a regular file",
            Self::SeedPermissions => "wallet seed file permissions must be 0600",
            Self::SeedRead => "wallet seed file could not be read",
            Self::SeedEncoding => "wallet seed must be exactly 32 lowercase-hex bytes",
            Self::DerivationIndex => "wallet derivation index is outside the BIP-86 range",
            Self::DerivationKey => "wallet key derivation produced an invalid key",
            Self::AddressEncoding => "taproot address could not be encoded",
            Self::Randomness => "operating-system randomness is unavailable",
            Self::CooperativeSigning => "cooperative signing failed closed",
            Self::LiquidSigning => "Liquid script-path signing failed closed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for WalletError {}

struct SecretSeed(Vec<u8>);

impl Drop for SecretSeed {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl fmt::Debug for SecretSeed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretSeed([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitcoinNetwork {
    Mainnet,
    Testnet,
    Signet,
    Regtest,
}

impl BitcoinNetwork {
    fn coin_type(self) -> u32 {
        match self {
            Self::Mainnet => 0,
            Self::Testnet | Self::Signet | Self::Regtest => 1,
        }
    }

    pub(crate) fn human_readable_part(self) -> &'static str {
        match self {
            Self::Mainnet => "bc",
            Self::Testnet | Self::Signet => "tb",
            Self::Regtest => "bcrt",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WalletPath {
    pub account: u32,
    pub change: bool,
    pub address_index: u32,
}

impl WalletPath {
    pub fn new(account: u32, change: bool, address_index: u32) -> Result<Self, WalletError> {
        if account > MAX_ACCOUNT_INDEX || address_index > MAX_ACCOUNT_INDEX {
            return Err(WalletError::DerivationIndex);
        }
        Ok(Self {
            account,
            change,
            address_index,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaprootAddress {
    pub path: WalletPath,
    pub internal_key: [u8; 32],
    pub output_key: [u8; 32],
    pub script_pubkey: [u8; 34],
    pub address: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletSignature {
    pub public_key: [u8; 32],
    pub signature: [u8; 64],
}

pub struct ProviderWallet {
    seed: SecretSeed,
    network: BitcoinNetwork,
}

pub struct WalletMusig2Nonce {
    path: WalletPath,
    context_digest: [u8; 32],
    keys: Vec<PublicKey>,
    tweaks: Vec<Musig2Tweak>,
    message: Vec<u8>,
    secret_nonce: Musig2SecretNonce,
}

impl fmt::Debug for WalletMusig2Nonce {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WalletMusig2Nonce")
            .field("path", &self.path)
            .field("context_digest", &self.context_digest)
            .field("public_nonce", &self.secret_nonce.public_nonce())
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

impl WalletMusig2Nonce {
    pub fn public_nonce(&self) -> [u8; 66] {
        self.secret_nonce.public_nonce()
    }
}

impl fmt::Debug for ProviderWallet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderWallet")
            .field("seed", &self.seed)
            .field("network", &self.network)
            .finish()
    }
}

impl ProviderWallet {
    pub fn load_from_environment(network: BitcoinNetwork) -> Result<Self, WalletError> {
        let path = match env::var(SEED_FILE_ENV) {
            Ok(path) => path,
            Err(env::VarError::NotPresent) => return Err(WalletError::MissingSeedPath),
            Err(env::VarError::NotUnicode(_)) => return Err(WalletError::SeedPathEncoding),
        };
        validate_seed_path(&path)?;
        Self::load(path, network)
    }

    pub fn load(path: impl AsRef<Path>, network: BitcoinNetwork) -> Result<Self, WalletError> {
        let path = path.as_ref();
        let metadata = fs::symlink_metadata(path).map_err(|_| WalletError::SeedMetadata)?;
        if metadata.file_type().is_symlink() {
            return Err(WalletError::SeedSymlink);
        }
        if !metadata.is_file() {
            return Err(WalletError::SeedFileType);
        }
        validate_seed_permissions(&metadata)?;
        if metadata.len() > (SEED_HEX_LENGTH + 1) as u64 {
            return Err(WalletError::SeedEncoding);
        }

        let file = open_seed_file(path)?;
        let opened_metadata = file.metadata().map_err(|_| WalletError::SeedMetadata)?;
        if !opened_metadata.is_file() || !same_seed_file(&metadata, &opened_metadata) {
            return Err(WalletError::SeedFileType);
        }
        validate_seed_permissions(&opened_metadata)?;
        if opened_metadata.len() > (SEED_HEX_LENGTH + 1) as u64 {
            return Err(WalletError::SeedEncoding);
        }
        let mut encoded = Vec::with_capacity(SEED_HEX_LENGTH + 1);
        file.take((SEED_HEX_LENGTH + 2) as u64)
            .read_to_end(&mut encoded)
            .map_err(|_| WalletError::SeedRead)?;
        if encoded.last() == Some(&b'\n') {
            encoded.pop();
        }
        if encoded.len() != SEED_HEX_LENGTH {
            encoded.fill(0);
            return Err(WalletError::SeedEncoding);
        }
        let seed = decode_lower_hex_32(&encoded).ok_or(WalletError::SeedEncoding);
        encoded.fill(0);
        Ok(Self {
            seed: SecretSeed(seed?.to_vec()),
            network,
        })
    }

    pub fn network(&self) -> BitcoinNetwork {
        self.network
    }

    pub fn derive_address(&self, path: WalletPath) -> Result<TaprootAddress, WalletError> {
        let derived_key = self.derive_bip86_key(path)?;
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &derived_key);
        let (internal_key, parity) = keypair.x_only_public_key();
        let tweak_bytes = tagged_hash("TapTweak", &internal_key.serialize());
        let tweak = Scalar::from_be_bytes(tweak_bytes).map_err(|_| WalletError::DerivationKey)?;
        let (output_key, _) = internal_key
            .add_tweak(&secp, &tweak)
            .map_err(|_| WalletError::DerivationKey)?;
        let mut script_pubkey = [0_u8; 34];
        script_pubkey[0] = 0x51;
        script_pubkey[1] = 0x20;
        script_pubkey[2..].copy_from_slice(&output_key.serialize());
        let address =
            encode_segwit_v1_address(self.network.human_readable_part(), &output_key.serialize())?;

        let mut normalized_key = derived_key;
        if parity == Parity::Odd {
            normalized_key = normalized_key.negate();
        }
        let tweaked_key = normalized_key
            .add_tweak(&tweak)
            .map_err(|_| WalletError::DerivationKey)?;
        let tweaked_keypair = Keypair::from_secret_key(&secp, &tweaked_key);
        if tweaked_keypair.x_only_public_key().0 != output_key {
            return Err(WalletError::DerivationKey);
        }

        Ok(TaprootAddress {
            path,
            internal_key: internal_key.serialize(),
            output_key: output_key.serialize(),
            script_pubkey,
            address,
        })
    }

    pub fn sign_script_path(
        &self,
        path: WalletPath,
        sighash: &[u8; 32],
    ) -> Result<WalletSignature, WalletError> {
        let secret_key = self.derive_bip86_key(path)?;
        sign_digest(secret_key, sighash)
    }

    pub fn sign_key_path(
        &self,
        path: WalletPath,
        sighash: &[u8; 32],
    ) -> Result<WalletSignature, WalletError> {
        let secret_key = self.derive_bip86_key(path)?;
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        let (internal_key, parity) = keypair.x_only_public_key();
        let tweak = Scalar::from_be_bytes(tagged_hash("TapTweak", &internal_key.serialize()))
            .map_err(|_| WalletError::DerivationKey)?;
        let normalized_key = if parity == Parity::Odd {
            secret_key.negate()
        } else {
            secret_key
        };
        let tweaked_key = normalized_key
            .add_tweak(&tweak)
            .map_err(|_| WalletError::DerivationKey)?;
        sign_digest(tweaked_key, sighash)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign_liquid_script_path(
        &self,
        path: WalletPath,
        transaction: &LiquidTransaction,
        prevouts: &[LiquidPrevout],
        input_index: usize,
        genesis_hash: LiquidGenesisHash,
        script: &[u8],
        control_block: &[u8],
    ) -> Result<WalletSignature, WalletError> {
        let secret_key = self.derive_bip86_key(path)?;
        let keypair = Keypair::from_secret_key(&Secp256k1::signing_only(), &secret_key);
        let public_key = keypair.x_only_public_key().0;
        let sighash = liquid_taproot_script_spend_sighash(
            transaction,
            prevouts,
            input_index,
            genesis_hash,
            script,
            control_block,
            None,
        )
        .map_err(|_| WalletError::LiquidSigning)?;
        let signature = sign_liquid_taproot_sighash(sighash, &keypair);
        verify_liquid_taproot_sighash_signature(sighash, &signature, public_key)
            .map_err(|_| WalletError::LiquidSigning)?;
        Ok(WalletSignature {
            public_key: public_key.serialize(),
            signature,
        })
    }

    pub fn begin_cooperative_signing(
        &self,
        path: WalletPath,
        context_digest: [u8; 32],
        keys: &[PublicKey],
        tweaks: &[Musig2Tweak],
        message: &[u8],
    ) -> Result<WalletMusig2Nonce, WalletError> {
        let secret_key = self.derive_even_key(path)?;
        let aggregate_key = musig2_tweaked_aggregate_key(keys, tweaks)
            .map_err(|_| WalletError::CooperativeSigning)?
            .serialize();
        let randomness = operating_system_randomness()?;
        let secret_nonce = musig2_nonce_gen(
            &secret_key,
            &aggregate_key,
            message,
            &context_digest,
            randomness,
        )
        .map_err(|_| WalletError::CooperativeSigning)?;
        Ok(WalletMusig2Nonce {
            path,
            context_digest,
            keys: keys.to_vec(),
            tweaks: tweaks.to_vec(),
            message: message.to_vec(),
            secret_nonce,
        })
    }

    pub fn sign_cooperative_partial(
        &self,
        nonce: &mut WalletMusig2Nonce,
        context_digest: [u8; 32],
        public_nonces: &[[u8; 66]],
    ) -> Result<[u8; 32], WalletError> {
        if nonce.context_digest != context_digest {
            return Err(WalletError::CooperativeSigning);
        }
        let secret_key = self.derive_even_key(nonce.path)?;
        musig2_partial_sign(
            &mut nonce.secret_nonce,
            &secret_key,
            &nonce.keys,
            public_nonces,
            &nonce.tweaks,
            &nonce.message,
        )
        .map_err(|_| WalletError::CooperativeSigning)
    }

    fn derive_bip86_key(&self, path: WalletPath) -> Result<SecretKey, WalletError> {
        let indexes = [
            TAPROOT_PURPOSE | HARDENED_INDEX,
            self.network.coin_type() | HARDENED_INDEX,
            path.account | HARDENED_INDEX,
            u32::from(path.change),
            path.address_index,
        ];
        let mut extended_key = ExtendedPrivateKey::master(&self.seed.0)?;
        for index in indexes {
            extended_key = extended_key.derive_child(index)?;
        }
        Ok(extended_key.secret_key)
    }

    fn derive_even_key(&self, path: WalletPath) -> Result<SecretKey, WalletError> {
        let secret_key = self.derive_bip86_key(path)?;
        let keypair = Keypair::from_secret_key(&Secp256k1::signing_only(), &secret_key);
        Ok(if keypair.x_only_public_key().1 == Parity::Odd {
            secret_key.negate()
        } else {
            secret_key
        })
    }

    #[cfg(test)]
    fn from_seed_material(seed: Vec<u8>, network: BitcoinNetwork) -> Self {
        Self {
            seed: SecretSeed(seed),
            network,
        }
    }
}

fn operating_system_randomness() -> Result<[u8; 32], WalletError> {
    let mut randomness = [0_u8; 32];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut randomness))
        .map_err(|_| WalletError::Randomness)?;
    Ok(randomness)
}

fn validate_seed_path(path: &str) -> Result<(), WalletError> {
    if path.is_empty()
        || path.len() > MAX_SEED_PATH_BYTES
        || path
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
        || !Path::new(path).is_absolute()
    {
        return Err(WalletError::SeedPathEncoding);
    }
    Ok(())
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
fn open_seed_file(path: &Path) -> Result<File, WalletError> {
    use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt};

    #[cfg(any(target_os = "linux", target_os = "android"))]
    const NO_FOLLOW: i32 = 0x20_000;
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    const NO_FOLLOW: i32 = 0x100;

    OpenOptions::new()
        .read(true)
        .custom_flags(NO_FOLLOW)
        .open(path)
        .map_err(|_| WalletError::SeedRead)
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)))]
fn open_seed_file(path: &Path) -> Result<File, WalletError> {
    File::open(path).map_err(|_| WalletError::SeedRead)
}

#[cfg(unix)]
fn same_seed_file(before: &fs::Metadata, opened: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    before.dev() == opened.dev() && before.ino() == opened.ino()
}

#[cfg(not(unix))]
fn same_seed_file(_before: &fs::Metadata, _opened: &fs::Metadata) -> bool {
    false
}

struct ExtendedPrivateKey {
    secret_key: SecretKey,
    chain_code: [u8; 32],
}

impl ExtendedPrivateKey {
    fn master(seed: &[u8]) -> Result<Self, WalletError> {
        let digest = hmac_sha512(b"Bitcoin seed", seed);
        let mut secret_bytes = [0_u8; 32];
        secret_bytes.copy_from_slice(&digest[..32]);
        let secret_key =
            SecretKey::from_byte_array(secret_bytes).map_err(|_| WalletError::DerivationKey)?;
        secret_bytes.fill(0);
        let mut chain_code = [0_u8; 32];
        chain_code.copy_from_slice(&digest[32..]);
        Ok(Self {
            secret_key,
            chain_code,
        })
    }

    fn derive_child(&self, index: u32) -> Result<Self, WalletError> {
        let mut data = Vec::with_capacity(37);
        if index & HARDENED_INDEX != 0 {
            data.push(0);
            data.extend_from_slice(&self.secret_key.secret_bytes());
        } else {
            let secp = Secp256k1::new();
            data.extend_from_slice(
                &PublicKey::from_secret_key(&secp, &self.secret_key).serialize(),
            );
        }
        data.extend_from_slice(&index.to_be_bytes());
        let digest = hmac_sha512(&self.chain_code, &data);
        data.fill(0);
        let mut tweak_bytes = [0_u8; 32];
        tweak_bytes.copy_from_slice(&digest[..32]);
        let tweak = Scalar::from_be_bytes(tweak_bytes).map_err(|_| WalletError::DerivationKey)?;
        tweak_bytes.fill(0);
        let secret_key = self
            .secret_key
            .add_tweak(&tweak)
            .map_err(|_| WalletError::DerivationKey)?;
        let mut chain_code = [0_u8; 32];
        chain_code.copy_from_slice(&digest[32..]);
        Ok(Self {
            secret_key,
            chain_code,
        })
    }
}

fn sign_digest(secret_key: SecretKey, sighash: &[u8; 32]) -> Result<WalletSignature, WalletError> {
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let public_key = keypair.x_only_public_key().0.serialize();
    let signature = secp
        .sign_schnorr_no_aux_rand(sighash, &keypair)
        .to_byte_array();
    Ok(WalletSignature {
        public_key,
        signature,
    })
}

fn hmac_sha512(key: &[u8], message: &[u8]) -> [u8; 64] {
    let mut normalized_key = [0_u8; HMAC_SHA512_BLOCK_LENGTH];
    if key.len() > HMAC_SHA512_BLOCK_LENGTH {
        let digest = Sha512::digest(key);
        normalized_key[..64].copy_from_slice(&digest);
    } else {
        normalized_key[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = [0x36_u8; HMAC_SHA512_BLOCK_LENGTH];
    let mut outer_pad = [0x5c_u8; HMAC_SHA512_BLOCK_LENGTH];
    for ((inner, outer), key_byte) in inner_pad
        .iter_mut()
        .zip(outer_pad.iter_mut())
        .zip(normalized_key)
    {
        *inner ^= key_byte;
        *outer ^= key_byte;
    }
    normalized_key.fill(0);

    let mut inner = Sha512::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner_digest = inner.finalize();
    inner_pad.fill(0);

    let mut outer = Sha512::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    let digest: [u8; 64] = outer.finalize().into();
    outer_pad.fill(0);
    digest
}

fn tagged_hash(tag: &str, message: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag.as_bytes());
    let mut digest = Sha256::new();
    digest.update(tag_hash);
    digest.update(tag_hash);
    digest.update(message);
    digest.finalize().into()
}

fn decode_lower_hex_32(encoded: &[u8]) -> Option<[u8; 32]> {
    if encoded.len() != SEED_HEX_LENGTH {
        return None;
    }
    let mut output = [0_u8; 32];
    for (index, pair) in encoded.chunks_exact(2).enumerate() {
        let high = lower_hex_value(*pair.first()?)?;
        let low = lower_hex_value(*pair.get(1)?)?;
        *output.get_mut(index)? = (high << 4) | low;
    }
    Some(output)
}

fn lower_hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(unix)]
fn validate_seed_permissions(metadata: &fs::Metadata) -> Result<(), WalletError> {
    use std::os::unix::fs::PermissionsExt;

    if metadata.permissions().mode() & 0o777 != 0o600 {
        return Err(WalletError::SeedPermissions);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_seed_permissions(_metadata: &fs::Metadata) -> Result<(), WalletError> {
    Err(WalletError::SeedPermissions)
}

pub(crate) fn encode_segwit_v1_address(
    hrp: &str,
    program: &[u8; 32],
) -> Result<String, WalletError> {
    let mut values = Vec::with_capacity(53);
    values.push(1);
    values.extend(convert_bits(program, 8, 5, true)?);
    let checksum = bech32m_checksum(hrp, &values);
    values.extend(checksum);
    let mut output = String::with_capacity(hrp.len() + 1 + values.len());
    output.push_str(hrp);
    output.push('1');
    const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    for value in values {
        let character = *CHARSET
            .get(usize::from(value))
            .ok_or(WalletError::AddressEncoding)?;
        output.push(char::from(character));
    }
    Ok(output)
}

fn convert_bits(
    input: &[u8],
    from_bits: u32,
    to_bits: u32,
    pad: bool,
) -> Result<Vec<u8>, WalletError> {
    let maximum_value = (1_u32 << to_bits) - 1;
    let maximum_accumulator = (1_u32 << (from_bits + to_bits - 1)) - 1;
    let mut accumulator = 0_u32;
    let mut bit_count = 0_u32;
    let mut output = Vec::new();
    for value in input {
        if u32::from(*value) >> from_bits != 0 {
            return Err(WalletError::AddressEncoding);
        }
        accumulator = ((accumulator << from_bits) | u32::from(*value)) & maximum_accumulator;
        bit_count += from_bits;
        while bit_count >= to_bits {
            bit_count -= to_bits;
            output.push(((accumulator >> bit_count) & maximum_value) as u8);
        }
    }
    if pad && bit_count > 0 {
        output.push(((accumulator << (to_bits - bit_count)) & maximum_value) as u8);
    } else if bit_count >= from_bits
        || ((accumulator << (to_bits - bit_count)) & maximum_value) != 0
    {
        return Err(WalletError::AddressEncoding);
    }
    Ok(output)
}

fn bech32m_checksum(hrp: &str, values: &[u8]) -> [u8; 6] {
    let mut expanded = Vec::with_capacity(hrp.len() * 2 + 1 + values.len() + 6);
    expanded.extend(hrp.bytes().map(|byte| byte >> 5));
    expanded.push(0);
    expanded.extend(hrp.bytes().map(|byte| byte & 31));
    expanded.extend_from_slice(values);
    expanded.extend_from_slice(&[0; 6]);
    let polymod = bech32_polymod(&expanded) ^ 0x2bc8_30a3;
    let mut checksum = [0_u8; 6];
    for (position, value) in checksum.iter_mut().enumerate() {
        let shift = 5 * (5 - position);
        *value = ((polymod >> shift) & 31) as u8;
    }
    checksum
}

fn bech32_polymod(values: &[u8]) -> u32 {
    const GENERATORS: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut checksum = 1_u32;
    for value in values {
        let top = checksum >> 25;
        checksum = ((checksum & 0x01ff_ffff) << 5) ^ u32::from(*value);
        for (index, generator) in GENERATORS.iter().enumerate() {
            if (top >> index) & 1 != 0 {
                checksum ^= generator;
            }
        }
    }
    checksum
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Secp256k1, XOnlyPublicKey, schnorr::Signature};
    use std::{
        error::Error,
        fs::OpenOptions,
        io::Write,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_TEST_FILE: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn bip86_first_receiving_address_matches_published_vector() -> Result<(), Box<dyn Error>> {
        let seed = decode_hex(
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
             9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
        )?;
        let wallet = ProviderWallet::from_seed_material(seed, BitcoinNetwork::Mainnet);
        let path = WalletPath::new(0, false, 0)?;
        let address = wallet.derive_address(path)?;
        assert_eq!(
            encode_hex(&address.internal_key),
            "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"
        );
        assert_eq!(
            encode_hex(&address.output_key),
            "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"
        );
        assert_eq!(
            address.address,
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
        );
        Ok(())
    }

    #[test]
    fn seed_loader_rejects_weak_permissions_and_symlinks() -> Result<(), Box<dyn Error>> {
        let path = temporary_path("seed");
        write_seed_file(&path, 0o600)?;
        let wallet = ProviderWallet::load(&path, BitcoinNetwork::Regtest)?;
        assert!(!format!("{wallet:?}").contains("00010203"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::{PermissionsExt, symlink};

            fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
            assert_eq!(
                ProviderWallet::load(&path, BitcoinNetwork::Regtest).err(),
                Some(WalletError::SeedPermissions)
            );
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
            let link = temporary_path("seed-link");
            symlink(&path, &link)?;
            assert_eq!(
                ProviderWallet::load(&link, BitcoinNetwork::Regtest).err(),
                Some(WalletError::SeedSymlink)
            );
            fs::remove_file(link)?;
        }

        fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn seed_loader_rejects_uppercase_or_wrong_length() -> Result<(), Box<dyn Error>> {
        let uppercase = temporary_path("seed-uppercase");
        write_private_file(
            &uppercase,
            b"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F\n",
            0o600,
        )?;
        assert_eq!(
            ProviderWallet::load(&uppercase, BitcoinNetwork::Regtest).err(),
            Some(WalletError::SeedEncoding)
        );
        fs::remove_file(uppercase)?;

        let short = temporary_path("seed-short");
        write_private_file(&short, b"00\n", 0o600)?;
        assert_eq!(
            ProviderWallet::load(&short, BitcoinNetwork::Regtest).err(),
            Some(WalletError::SeedEncoding)
        );
        fs::remove_file(short)?;
        Ok(())
    }

    #[test]
    fn configured_seed_path_is_bounded_absolute_utf8() {
        assert!(validate_seed_path("/var/lib/immortal-provider/wallet.seed").is_ok());
        assert_eq!(
            validate_seed_path("wallet.seed"),
            Err(WalletError::SeedPathEncoding)
        );
        assert_eq!(
            validate_seed_path(&format!("/{}", "a".repeat(MAX_SEED_PATH_BYTES))),
            Err(WalletError::SeedPathEncoding)
        );
    }

    #[test]
    fn script_and_key_path_signatures_verify_for_the_derived_keys() -> Result<(), Box<dyn Error>> {
        let wallet = ProviderWallet::from_seed_material(vec![7_u8; 32], BitcoinNetwork::Regtest);
        let path = WalletPath::new(0, false, 9)?;
        let sighash = [42_u8; 32];
        let script_signature = wallet.sign_script_path(path, &sighash)?;
        verify_signature(&script_signature, &sighash)?;
        assert_eq!(script_signature, wallet.sign_script_path(path, &sighash)?);

        let key_signature = wallet.sign_key_path(path, &sighash)?;
        verify_signature(&key_signature, &sighash)?;
        assert_eq!(key_signature, wallet.sign_key_path(path, &sighash)?);
        let address = wallet.derive_address(path)?;
        assert_eq!(key_signature.public_key, address.output_key);
        assert_ne!(script_signature.public_key, key_signature.public_key);
        Ok(())
    }

    #[test]
    fn cooperative_nonce_refuses_a_changed_context_before_consumption() -> Result<(), Box<dyn Error>>
    {
        let wallet = ProviderWallet::from_seed_material(vec![8_u8; 32], BitcoinNetwork::Regtest);
        let first_path = WalletPath::new(0, false, 20)?;
        let second_path = WalletPath::new(0, false, 21)?;
        let first_key = wallet.derive_even_key(first_path)?;
        let second_key = wallet.derive_even_key(second_path)?;
        let secp = Secp256k1::signing_only();
        let keys = [
            PublicKey::from_secret_key(&secp, &first_key),
            PublicKey::from_secret_key(&secp, &second_key),
        ];
        let context_digest = [12; 32];
        let message = [13; 32];
        let mut first_nonce =
            wallet.begin_cooperative_signing(first_path, context_digest, &keys, &[], &message)?;
        let second_nonce =
            wallet.begin_cooperative_signing(second_path, context_digest, &keys, &[], &message)?;
        let public_nonces = [first_nonce.public_nonce(), second_nonce.public_nonce()];

        assert_eq!(
            wallet
                .sign_cooperative_partial(&mut first_nonce, [14; 32], &public_nonces)
                .err(),
            Some(WalletError::CooperativeSigning)
        );
        assert!(!first_nonce.secret_nonce.is_consumed());
        wallet.sign_cooperative_partial(&mut first_nonce, context_digest, &public_nonces)?;
        assert!(first_nonce.secret_nonce.is_consumed());
        Ok(())
    }

    fn verify_signature(
        signature: &WalletSignature,
        sighash: &[u8; 32],
    ) -> Result<(), Box<dyn Error>> {
        let secp = Secp256k1::verification_only();
        let public_key = XOnlyPublicKey::from_byte_array(signature.public_key)?;
        let signature = Signature::from_byte_array(signature.signature);
        secp.verify_schnorr(&signature, sighash, &public_key)?;
        Ok(())
    }

    fn temporary_path(label: &str) -> std::path::PathBuf {
        let sequence = NEXT_TEST_FILE.fetch_add(1, Ordering::Relaxed);
        env::temp_dir().join(format!(
            "immortal-provider-wallet-{label}-{}-{sequence}",
            std::process::id()
        ))
    }

    fn write_seed_file(path: &Path, mode: u32) -> Result<(), Box<dyn Error>> {
        write_private_file(
            path,
            b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n",
            mode,
        )
    }

    fn write_private_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), Box<dyn Error>> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(mode);
        }
        let mut file = options.open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    }

    fn decode_hex(encoded: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        let encoded = encoded.replace([' ', '\n'], "");
        if encoded.len() % 2 != 0 {
            return Err("odd hex length".into());
        }
        let mut decoded = Vec::with_capacity(encoded.len() / 2);
        for pair in encoded.as_bytes().chunks_exact(2) {
            let high = lower_hex_value(pair[0]).ok_or("hex")?;
            let low = lower_hex_value(pair[1]).ok_or("hex")?;
            decoded.push((high << 4) | low);
        }
        Ok(decoded)
    }

    fn encode_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        encoded
    }
}
