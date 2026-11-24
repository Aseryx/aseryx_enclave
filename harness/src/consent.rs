//! The typed data of an attested job and the digest an enclave signs a result with.
//!
//! This is the Rust side of `consent.mjs` in `aseryx_digital_key`, which the decrypt Lit Action, the API and the app
//! use. Every digest here must equal the one that module computes: the tests check them against a vector that ethers'
//! `TypedDataEncoder` produced.

use serde::Deserialize;
use serde::de::{self, Deserializer, Visitor};
use serde_json::Value;
use sha3::{Digest, Keccak256};
use std::fmt;

/// The prefix of the digest an enclave signs a result with.
pub const RESULT_DOMAIN: &str = "aseryx-enclave-result-v1";

const DOMAIN_NAME: &str = "Aseryx";
const DOMAIN_VERSION: &str = "1";
const DOMAIN_TYPE: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
const MAX_CHECKS: usize = 5;
const MAX_CANONICAL_DEPTH: usize = 8;
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// Why a consent value or a result was refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConsentError {
    /// A value that must be 0x followed by 64 hex digits was not.
    #[error("not a bytes32")]
    Bytes32,
    /// A value that must be 0x followed by 40 hex digits was not.
    #[error("not an address")]
    Address,
    /// A value was not a decimal integer in the range of a uint256.
    #[error("not a uint256")]
    Uint256,
    /// A string was empty or longer than its field allows.
    #[error("not a string of 1 to {max} characters")]
    Text {
        /// The longest length the field allows.
        max: usize,
    },
    /// A threshold job did not name between one and five checks.
    #[error("needs 1 to {MAX_CHECKS} check hashes")]
    CheckCount,
    /// A firmware version was not a uint32.
    #[error("not a uint32")]
    Svn,
    /// A chain id was zero.
    #[error("the chain id is zero")]
    ChainId,
    /// A result cannot be written as canonical JSON.
    #[error("not canonical JSON: {0}")]
    Canonical(&'static str),
}

fn keccak(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// Thirty-two bytes, written as 0x and 64 hex digits (either letter case on input).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bytes32(pub [u8; 32]);

impl Bytes32 {
    /// Parses 0x followed by 64 hex digits.
    ///
    /// # Errors
    ///
    /// [`ConsentError::Bytes32`] for any other text.
    pub fn parse(text: &str) -> Result<Self, ConsentError> {
        let digits = text.strip_prefix("0x").ok_or(ConsentError::Bytes32)?;
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(digits, &mut bytes).map_err(|_| ConsentError::Bytes32)?;
        Ok(Self(bytes))
    }
}

impl fmt::Display for Bytes32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for Bytes32 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).map_err(de::Error::custom)
    }
}

/// A 20-byte account address, written as 0x and 40 hex digits (either letter case on input).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Address(pub [u8; 20]);

impl Address {
    /// Parses 0x followed by 40 hex digits.
    ///
    /// # Errors
    ///
    /// [`ConsentError::Address`] for any other text.
    pub fn parse(text: &str) -> Result<Self, ConsentError> {
        let digits = text.strip_prefix("0x").ok_or(ConsentError::Address)?;
        let mut bytes = [0u8; 20];
        hex::decode_to_slice(digits, &mut bytes).map_err(|_| ConsentError::Address)?;
        Ok(Self(bytes))
    }

    fn word(self) -> [u8; 32] {
        let mut word = [0u8; 32];
        word[12..].copy_from_slice(&self.0);
        word
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).map_err(de::Error::custom)
    }
}

/// An unsigned 256-bit integer, as its big-endian bytes. It reads from a decimal string or a non-negative integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Uint256(pub [u8; 32]);

impl Uint256 {
    /// Parses a decimal integer with no sign and no leading zero.
    ///
    /// # Errors
    ///
    /// [`ConsentError::Uint256`] for any other text, or a value above 2^256 - 1.
    pub fn parse(text: &str) -> Result<Self, ConsentError> {
        let valid = !text.is_empty()
            && text.len() <= 78
            && text.bytes().all(|b| b.is_ascii_digit())
            && (text == "0" || !text.starts_with('0'));
        if !valid {
            return Err(ConsentError::Uint256);
        }
        let mut value = [0u8; 32];
        for digit in text.bytes() {
            let mut carry = u16::from(digit - b'0');
            for byte in value.iter_mut().rev() {
                let next = u16::from(*byte) * 10 + carry;
                *byte = (next & 0xff) as u8;
                carry = next >> 8;
            }
            if carry != 0 {
                return Err(ConsentError::Uint256);
            }
        }
        Ok(Self(value))
    }

    /// The value as a decimal string, with no leading zeros.
    #[must_use]
    pub fn to_decimal(&self) -> String {
        let mut limbs = self.0;
        let mut digits = Vec::new();
        while limbs.iter().any(|b| *b != 0) {
            let mut remainder = 0u16;
            for byte in &mut limbs {
                let current = remainder * 256 + u16::from(*byte);
                *byte = (current / 10) as u8;
                remainder = current % 10;
            }
            digits.push(b'0' + remainder as u8);
        }
        if digits.is_empty() {
            digits.push(b'0');
        }
        digits.reverse();
        String::from_utf8(digits).expect("digits are ASCII")
    }

    /// An integer that fits in 64 bits.
    #[must_use]
    pub fn from_u64(value: u64) -> Self {
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        Self(bytes)
    }
}

impl<'de> Deserialize<'de> for Uint256 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct UintVisitor;
        impl Visitor<'_> for UintVisitor {
            type Value = Uint256;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a decimal string or a non-negative integer")
            }
            fn visit_str<E: de::Error>(self, text: &str) -> Result<Uint256, E> {
                Uint256::parse(text).map_err(E::custom)
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Uint256, E> {
                Ok(Uint256::from_u64(value))
            }
        }
        deserializer.deserialize_any(UintVisitor)
    }
}

/// A firmware version number: a uint32, read from a number or a decimal string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Svn(pub u32);

impl<'de> Deserialize<'de> for Svn {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SvnVisitor;
        impl Visitor<'_> for SvnVisitor {
            type Value = Svn;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a uint32 as a number or a decimal string")
            }
            fn visit_str<E: de::Error>(self, text: &str) -> Result<Svn, E> {
                let plain = !text.is_empty()
                    && text.bytes().all(|b| b.is_ascii_digit())
                    && (text == "0" || !text.starts_with('0'));
                if !plain {
                    return Err(E::custom(ConsentError::Svn));
                }
                text.parse()
                    .map(Svn)
                    .map_err(|_| E::custom(ConsentError::Svn))
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Svn, E> {
                u32::try_from(value)
                    .map(Svn)
                    .map_err(|_| E::custom(ConsentError::Svn))
            }
        }
        deserializer.deserialize_any(SvnVisitor)
    }
}

/// The four SEV-SNP firmware versions a token reports and a consent can set minimums for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tcb {
    /// The bootloader version.
    pub bootloader: u32,
    /// The trusted execution environment version.
    pub tee: u32,
    /// The SNP firmware version.
    pub snp: u32,
    /// The microcode version.
    pub microcode: u32,
}

impl Tcb {
    /// For each firmware version, the higher of `self` and `floor`.
    #[must_use]
    pub fn at_least(self, floor: Self) -> Self {
        Self {
            bootloader: self.bootloader.max(floor.bootloader),
            tee: self.tee.max(floor.tee),
            snp: self.snp.max(floor.snp),
            microcode: self.microcode.max(floor.microcode),
        }
    }
}

/// A non-empty string of at most `MAX` characters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Text<const MAX: usize>(String);

impl<const MAX: usize> Text<MAX> {
    /// Checks the length.
    ///
    /// # Errors
    ///
    /// [`ConsentError::Text`] for an empty string or one longer than `MAX` characters.
    pub fn new(text: String) -> Result<Self, ConsentError> {
        if text.is_empty() || text.chars().count() > MAX {
            return Err(ConsentError::Text { max: MAX });
        }
        Ok(Self(text))
    }
}

impl<'de, const MAX: usize> Deserialize<'de> for Text<MAX> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

/// One to five check hashes of a threshold job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckHashes(Vec<Bytes32>);

impl CheckHashes {
    /// The hashes, in the order the owner signed them.
    #[must_use]
    pub fn as_slice(&self) -> &[Bytes32] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for CheckHashes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let hashes = Vec::<Bytes32>::deserialize(deserializer)?;
        if hashes.is_empty() || hashes.len() > MAX_CHECKS {
            return Err(de::Error::custom(ConsentError::CheckCount));
        }
        Ok(Self(hashes))
    }
}

/// The chain and the Digital Key contract a consent is signed for. Callers pass the same two values they use for the
/// signed listing record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Domain {
    chain_id: u64,
    verifying_contract: Address,
}

impl Domain {
    /// A domain for a chain and the Digital Key contract.
    ///
    /// # Errors
    ///
    /// [`ConsentError::ChainId`] for chain id zero.
    pub fn new(chain_id: u64, verifying_contract: Address) -> Result<Self, ConsentError> {
        if chain_id == 0 {
            return Err(ConsentError::ChainId);
        }
        Ok(Self {
            chain_id,
            verifying_contract,
        })
    }

    fn separator(self) -> [u8; 32] {
        keccak(&[
            &keccak(&[DOMAIN_TYPE.as_bytes()]),
            &keccak(&[DOMAIN_NAME.as_bytes()]),
            &keccak(&[DOMAIN_VERSION.as_bytes()]),
            &Uint256::from_u64(self.chain_id).0,
            &self.verifying_contract.word(),
        ])
    }
}

/// A typed-data struct: its EIP-712 type string and its encoded fields.
trait Typed {
    const TYPE: &'static str;
    fn words(&self) -> Vec<[u8; 32]>;
}

fn text_word<const MAX: usize>(text: &Text<MAX>) -> [u8; 32] {
    keccak(&[text.0.as_bytes()])
}

fn svn_word(value: Svn) -> [u8; 32] {
    Uint256::from_u64(u64::from(value.0)).0
}

fn bool_word(value: bool) -> [u8; 32] {
    Uint256::from_u64(u64::from(value)).0
}

/// The digest the signer signs for a typed value in a domain.
fn digest<T: Typed>(value: &T, domain: Domain) -> Bytes32 {
    let words = value.words();
    let mut parts: Vec<&[u8]> = Vec::with_capacity(words.len() + 1);
    let type_hash = keccak(&[T::TYPE.as_bytes()]);
    parts.push(&type_hash);
    parts.extend(words.iter().map(<[u8; 32]>::as_slice));
    let struct_hash = keccak(&parts);
    Bytes32(keccak(&[&[0x19, 0x01], &domain.separator(), &struct_hash]))
}

/// The owner's consent to appraise a dataset in a named workload.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppraisalJob {
    /// The Digital Key token id.
    pub token_id: Uint256,
    /// The dataset's registry id.
    pub dataset: Text<200>,
    /// The manifest's content identifier.
    pub manifest_cid: Text<256>,
    /// The SHA-256 of the plaintext.
    pub plaintext_hash: Bytes32,
    /// The appraisal family.
    pub family: Text<64>,
    /// The rules version.
    pub rules_version: Text<64>,
    /// The workload identity: the SHA-256 of the container group's policy.
    pub workload_identity: Bytes32,
    /// The job id.
    pub job_id: Bytes32,
    /// The lowest bootloader version the signer accepts.
    pub min_bootloader_svn: Svn,
    /// The lowest trusted execution environment version the signer accepts.
    pub min_tee_svn: Svn,
    /// The lowest SNP firmware version the signer accepts.
    pub min_snp_svn: Svn,
    /// The lowest microcode version the signer accepts.
    pub min_microcode_svn: Svn,
    /// When the consent expires, in seconds since the epoch.
    pub expires_at: Uint256,
}

impl Typed for AppraisalJob {
    const TYPE: &'static str = "AppraisalJob(uint256 tokenId,string dataset,string manifestCid,bytes32 plaintextHash,string family,string rulesVersion,bytes32 workloadIdentity,bytes32 jobId,uint32 minBootloaderSvn,uint32 minTeeSvn,uint32 minSnpSvn,uint32 minMicrocodeSvn,uint256 expiresAt)";
    fn words(&self) -> Vec<[u8; 32]> {
        vec![
            self.token_id.0,
            text_word(&self.dataset),
            text_word(&self.manifest_cid),
            self.plaintext_hash.0,
            text_word(&self.family),
            text_word(&self.rules_version),
            self.workload_identity.0,
            self.job_id.0,
            svn_word(self.min_bootloader_svn),
            svn_word(self.min_tee_svn),
            svn_word(self.min_snp_svn),
            svn_word(self.min_microcode_svn),
            self.expires_at.0,
        ]
    }
}

impl AppraisalJob {
    /// The firmware minimums the signer asks for.
    #[must_use]
    pub fn min_tcb(&self) -> Tcb {
        Tcb {
            bootloader: self.min_bootloader_svn.0,
            tee: self.min_tee_svn.0,
            snp: self.min_snp_svn.0,
            microcode: self.min_microcode_svn.0,
        }
    }

    /// The digest the owner signs.
    #[must_use]
    pub fn digest(&self, domain: Domain) -> Bytes32 {
        digest(self, domain)
    }
}

/// The owner's consent to answer threshold checks in a named workload.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ThresholdJob {
    /// The Digital Key token id.
    pub token_id: Uint256,
    /// The dataset's registry id.
    pub dataset: Text<200>,
    /// The manifest's content identifier.
    pub manifest_cid: Text<256>,
    /// The SHA-256 of the plaintext.
    pub plaintext_hash: Bytes32,
    /// The appraisal family.
    pub family: Text<64>,
    /// The rules version.
    pub rules_version: Text<64>,
    /// The data label's hash, a field element.
    pub label_hash: Uint256,
    /// The checks to answer.
    pub check_hashes: CheckHashes,
    /// The workload identity: the SHA-256 of the container group's policy.
    pub workload_identity: Bytes32,
    /// The job id.
    pub job_id: Bytes32,
    /// The lowest bootloader version the signer accepts.
    pub min_bootloader_svn: Svn,
    /// The lowest trusted execution environment version the signer accepts.
    pub min_tee_svn: Svn,
    /// The lowest SNP firmware version the signer accepts.
    pub min_snp_svn: Svn,
    /// The lowest microcode version the signer accepts.
    pub min_microcode_svn: Svn,
    /// When the consent expires, in seconds since the epoch.
    pub expires_at: Uint256,
}

impl Typed for ThresholdJob {
    const TYPE: &'static str = "ThresholdJob(uint256 tokenId,string dataset,string manifestCid,bytes32 plaintextHash,string family,string rulesVersion,uint256 labelHash,bytes32[] checkHashes,bytes32 workloadIdentity,bytes32 jobId,uint32 minBootloaderSvn,uint32 minTeeSvn,uint32 minSnpSvn,uint32 minMicrocodeSvn,uint256 expiresAt)";
    fn words(&self) -> Vec<[u8; 32]> {
        let hashes: Vec<&[u8]> = self
            .check_hashes
            .as_slice()
            .iter()
            .map(|h| h.0.as_slice())
            .collect();
        vec![
            self.token_id.0,
            text_word(&self.dataset),
            text_word(&self.manifest_cid),
            self.plaintext_hash.0,
            text_word(&self.family),
            text_word(&self.rules_version),
            self.label_hash.0,
            keccak(&hashes),
            self.workload_identity.0,
            self.job_id.0,
            svn_word(self.min_bootloader_svn),
            svn_word(self.min_tee_svn),
            svn_word(self.min_snp_svn),
            svn_word(self.min_microcode_svn),
            self.expires_at.0,
        ]
    }
}

impl ThresholdJob {
    /// The firmware minimums the signer asks for.
    #[must_use]
    pub fn min_tcb(&self) -> Tcb {
        Tcb {
            bootloader: self.min_bootloader_svn.0,
            tee: self.min_tee_svn.0,
            snp: self.min_snp_svn.0,
            microcode: self.min_microcode_svn.0,
        }
    }

    /// The digest the owner signs.
    #[must_use]
    pub fn digest(&self, domain: Domain) -> Bytes32 {
        digest(self, domain)
    }
}

/// The buyer's consent to check a dispute's evidence in a named workload.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DisputeJob {
    /// The dispute id.
    pub dispute_id: Uint256,
    /// The Digital Key token id.
    pub token_id: Uint256,
    /// The dataset's registry id.
    pub dataset: Text<200>,
    /// The buyer's wallet.
    pub buyer: Address,
    /// The SHA-256 of the evidence plaintext.
    pub evidence_hash: Bytes32,
    /// The appraisal family.
    pub family: Text<64>,
    /// The rules version.
    pub rules_version: Text<64>,
    /// The workload identity: the SHA-256 of the container group's policy.
    pub workload_identity: Bytes32,
    /// The job id.
    pub job_id: Bytes32,
    /// The lowest bootloader version the signer accepts.
    pub min_bootloader_svn: Svn,
    /// The lowest trusted execution environment version the signer accepts.
    pub min_tee_svn: Svn,
    /// The lowest SNP firmware version the signer accepts.
    pub min_snp_svn: Svn,
    /// The lowest microcode version the signer accepts.
    pub min_microcode_svn: Svn,
    /// When the consent expires, in seconds since the epoch.
    pub expires_at: Uint256,
}

impl Typed for DisputeJob {
    const TYPE: &'static str = "DisputeJob(uint256 disputeId,uint256 tokenId,string dataset,address buyer,bytes32 evidenceHash,string family,string rulesVersion,bytes32 workloadIdentity,bytes32 jobId,uint32 minBootloaderSvn,uint32 minTeeSvn,uint32 minSnpSvn,uint32 minMicrocodeSvn,uint256 expiresAt)";
    fn words(&self) -> Vec<[u8; 32]> {
        vec![
            self.dispute_id.0,
            self.token_id.0,
            text_word(&self.dataset),
            self.buyer.word(),
            self.evidence_hash.0,
            text_word(&self.family),
            text_word(&self.rules_version),
            self.workload_identity.0,
            self.job_id.0,
            svn_word(self.min_bootloader_svn),
            svn_word(self.min_tee_svn),
            svn_word(self.min_snp_svn),
            svn_word(self.min_microcode_svn),
            self.expires_at.0,
        ]
    }
}

impl DisputeJob {
    /// The firmware minimums the signer asks for.
    #[must_use]
    pub fn min_tcb(&self) -> Tcb {
        Tcb {
            bootloader: self.min_bootloader_svn.0,
            tee: self.min_tee_svn.0,
            snp: self.min_snp_svn.0,
            microcode: self.min_microcode_svn.0,
        }
    }

    /// The digest the buyer signs.
    #[must_use]
    pub fn digest(&self, domain: Domain) -> Bytes32 {
        digest(self, domain)
    }
}

/// The owner's approval or refusal of a computed threshold answer.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ThresholdAnswerApproval {
    /// The job id.
    pub job_id: Bytes32,
    /// The check the answer is for.
    pub check_hash: Bytes32,
    /// The hash of the enclave-signed result for that check.
    pub result_hash: Bytes32,
    /// Whether the owner approves it.
    pub approved: bool,
}

impl Typed for ThresholdAnswerApproval {
    const TYPE: &'static str =
        "ThresholdAnswerApproval(bytes32 jobId,bytes32 checkHash,bytes32 resultHash,bool approved)";
    fn words(&self) -> Vec<[u8; 32]> {
        vec![
            self.job_id.0,
            self.check_hash.0,
            self.result_hash.0,
            bool_word(self.approved),
        ]
    }
}

impl ThresholdAnswerApproval {
    /// The digest the owner signs.
    #[must_use]
    pub fn digest(&self, domain: Domain) -> Bytes32 {
        digest(self, domain)
    }
}

/// Writes a value as canonical JSON: sorted field names of letters and digits, and strings, booleans, null and safe
/// integers only.
///
/// # Errors
///
/// [`ConsentError::Canonical`] for a float, an integer beyond 2^53 - 1, a field name outside letters and digits, or a
/// value nested deeper than eight levels.
pub fn canonical_json(value: &Value) -> Result<String, ConsentError> {
    fn write(value: &Value, depth: usize, out: &mut String) -> Result<(), ConsentError> {
        if depth > MAX_CANONICAL_DEPTH {
            return Err(ConsentError::Canonical("value too deep"));
        }
        match value {
            Value::Null => out.push_str("null"),
            Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Value::String(_) => out.push_str(&value.to_string()),
            Value::Number(n) => match (n.as_u64(), n.as_i64()) {
                (Some(u), _) if u <= MAX_SAFE_INTEGER => out.push_str(&u.to_string()),
                (None, Some(i)) if i.unsigned_abs() <= MAX_SAFE_INTEGER => {
                    out.push_str(&i.to_string())
                }
                _ => return Err(ConsentError::Canonical("number is not a safe integer")),
            },
            Value::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write(item, depth + 1, out)?;
                }
                out.push(']');
            }
            Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                out.push('{');
                for (i, key) in keys.into_iter().enumerate() {
                    let mut chars = key.chars();
                    let valid = chars.next().is_some_and(|c| c.is_ascii_alphabetic())
                        && chars.all(|c| c.is_ascii_alphanumeric());
                    if !valid {
                        return Err(ConsentError::Canonical("invalid field name"));
                    }
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(&Value::String(key.clone()).to_string());
                    out.push(':');
                    write(&map[key], depth + 1, out)?;
                }
                out.push('}');
            }
        }
        Ok(())
    }
    let mut out = String::new();
    write(value, 0, &mut out)?;
    Ok(out)
}

/// The digest an enclave signs a result with: keccak256 of the result domain tag followed by the canonical JSON of the
/// result.
///
/// # Errors
///
/// The errors of [`canonical_json`].
pub fn result_digest(result: &Value) -> Result<Bytes32, ConsentError> {
    let text = canonical_json(result)?;
    Ok(Bytes32(keccak(&[
        RESULT_DOMAIN.as_bytes(),
        text.as_bytes(),
    ])))
}
