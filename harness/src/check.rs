//! A threshold check and its hash.
//!
//! The owner's consent names each check by its hash. The workload hashes the check it is given the same way the web
//! application, the API and the SDK do, so the API cannot swap one check for another under the same hash: the SHA-256 of
//! the canonical JSON of the normalized check (conditions sorted by column, values sorted, absent fields omitted), the
//! first 31 bytes of it as a field element.

use crate::consent::Bytes32;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;

const MAX_CONDITIONS: usize = 5;

/// Why a check was refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CheckError {
    /// The text is not a check: JSON of exactly `conditions` and `allowed_failure_permille`.
    #[error("not a threshold check")]
    Shape,
    /// A check has between one and five conditions.
    #[error("a check has 1 to 5 conditions")]
    Conditions,
}

/// A field that may be absent but, when present, must have a value: `null` is not the same as absent in the hash.
fn present<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    T::deserialize(deserializer).map(Some)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Condition {
    column: String,
    #[serde(default, deserialize_with = "present")]
    min: Option<String>,
    #[serde(default, deserialize_with = "present")]
    max: Option<String>,
    #[serde(default, deserialize_with = "present")]
    values: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Check {
    conditions: Vec<Condition>,
    allowed_failure_permille: u32,
}

/// A parsed check: its number of conditions and allowed failure, and its hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCheck {
    /// The number of conditions, which picks the threshold circuit.
    pub conditions: u32,
    /// The share of rows allowed to fail, in permille.
    pub allowed_failure_permille: u32,
    /// The check's hash as the consent names it: 0x and 64 hex digits, the field element left-padded.
    pub hash: Bytes32,
}

fn by_code_unit(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

fn json_string(text: &str) -> String {
    serde_json::Value::String(text.to_owned()).to_string()
}

/// The canonical JSON of the normalized check: keys sorted by UTF-16 code unit at every level.
fn canonical(check: &Check) -> String {
    let mut conditions: Vec<&Condition> = check.conditions.iter().collect();
    conditions.sort_by(|a, b| by_code_unit(&a.column, &b.column));
    let rendered: Vec<String> = conditions
        .iter()
        .map(|c| {
            let mut fields = vec![format!("\"column\":{}", json_string(&c.column))];
            if let Some(max) = &c.max {
                fields.push(format!("\"max\":{}", json_string(max)));
            }
            if let Some(min) = &c.min {
                fields.push(format!("\"min\":{}", json_string(min)));
            }
            if let Some(values) = &c.values {
                let mut sorted: Vec<&String> = values.iter().collect();
                sorted.sort_by(|a, b| by_code_unit(a, b));
                let items: Vec<String> = sorted.iter().map(|v| json_string(v)).collect();
                fields.push(format!("\"values\":[{}]", items.join(",")));
            }
            format!("{{{}}}", fields.join(","))
        })
        .collect();
    format!(
        "{{\"allowed_failure_permille\":{},\"conditions\":[{}]}}",
        check.allowed_failure_permille,
        rendered.join(",")
    )
}

/// Parses a check as the engine reads it and hashes it as the consent names it.
///
/// # Errors
///
/// [`CheckError::Shape`] for text that is not exactly a check and [`CheckError::Conditions`] for one with no condition or
/// more than five.
pub fn parse_check(text: &str) -> Result<ParsedCheck, CheckError> {
    let check: Check = serde_json::from_str(text).map_err(|_| CheckError::Shape)?;
    if check.conditions.is_empty() || check.conditions.len() > MAX_CONDITIONS {
        return Err(CheckError::Conditions);
    }
    let digest = Sha256::digest(canonical(&check).as_bytes());
    let mut hash = [0u8; 32];
    hash[1..].copy_from_slice(&digest[..31]);
    Ok(ParsedCheck {
        conditions: u32::try_from(check.conditions.len()).map_err(|_| CheckError::Conditions)?,
        allowed_failure_permille: check.allowed_failure_permille,
        hash: Bytes32(hash),
    })
}
