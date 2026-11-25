//! Reading a snarkjs `.zkey` file into an arkworks Groth16 proving key.
//!
//! The reader follows the layout `snarkjs zkey` writes (a binary container of numbered sections) and is adapted from
//! the `ark-circom` crate's `zkey.rs` (MIT OR Apache-2.0, <https://github.com/arkworks-rs/circom-compat>), which this
//! crate does not depend on so the image carries one WebAssembly runtime. Points are stored in Montgomery form and the
//! coefficients multiplied by R squared, as snarkjs writes them. The file is public data, pinned by its SHA-256 before it
//! is read.

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ff::{BigInteger256, PrimeField, Zero};
use ark_groth16::{ProvingKey, VerifyingKey};
use std::collections::HashMap;

const SECTION_HEADER: u32 = 2;
const SECTION_IC: u32 = 3;
const SECTION_COEFFS: u32 = 4;
const SECTION_A: u32 = 5;
const SECTION_B1: u32 = 6;
const SECTION_B2: u32 = 7;
const SECTION_L: u32 = 8;
const SECTION_H: u32 = 9;
const FIELD_BYTES: u32 = 32;
const MAX_VARIABLES: usize = 1 << 24;

/// Why a zkey was refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ZkeyError {
    /// The file ends before a value it declares, or declares a section it does not contain.
    #[error("the zkey is truncated or lacks a section")]
    Truncated,
    /// The file is not a Groth16 zkey of this curve and field.
    #[error("the zkey is not a Groth16 zkey over BN254")]
    Format,
    /// A count or an index is outside what the header allows.
    #[error("the zkey declares a size or an index outside its own bounds")]
    Bounds,
}

/// The A and B constraint matrices of the circuit; C is implied by the witness map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Matrices {
    /// The number of public variables plus the constant one.
    pub num_instance_variables: usize,
    /// The number of constraints, without the ones that bind the public inputs.
    pub num_constraints: usize,
    /// The A matrix: for each constraint, its coefficients and signals.
    pub a: Vec<Vec<(Fr, usize)>>,
    /// The B matrix.
    pub b: Vec<Vec<(Fr, usize)>>,
}

/// A proving key with the matrices of its circuit.
#[derive(Debug, Clone)]
pub struct Zkey {
    /// The Groth16 proving key.
    pub proving_key: ProvingKey<Bn254>,
    /// The circuit's matrices.
    pub matrices: Matrices,
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn at(bytes: &'a [u8], at: usize) -> Self {
        Self { bytes, at }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ZkeyError> {
        let end = self.at.checked_add(n).ok_or(ZkeyError::Truncated)?;
        let out = self.bytes.get(self.at..end).ok_or(ZkeyError::Truncated)?;
        self.at = end;
        Ok(out)
    }

    fn u32(&mut self) -> Result<u32, ZkeyError> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().map_err(|_| ZkeyError::Truncated)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, ZkeyError> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().map_err(|_| ZkeyError::Truncated)?,
        ))
    }

    fn bigint(&mut self) -> Result<BigInteger256, ZkeyError> {
        let bytes = self.take(32)?;
        let mut limbs = [0u64; 4];
        for (limb, chunk) in limbs.iter_mut().zip(bytes.chunks_exact(8)) {
            *limb = u64::from_le_bytes(chunk.try_into().map_err(|_| ZkeyError::Truncated)?);
        }
        Ok(BigInteger256::new(limbs))
    }

    /// A base field element, already in Montgomery form.
    fn fq(&mut self) -> Result<Fq, ZkeyError> {
        Ok(Fq::new_unchecked(self.bigint()?))
    }

    /// A coefficient, which snarkjs writes multiplied by R squared: reading it as Montgomery form twice divides by R.
    fn coefficient(&mut self) -> Result<Fr, ZkeyError> {
        Ok(Fr::new_unchecked(
            Fr::new_unchecked(self.bigint()?).into_bigint(),
        ))
    }

    fn fq2(&mut self) -> Result<Fq2, ZkeyError> {
        Ok(Fq2::new(self.fq()?, self.fq()?))
    }

    fn g1(&mut self) -> Result<G1Affine, ZkeyError> {
        let (x, y) = (self.fq()?, self.fq()?);
        if x.is_zero() && y.is_zero() {
            return Ok(G1Affine::identity());
        }
        let point = G1Affine::new_unchecked(x, y);
        if !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() {
            return Err(ZkeyError::Format);
        }
        Ok(point)
    }

    fn g2(&mut self) -> Result<G2Affine, ZkeyError> {
        let (x, y) = (self.fq2()?, self.fq2()?);
        if x.is_zero() && y.is_zero() {
            return Ok(G2Affine::identity());
        }
        let point = G2Affine::new_unchecked(x, y);
        if !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() {
            return Err(ZkeyError::Format);
        }
        Ok(point)
    }
}

struct Header {
    n_vars: usize,
    n_public: usize,
    domain_size: usize,
    alpha_g1: G1Affine,
    beta_g1: G1Affine,
    beta_g2: G2Affine,
    gamma_g2: G2Affine,
    delta_g1: G1Affine,
    delta_g2: G2Affine,
}

fn sections(bytes: &[u8]) -> Result<HashMap<u32, usize>, ZkeyError> {
    let mut reader = Reader::at(bytes, 0);
    if reader.take(4)? != b"zkey" {
        return Err(ZkeyError::Format);
    }
    let (_version, count) = (reader.u32()?, reader.u32()?);
    let mut found = HashMap::new();
    for _ in 0..count {
        let (id, length) = (reader.u32()?, reader.u64()?);
        found.entry(id).or_insert(reader.at);
        reader.at = reader
            .at
            .checked_add(usize::try_from(length).map_err(|_| ZkeyError::Bounds)?)
            .ok_or(ZkeyError::Bounds)?;
        if reader.at > bytes.len() {
            return Err(ZkeyError::Truncated);
        }
    }
    Ok(found)
}

fn header(bytes: &[u8], found: &HashMap<u32, usize>) -> Result<Header, ZkeyError> {
    let mut r = Reader::at(
        bytes,
        *found.get(&SECTION_HEADER).ok_or(ZkeyError::Truncated)?,
    );
    let n8q = r.u32()?;
    let _q = r.bigint()?;
    let n8r = r.u32()?;
    let _r = r.bigint()?;
    if n8q != FIELD_BYTES || n8r != FIELD_BYTES {
        return Err(ZkeyError::Format);
    }
    let n_vars = r.u32()? as usize;
    let n_public = r.u32()? as usize;
    let domain_size = r.u32()? as usize;
    if n_vars > MAX_VARIABLES
        || n_public >= n_vars
        || !domain_size.is_power_of_two()
        || domain_size > MAX_VARIABLES
    {
        return Err(ZkeyError::Bounds);
    }
    Ok(Header {
        n_vars,
        n_public,
        domain_size,
        alpha_g1: r.g1()?,
        beta_g1: r.g1()?,
        beta_g2: r.g2()?,
        gamma_g2: r.g2()?,
        delta_g1: r.g1()?,
        delta_g2: r.g2()?,
    })
}

fn g1_vec(
    bytes: &[u8],
    found: &HashMap<u32, usize>,
    section: u32,
    n: usize,
) -> Result<Vec<G1Affine>, ZkeyError> {
    let mut r = Reader::at(bytes, *found.get(&section).ok_or(ZkeyError::Truncated)?);
    (0..n).map(|_| r.g1()).collect()
}

fn g2_vec(
    bytes: &[u8],
    found: &HashMap<u32, usize>,
    section: u32,
    n: usize,
) -> Result<Vec<G2Affine>, ZkeyError> {
    let mut r = Reader::at(bytes, *found.get(&section).ok_or(ZkeyError::Truncated)?);
    (0..n).map(|_| r.g2()).collect()
}

fn matrices(bytes: &[u8], found: &HashMap<u32, usize>, h: &Header) -> Result<Matrices, ZkeyError> {
    let mut r = Reader::at(
        bytes,
        *found.get(&SECTION_COEFFS).ok_or(ZkeyError::Truncated)?,
    );
    let count = r.u32()?;
    let mut lists = vec![vec![Vec::new(); h.domain_size]; 2];
    let mut max_constraint = 0usize;
    for _ in 0..count {
        let (matrix, constraint, signal) =
            (r.u32()? as usize, r.u32()? as usize, r.u32()? as usize);
        let value = r.coefficient()?;
        if matrix > 1 || constraint >= h.domain_size || signal >= h.n_vars {
            return Err(ZkeyError::Bounds);
        }
        max_constraint = max_constraint.max(constraint);
        lists[matrix][constraint].push((value, signal));
    }
    let num_constraints = max_constraint
        .checked_sub(h.n_public)
        .ok_or(ZkeyError::Bounds)?;
    for list in &mut lists {
        list.truncate(num_constraints);
    }
    let b = lists.pop().ok_or(ZkeyError::Bounds)?;
    let a = lists.pop().ok_or(ZkeyError::Bounds)?;
    Ok(Matrices {
        num_instance_variables: h.n_public + 1,
        num_constraints,
        a,
        b,
    })
}

/// Reads a snarkjs Groth16 zkey over BN254.
///
/// # Errors
///
/// [`ZkeyError`] for a file that is truncated, of another format, or whose counts and indices are outside its header's
/// bounds, and for a point that is not on the curve or not in its subgroup.
pub fn read_zkey(bytes: &[u8]) -> Result<Zkey, ZkeyError> {
    let found = sections(bytes)?;
    let h = header(bytes, &found)?;
    let gamma_abc_g1 = g1_vec(bytes, &found, SECTION_IC, h.n_public + 1)?;
    let proving_key = ProvingKey::<Bn254> {
        vk: VerifyingKey::<Bn254> {
            alpha_g1: h.alpha_g1,
            beta_g2: h.beta_g2,
            gamma_g2: h.gamma_g2,
            delta_g2: h.delta_g2,
            gamma_abc_g1,
        },
        beta_g1: h.beta_g1,
        delta_g1: h.delta_g1,
        a_query: g1_vec(bytes, &found, SECTION_A, h.n_vars)?,
        b_g1_query: g1_vec(bytes, &found, SECTION_B1, h.n_vars)?,
        b_g2_query: g2_vec(bytes, &found, SECTION_B2, h.n_vars)?,
        h_query: g1_vec(bytes, &found, SECTION_H, h.domain_size)?,
        l_query: g1_vec(bytes, &found, SECTION_L, h.n_vars - h.n_public - 1)?,
    };
    let matrices = matrices(bytes, &found, &h)?;
    Ok(Zkey {
        proving_key,
        matrices,
    })
}
