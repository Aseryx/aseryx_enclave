//! The witness map snarkjs uses, as an arkworks `R1CSToQAP` reduction.
//!
//! Arkworks computes the coefficients of H as (AB - C) / Z over the evaluation domain. snarkjs instead precomputes the
//! Lagrange form of the powers of tau in a domain twice as large, and its witness map is the odd coefficients of AB - C
//! in that domain. This module is adapted from `ark-circom`'s `circom/qap.rs` (MIT OR Apache-2.0,
//! <https://github.com/arkworks-rs/circom-compat>), without its parallelism.

use ark_ff::PrimeField;
use ark_groth16::r1cs_to_qap::{LibsnarkReduction, R1CSToQAP, evaluate_constraint};
use ark_poly::EvaluationDomain;
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};

/// The reduction a zkey made by snarkjs needs.
pub struct SnarkjsReduction;

impl R1CSToQAP for SnarkjsReduction {
    #[allow(clippy::type_complexity)]
    fn instance_map_with_evaluation<F: PrimeField, D: EvaluationDomain<F>>(
        cs: ConstraintSystemRef<F>,
        t: &F,
    ) -> Result<(Vec<F>, Vec<F>, Vec<F>, F, usize, usize), SynthesisError> {
        LibsnarkReduction::instance_map_with_evaluation::<F, D>(cs, t)
    }

    fn witness_map_from_matrices<F: PrimeField, D: EvaluationDomain<F>>(
        matrices: &[Vec<Vec<(F, usize)>>],
        num_inputs: usize,
        num_constraints: usize,
        full_assignment: &[F],
    ) -> Result<Vec<F>, SynthesisError> {
        let zero = F::zero();
        let domain =
            D::new(num_constraints + num_inputs).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let domain_size = domain.size();

        let mut a = vec![zero; domain_size];
        let mut b = vec![zero; domain_size];
        for (i, (at, bt)) in matrices[0]
            .iter()
            .zip(&matrices[1])
            .enumerate()
            .take(num_constraints)
        {
            a[i] = evaluate_constraint(at, full_assignment);
            b[i] = evaluate_constraint(bt, full_assignment);
        }
        a[num_constraints..num_constraints + num_inputs]
            .clone_from_slice(&full_assignment[..num_inputs]);

        let mut c = vec![zero; domain_size];
        for i in 0..num_constraints {
            c[i] = a[i] * b[i];
        }

        domain.ifft_in_place(&mut a);
        domain.ifft_in_place(&mut b);

        let root_of_unity = D::new(2 * domain_size)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?
            .element(1);
        D::distribute_powers_and_mul_by_const(&mut a, root_of_unity, F::one());
        D::distribute_powers_and_mul_by_const(&mut b, root_of_unity, F::one());

        domain.fft_in_place(&mut a);
        domain.fft_in_place(&mut b);

        let mut ab = domain.mul_polynomials_in_evaluation_domain(&a, &b);
        drop((a, b));

        domain.ifft_in_place(&mut c);
        D::distribute_powers_and_mul_by_const(&mut c, root_of_unity, F::one());
        domain.fft_in_place(&mut c);

        for (ab_i, c_i) in ab.iter_mut().zip(c) {
            *ab_i -= &c_i;
        }
        Ok(ab)
    }

    fn h_query_scalars<F: PrimeField, D: EvaluationDomain<F>>(
        max_power: usize,
        t: F,
        _: F,
        delta_inverse: F,
    ) -> Result<Vec<F>, SynthesisError> {
        // The usual H query has domain - 1 powers and Z has domain powers, so HZ has 2 * domain - 1.
        let mut scalars: Vec<F> = (0..=2 * max_power)
            .map(|i| delta_inverse * t.pow([i as u64]))
            .collect();
        let domain = D::new(scalars.len()).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        domain.ifft_in_place(&mut scalars);
        Ok(scalars.into_iter().skip(1).step_by(2).collect())
    }
}
