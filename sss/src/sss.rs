use lambdaworks_math::{
    field::{element::FieldElement, fields::u64_prime_field::U64PrimeField},
    polynomial::Polynomial,
};
use rand::Rng;

// field element mod 37
type FE = FieldElement<U64PrimeField<37>>;

// generate random polynomial
// f(x) = a1.x + a2.x^2 + ... + an.x^n
fn generate_polynomial(secret: FE, k: usize) -> Polynomial<FE> {
    let mut rng = rand::thread_rng();

    // a0 is the secret
    let mut coefficients = vec![secret];

    for _ in 1..k {
        let random_coefficient = rng.gen_range(1..1000);
        coefficients.push(random_coefficient.into());
    }

    Polynomial::new(&coefficients)
}

fn create_shares(poly: &Polynomial<FE>, n: usize) -> Vec<(FE, FE)> {
    (1..=n)
        .map(|i| {
            // convert i to a field element
            let x = FE::from(i as u64);
            // evaluation
            (x, poly.evaluate(&x))
        })
        .collect()
}

// lagrange interpolation
fn reconstruct_secret(shares: &[(FE, FE)]) -> FE {
    // take x and y values from shares
    let (shares_x, shares_y): (Vec<FE>, Vec<FE>) = shares.iter().cloned().unzip();

    let polynomial = Polynomial::interpolate(&shares_x, &shares_y).unwrap();
    // a0 : evaluation of X0
    polynomial.evaluate(&FE::zero())
}

#[cfg(test)]
mod tests {
    use super::*;
    type FE = FieldElement<U64PrimeField<37>>;
    const k: usize = 3;
    const n: usize = 5;

    #[test]
    fn test_generate_polynomial() {
        let secret = FE::from(33653347);
        let poly = generate_polynomial(secret, k);

        // degree is k-1
        assert_eq!(poly.degree(), k - 1);
        // a0 is the secret
        assert_eq!(poly.coefficients()[0], secret);
    }

    #[test]
    fn test_create_shares() {
        let secret = FE::from(33653347);
        let poly = generate_polynomial(secret, k);
        let shares = create_shares(&poly, n);

        assert_eq!(shares.len(), n);

        for (x, y) in shares {
            assert_eq!(y, poly.evaluate(&x));
        }
    }

    #[test]
    fn test_reconstruct_secret() {
        let secret = FE::from(33653347);
        let poly = generate_polynomial(secret, k);
        let shares = create_shares(&poly, n);

        // k shares to reconstructed the secret
        let selected_shares: Vec<(FE, FE)> = shares.into_iter().take(k).collect();
        let reconstructed_secret = reconstruct_secret(&selected_shares);

        assert_eq!(reconstructed_secret, secret);
    }
}
