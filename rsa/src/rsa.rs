use glass_pumpkin::prime;
use num_bigint::*;
use num_traits::{One, Zero};
use sha2::{Digest, Sha256};

struct Keys {
    public_key: (BigInt, BigInt),
    private_key: BigInt,
}

impl Keys {
    fn modular_inverse(a: &BigInt, m: &BigInt) -> Option<BigInt> {
        let (zero, one, mut mn, mut xy) = (
            BigInt::zero(),
            BigInt::one(),
            (m.clone(), a.clone()),
            (BigInt::zero(), BigInt::one()),
        );

        while mn.1 != zero {
            let q = &mn.0 / &mn.1;
            mn = (mn.1.clone(), &mn.0 - &q * &mn.1);
            xy = (xy.1.clone(), &xy.0 - &q * &xy.1);
        }

        if mn.0 > one {
            return None;
        }

        if xy.0 < zero {
            xy.0 += m;
        }

        Some(xy.0)
    }
    fn generate_keys() -> (Self, BigUint, BigUint) {
        // 1. generate random 1024 bits primes p and q
        let p = prime::new(1024).expect("Failed to generate p");
        let q = prime::new(1024).expect("Failed to generate q");

        // primality testing
        assert!(prime::check(&p), "p is not prime");
        assert!(prime::check(&q), "q is not prime");

        // 2. compute n = p * q
        let n = (&p * &q).to_bigint().expect("Failed to compute n");

        // compute phi_of_n = (p - 1) * (q - 1)
        let phi_of_n = (&p - BigUint::one()) * (&q - BigUint::one());

        // 3. choose e = 65537
        let e = BigInt::from(65537u64);

        // 4. compute e^-1 & d = e^-1 mod (phi_of_n) by
        let d =
            Self::modular_inverse(&e, &phi_of_n.into()).expect("Failed to compute modular inverse");

        (
            Keys {
                public_key: (e, n),
                private_key: d,
            },
            p,
            q,
        )
    }

    fn encrypt(&self, message: &str) -> BigInt {
        // m^e (mod n)
        let m = BigInt::from_bytes_be(num_bigint::Sign::Plus, message.as_bytes());
        let c = m.modpow(&self.public_key.0, &self.public_key.1);
        c
    }

    fn decrypt(&self, c: &BigInt) -> Vec<u8> {
        // d = c^d (mod n)
        let d = c.modpow(&self.private_key, &self.public_key.1);
        d.to_bytes_be().1
    }

    fn sign(&self, message: &str) -> BigInt {
        let mut hasher = Sha256::new();
        hasher.update(message.as_bytes());
        let hash = hasher.finalize();
        let hash_int = BigInt::from_bytes_be(num_bigint::Sign::Plus, &hash);

        let sig = hash_int.modpow(&self.private_key, &self.public_key.1);
        sig
    }

    fn verify(&self, message: &str, sig: &BigInt) -> bool {
        // Hash of m
        let mut hasher = Sha256::new();
        hasher.update(message.as_bytes());
        let hash = hasher.finalize();

        let hash_int = BigInt::from_bytes_be(num_bigint::Sign::Plus, &hash);

        // sig^e (mod n)
        let decrypted_hash = sig.modpow(&self.public_key.0, &self.public_key.1);

        hash_int == decrypted_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keys() {
        let (
            Keys {
                public_key: (e, n),
                private_key: d,
            },
            p,
            q,
        ) = Keys::generate_keys();

        assert!(e > BigInt::zero());
        assert!(n > BigInt::zero());
        assert!(d > BigInt::zero());

        let phi_of_n = (p.clone() - BigUint::one()) * (q.clone() - BigUint::one());
        let phi_of_n = phi_of_n.to_bigint().expect("Failed to convert phi_of_n");

        let ed_mod_phi = (e * d) % &phi_of_n;
        assert_eq!(ed_mod_phi, BigInt::one(), "1")
    }

    #[test]
    fn test_modular_inverse() {
        let a = BigInt::from(3);
        let m = BigInt::from(11);
        let inverse = Keys::modular_inverse(&a, &m).expect("Failed to compute modular inverse");
        assert_eq!((a * inverse) % m, BigInt::one(), "1");
    }

    #[test]
    fn test_encrypt_decrypt() {
        let (keys, _, _) = Keys::generate_keys();
        let message = "Hello";
        let c = keys.encrypt(message);
        let d = keys.decrypt(&c);

        assert_eq!(message.as_bytes(), &d[..], "Failed to decrypt message");
    }

    #[test]
    fn test_sign() {
        let (keys, _, _) = Keys::generate_keys();
        let message = "Hello";
        let signature = keys.sign(message);

        assert!(keys.verify(message, &signature), "The is not valid");
    }
}
