#![allow(clippy::must_use_candidate)]

pub use signature;

use crate::ffi;

mod signature_encoding;
mod signing_key;
mod verifying_key;

pub use signature_encoding::*;
pub use signing_key::*;
pub use verifying_key::*;

pub(crate) mod utils;
pub(crate) use utils::typenum;

trait FFIParams {
    /// Returns a static reference to the FFI struct representing this parameter set.
    ///
    /// Calling this function does not have runtime overhead: since the FFI
    /// symbol itself is already a `static`, the compiler will inline it down to
    /// a direct reference.
    fn prm() -> &'static ffi::slh_param_s;

    /// Returns a pointer to the static reference to the FFI struct representing
    /// this parameter set.
    ///
    /// Calling this function does not have runtime overhead, as the compiler
    /// will inline it down to a direct reference.
    fn prm_as_ptr() -> *const ffi::slh_param_s {
        core::ptr::from_ref(Self::prm())
    }
}

/// Trait for types that provide the length of the secret (signing) key.
#[allow(private_bounds)]
pub trait SigningKeyLen: FFIParams {
    /// Length of the secret (signing) key in bytes.
    ///
    /// Same as `Self::SECRET_KEY_LEN`
    const SIGNING_KEY_LEN: usize;

    /// Length of the secret (signing) key in bytes.
    ///
    /// Same as `Self::SIGNING_KEY_LEN`
    const SECRET_KEY_LEN: usize = Self::SIGNING_KEY_LEN;

    /// Retrieve the length of the secret (signing) key in bytes,
    /// using the FFI bindings.
    ///
    /// `Self::SIGNING_KEY_LENGTH` provides the same value as a `const`.
    fn signing_key_len() -> usize {
        let prm = Self::prm_as_ptr();
        unsafe { ffi::slh_sk_sz(prm) }
    }

    /// `Self::SIGNING_KEY_LEN` as a type
    type LEN: generic_array::ArrayLength;
}

/// Trait for types that provide the length of the public (verifying) key.
#[allow(private_bounds)]
pub trait VerifyingKeyLen: FFIParams {
    /// Length of the public (verifying) key in bytes.
    ///
    /// Same as `Self::PUBLIC_KEY_LEN`
    const VERIFYING_KEY_LEN: usize;

    /// Length of the public (verifying) key in bytes.
    ///
    /// Same as `Self::VERIFYING_KEY_LEN`
    const PUBLIC_KEY_LEN: usize = Self::VERIFYING_KEY_LEN;

    /// Retrieve the length of the public (verifying) key in bytes,
    /// using the FFI bindings.
    ///
    /// `Self::VERIFYING_KEY_LEN` provides the same value as a `const`.
    fn verifying_key_len() -> usize {
        let prm = Self::prm_as_ptr();
        unsafe { ffi::slh_pk_sz(prm) }
    }

    /// `Self::VERIFYING_KEY_LEN` as a type
    type LEN: generic_array::ArrayLength;
}

/// Trait for types that provide the length of the signature.
#[allow(private_bounds)]
pub trait SignatureLen: FFIParams {
    /// Length of the signature in bytes.
    const SIGNATURE_LEN: usize;

    /// Retrieve the length of the signature in bytes,
    /// using the FFI bindings.
    ///
    /// `Self::SIGNATURE_LEN` provides the same value as a `const`.
    fn signature_len() -> usize {
        let prm = Self::prm_as_ptr();
        unsafe { ffi::slh_sig_sz(prm) }
    }

    /// `Self::SIGNATURE_LEN` as a type
    type LEN: generic_array::ArrayLength;
}

/// Trait implemented by each of the 12 FIPS parameter sets
#[allow(private_bounds)]
pub trait ParameterSet:
    FFIParams
    + SigningKeyLen
    + VerifyingKeyLen
    + SignatureLen
    + PartialEq
    + Eq
    + Clone
    + core::fmt::Debug
{
    /// Human-readable name for parameter set, matching the FIPS-205 designations
    const NAME: &'static str;

    /// Retrieve the standard identifier string for this parameter set
    /// using the FFI bindings.
    ///
    /// `Self::NAME` provides the same value as a `const`.
    fn algorithm_name() -> &'static str {
        let prm = Self::prm_as_ptr();
        let name = unsafe { ffi::slh_alg_id(prm) };
        let name = core::ptr::NonNull::new(name.cast_mut()).expect("Expected a non-NULL pointer");
        let name = unsafe { core::ffi::CStr::from_ptr(name.as_ptr()) };

        let name = name.to_str().expect("Invalid UTF-8");
        debug_assert_eq!(name, Self::NAME);
        name
    }

    /// Associated OID with the Parameter as a `&str`
    const ALGORITHM_OID_STR: &'static str;

    //    /// Associated OID with the Parameter
    //    const ALGORITHM_OID: pkcs8::ObjectIdentifier;
}

#[allow(non_camel_case_types)]
#[derive(PartialEq, Eq, Clone, Debug)]
/// Implements SLH-DSA-SHAKE-128s from as described in NIST [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final).
pub struct SLH_DSA_SHAKE_128s {}

impl FFIParams for SLH_DSA_SHAKE_128s {
    fn prm() -> &'static ffi::slh_param_s {
        unsafe { &ffi::slh_dsa_shake_128s }
    }
}
impl SignatureLen for SLH_DSA_SHAKE_128s {
    const SIGNATURE_LEN: usize = 7856;

    type LEN = typenum::U7856;
}
impl SigningKeyLen for SLH_DSA_SHAKE_128s {
    const SIGNING_KEY_LEN: usize = 64;
    type LEN = typenum::U64;
}
impl VerifyingKeyLen for SLH_DSA_SHAKE_128s {
    const VERIFYING_KEY_LEN: usize = 32;
    type LEN = typenum::U32;
}
impl ParameterSet for SLH_DSA_SHAKE_128s {
    const NAME: &'static str = "SLH-DSA-SHAKE-128s";
    const ALGORITHM_OID_STR: &'static str = "2.16.840.1.101.3.4.3.26";
}

#[cfg(test)]
mod tests {
    #[cfg(test)]
    extern crate std; // bring in `std` only when testing

    use super::*;
    use crate::{SignatureLen, SigningKeyLen, VerifyingKeyLen};
    use typenum::Unsigned;
    //     use rand::Rng;
    //     use signature::*;
    //     use util::macros::test_parameter_sets;

    fn test_sizes<P: ParameterSet>() {
        assert_eq!(P::SIGNATURE_LEN, P::signature_len());
        assert_eq!(<P as SignatureLen>::LEN::to_usize(), P::SIGNATURE_LEN);

        assert_eq!(P::SIGNING_KEY_LEN, P::signing_key_len());
        assert_eq!(P::SIGNING_KEY_LEN, P::SECRET_KEY_LEN);
        assert_eq!(<P as SigningKeyLen>::LEN::to_usize(), P::SIGNING_KEY_LEN);

        assert_eq!(P::VERIFYING_KEY_LEN, P::verifying_key_len());
        assert_eq!(P::VERIFYING_KEY_LEN, P::PUBLIC_KEY_LEN);
        assert_eq!(
            <P as VerifyingKeyLen>::LEN::to_usize(),
            P::VERIFYING_KEY_LEN
        );

        assert_eq!(P::NAME, P::algorithm_name());
    }

    fn test_sign_verify<P: ParameterSet>() {
        //let mut rng = rand::rng();
        //let sk = SigningKey::<P>::new(&mut rng);
        let sk = SigningKey::<P>::keygen().expect("Keygen failed");
        std::println!("{sk:?}");
        let vk = sk.verifying_key();
        std::println!("{vk:?}");
        let msg = b"Hello, world!";
        let sig = sk.sign(msg);
        std::println!("{sig:?}");

        // Encode the signature into bytes for transfer between Signer and Verifier
        let sig_raw = sig.to_bytes();
        let sig_bytes: &[u8] = &sig_raw;
        std::println!("{sig_bytes:?}");
        assert_eq!(sig_bytes.len(), <<P as super::SignatureLen>::LEN>::USIZE);

        // Now decode the signature from bytes, simulating what the Verifier
        // would do after receiving the signature
        let recv_sig: Signature<P> = sig_bytes
            .try_into()
            .expect("Failed to parse the received signature");
        assert_eq!(recv_sig, sig);

        //vk.verify(msg, &sig).unwrap();
    }

    //     test_parameter_sets!(test_sign_verify);
    //
    //     // Check signature fails on modified message
    //     #[test]
    //     fn test_sign_verify_shake_128f_fail_on_modified_message() {
    //         let mut rng = rand::rng();
    //         let sk = SigningKey::<Shake128f>::new(&mut rng);
    //         let msg = b"Hello, world!";
    //         let modified_msg = b"Goodbye, world!";
    //
    //         let sig = sk.try_sign(msg).unwrap();
    //         let vk = sk.verifying_key();
    //         assert!(vk.verify(msg, &sig).is_ok());
    //         assert!(vk.verify(modified_msg, &sig).is_err());
    //     }
    //
    //     #[test]
    //     fn test_sign_verify_fail_with_wrong_verifying_key() {
    //         let mut rng = rand::rng();
    //         let sk = SigningKey::<Shake128f>::new(&mut rng);
    //         let wrong_sk = SigningKey::<Shake128f>::new(&mut rng); // Generate a different signing key
    //         let msg = b"Hello, world!";
    //
    //         let sig = sk.try_sign(msg).unwrap();
    //         let vk = sk.verifying_key();
    //         let wrong_vk = wrong_sk.verifying_key(); // Get the verifying key of the wrong signing key
    //         assert!(vk.verify(msg, &sig).is_ok());
    //         assert!(wrong_vk.verify(msg, &sig).is_err()); // This should fail because the verifying key does not match the signing key used
    //     }
    //
    //     #[test]
    //     fn test_sign_verify_fail_on_modified_signature() {
    //         let mut rng = rand::rng();
    //         let sk = SigningKey::<Shake128f>::new(&mut rng);
    //         let msg = b"Hello, world!";
    //
    //         let mut sig_bytes = sk.try_sign(msg).unwrap().to_bytes();
    //         // Randomly modify one byte in the signature
    //         let sig_len = sig_bytes.len();
    //         let random_byte_index = rng.random_range(0..sig_len);
    //         sig_bytes[random_byte_index] ^= 0xff; // Invert one byte to ensure it's different
    //         let sig = (&sig_bytes).into();
    //
    //         let vk = sk.verifying_key();
    //         assert!(
    //             vk.verify(msg, &sig).is_err(),
    //             "Verification should fail with a modified signature"
    //         );
    //     }
    //
    //     #[test]
    //     fn test_successive_signatures_not_equal() {
    //         let mut rng = rand::rng();
    //         let sk = SigningKey::<Shake128f>::new(&mut rng);
    //         let msg = b"Hello, world!";
    //
    //         let sig1 = sk.try_sign_with_rng(&mut rng, msg).unwrap();
    //         let sig2 = sk.try_sign_with_rng(&mut rng, msg).unwrap();
    //
    //         assert_ne!(
    //             sig1, sig2,
    //             "Two successive randomized signatures over the same message should not be equal"
    //         );
    //     }
    //
    //     #[test]
    //     fn test_sign_verify_nonempty_context() {
    //         let mut rng = rand::rng();
    //         let sk = SigningKey::<Shake128f>::new(&mut rng);
    //         let vk = sk.verifying_key();
    //         let msg = b"Hello, world!";
    //         let ctx = b"Test context";
    //         let sig = sk.try_sign_with_context(msg, ctx, None).unwrap();
    //         vk.try_verify_with_context(msg, ctx, &sig).unwrap();
    //     }
    //
    //     #[test]
    //     fn test_sign_verify_wrong_context() {
    //         let mut rng = rand::rng();
    //         let sk = SigningKey::<Shake128f>::new(&mut rng);
    //         let vk = sk.verifying_key();
    //         let msg = b"Hello, world!";
    //         let ctx = b"Test context!";
    //         let wrong_ctx = b"Wrong context";
    //         let sig = sk.try_sign_with_context(msg, ctx, None).unwrap();
    //         assert!(vk.try_verify_with_context(msg, wrong_ctx, &sig).is_err());
    //     }

    #[test]
    fn test_sizes_slh_dsa_shake_128s() {
        use SLH_DSA_SHAKE_128s as prmset;
        test_sizes::<prmset>();
    }

    #[test]
    fn test_sign_verify_slh_dsa_shake_128s() {
        use SLH_DSA_SHAKE_128s as prmset;
        test_sign_verify::<prmset>();
    }
}
