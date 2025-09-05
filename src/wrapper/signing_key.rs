use core::fmt;
use generic_array::GenericArray;
pub use signature::Keypair;

use super::utils::rand::randombytes;
use super::{ParameterSet, SignatureLen, SigningKeyLen, VerifyingKeyLen};
use crate::ffi::c_int;

/// SigningKey holds the secret key material for a given parameter set.
#[derive(Debug)]
pub struct SigningKey<P: ParameterSet> {
    sk: GenericArray<u8, <P as crate::SigningKeyLen>::LEN>,
}

impl<P: ParameterSet> Keypair for SigningKey<P> {
    type VerifyingKey = super::VerifyingKey<P>;

    fn verifying_key(&self) -> Self::VerifyingKey {
        let sk = self.sk.as_slice();
        let pk = &sk[sk.len() - P::VERIFYING_KEY_LEN..];
        let pk = GenericArray::from_slice(pk).clone();
        Self::VerifyingKey { pk }
    }
}

impl<P: ParameterSet> signature::Signer<super::Signature<P>> for SigningKey<P> {
    fn try_sign(&self, msg: &[u8]) -> Result<super::Signature<P>, signature::Error> {
        todo!()
    }
}

/// Errors that can occur during SLH key generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeygenError {
    /// The FFI function returned a non-zero status code.
    FFIError(c_int),
}

impl fmt::Display for KeygenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeygenError::FFIError(code) => write!(f, "FFI keygen failed with error code {}", code),
        }
    }
}

impl<P: ParameterSet> SigningKey<P> {
    /// Generate an SLH-DSA key pair
    pub fn keygen() -> Result<Self, KeygenError> {
        const SUCCESS: c_int = 0;

        let mut sk: GenericArray<u8, <P as SigningKeyLen>::LEN> = GenericArray::default();
        let mut pk: GenericArray<u8, <P as VerifyingKeyLen>::LEN> = GenericArray::default();

        let ret: c_int = {
            let prm = P::prm_as_ptr();

            let sk_slice = sk.as_mut_slice();
            let pk_slice = pk.as_mut_slice();

            let sk = sk_slice.as_mut_ptr();
            let pk = pk_slice.as_mut_ptr();

            unsafe { crate::ffi::slh_keygen(sk, pk, Some(randombytes), prm) }
        };

        match ret {
            SUCCESS => (),
            x => return Err(KeygenError::FFIError(x)),
        }

        // SAFETY: We assume slh_keygen fully initialized all bytes of the
        // array, if it returned 0.
        let sk = Self { sk };
        let _ = pk;
        Ok(sk)
    }
}
