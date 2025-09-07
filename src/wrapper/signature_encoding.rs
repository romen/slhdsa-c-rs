use core::convert::TryFrom;
use generic_array::GenericArray;
pub use signature::SignatureEncoding;

use super::utils::typenum::Unsigned;
use super::ParameterSet;

/// Represents a signature using the specified parameter set.
///
/// # Usage
///
/// ```rust
/// # use slhdsa_c_rs::*;
/// # use SLH_DSA_SHAKE_128s as P;
/// #
/// # let sk = SigningKey::<P>::keygen().expect("Keygen failed");
/// let msg: &[u8] = b"Hello, world!";
///
/// let signature = sk.sign(msg);
///
/// let encoded_signature: &[u8] = &(signature.to_bytes());
///
/// let recv_sig: Signature<P> = encoded_signature.try_into().expect("Failed to parse the received signature");
/// assert_eq!(recv_sig, signature);
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature<P: ParameterSet> {
    pub(super) sig: GenericArray<u8, <P as crate::SignatureLen>::LEN>,
}

impl<P: ParameterSet> signature::SignatureEncoding for Signature<P> {
    type Repr = GenericArray<u8, <P as crate::SignatureLen>::LEN>;
}

// Implement TryFrom<&[u8]> for Signature<P>
impl<P: ParameterSet> TryFrom<&[u8]> for Signature<P> {
    type Error = signature::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != <<P as crate::SignatureLen>::LEN>::USIZE {
            return Err(signature::Error::default());
        }
        let arr = GenericArray::from_slice(bytes).clone();
        Ok(Signature { sig: arr })
    }
}

// Implement From<Signature<P>> for GenericArray<u8, <P as crate::SignatureLen>::LEN>
impl<P: ParameterSet> From<Signature<P>> for GenericArray<u8, <P as crate::SignatureLen>::LEN> {
    fn from(sig: Signature<P>) -> Self {
        sig.sig
    }
}
