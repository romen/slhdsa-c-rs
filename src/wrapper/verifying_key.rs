pub(super) use super::signing_key::EMPTY_CTX;
pub use signature::Verifier;

use generic_array::GenericArray;

use super::ParameterSet;
use crate::{ffi::c_int, AsBytes};

/// Public key for signature verification.
#[derive(Clone, Debug)]
pub struct VerifyingKey<P: ParameterSet> {
    pub(super) pk: GenericArray<u8, <P as crate::VerifyingKeyLen>::LEN>,
}

impl<P: ParameterSet> VerifyingKey<P> {
    /// Use [`Self`] to verify that the provided `signature`
    /// for a given `message` bytestring is authentic
    /// under the associated `context` bytestring.
    ///
    /// # Errors
    ///
    /// Returns [`signature::Error`] if it is inauthentic,
    /// or otherwise returns `()`.
    pub fn verify_with_ctx(
        &self,
        message: &[u8],
        context: &[u8],
        signature: &super::Signature<P>,
    ) -> Result<(), signature::Error> {
        const SUCCESS: c_int = 1;
        let ret = {
            let prm = P::prm_as_ptr();
            let pk = self.pk.as_ptr();
            let sig = signature.as_bytes();

            unsafe {
                crate::ffi::slh_verify(
                    message.as_ptr(),
                    message.len(),
                    sig.as_ptr(),
                    sig.len(),
                    context.as_ptr(),
                    context.len(),
                    pk,
                    prm,
                )
            }
        };
        if ret != SUCCESS {
            return Err(signature::Error::default());
        }
        Ok(())
    }
}

impl<P: ParameterSet> signature::Verifier<super::Signature<P>> for VerifyingKey<P> {
    fn verify(&self, msg: &[u8], signature: &super::Signature<P>) -> Result<(), signature::Error> {
        self.verify_with_ctx(msg, EMPTY_CTX, signature)
    }
}
