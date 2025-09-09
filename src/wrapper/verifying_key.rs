pub(super) use super::signing_key::EMPTY_CTX;
pub use signature::Verifier;

use super::utils::typenum::Unsigned;
use generic_array::GenericArray;

use super::ParameterSet;
use crate::{ffi::c_int, utils::transcoding};
use transcoding::AsBytes;

/// Public key for signature verification.
#[derive(Clone, Debug)]
#[repr(transparent)]
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

impl<P: ParameterSet> From<VerifyingKey<P>>
    for GenericArray<u8, <P as crate::VerifyingKeyLen>::LEN>
{
    fn from(vk: VerifyingKey<P>) -> Self {
        vk.pk
    }
}

impl<P: ParameterSet> TryFrom<&[u8]> for VerifyingKey<P> {
    type Error = transcoding::TranscodingError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != <<P as crate::VerifyingKeyLen>::LEN>::USIZE {
            return Err(transcoding::TranscodingError {});
        }
        let arr = GenericArray::from_slice(bytes).clone();
        Ok(Self { pk: arr })
    }
}

impl<P: ParameterSet> AsRef<[u8]> for VerifyingKey<P> {
    fn as_ref(&self) -> &[u8] {
        self.pk.as_ref()
    }
}

/// Single unsafe helper for internal use to cast a `GenericArray` of the
/// right size into a `VerifyingKey` reference.
///
/// ## Safety
///
/// Callers should ensure the underlying bytes represent a valid public key.
///
/// This should be used only for internal zero-cost abstractions, relying on the
/// fact that `VeryfingKey` is `#[repr(transparent)]`
#[inline]
pub(super) unsafe fn vk_from_inner<P: ParameterSet>(
    inner: &GenericArray<u8, <P as crate::VerifyingKeyLen>::LEN>,
) -> &VerifyingKey<P> {
    debug_assert_eq!(inner.len(), P::VERIFYING_KEY_LEN);
    let ptr = inner.as_ptr();
    let ptr = ptr.cast::<super::verifying_key::VerifyingKey<P>>();
    &*(ptr)
}
