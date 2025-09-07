pub(super) use super::signing_key::EMPTY_CTX;
pub use signature::Verifier;

use generic_array::GenericArray;

use super::ParameterSet;

/// Public key for signature verification.
#[derive(Clone, Debug)]
pub struct VerifyingKey<P: ParameterSet> {
    pub(super) pk: GenericArray<u8, <P as crate::VerifyingKeyLen>::LEN>,
}

impl<P: ParameterSet> VerifyingKey<P> {
    fn verify_with_ctx(
        &self,
        msg: &[u8],
        ctx: &[u8],
        signature: &super::Signature<P>,
    ) -> Result<(), signature::Error> {
        todo!()
    }
}

impl<P: ParameterSet> signature::Verifier<super::Signature<P>> for VerifyingKey<P> {
    fn verify(&self, msg: &[u8], signature: &super::Signature<P>) -> Result<(), signature::Error> {
        self.verify_with_ctx(msg, EMPTY_CTX, signature)
    }
}
