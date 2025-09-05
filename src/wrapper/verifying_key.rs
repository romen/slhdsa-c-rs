use generic_array::GenericArray;

use super::ParameterSet;

/// Public key for signature verification.
#[derive(Clone, Debug)]
pub struct VerifyingKey<P: ParameterSet> {
    pub(super) pk: GenericArray<u8, <P as crate::VerifyingKeyLen>::LEN>,
}
