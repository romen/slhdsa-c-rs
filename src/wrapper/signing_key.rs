pub use signature::Keypair;
pub use signature::KeypairRef;
pub use signature::Signer;
pub(super) const EMPTY_CTX: &[u8; 0] = &[];

use core::fmt;
use generic_array::GenericArray;

use super::utils::rand::randombytes;
use super::utils::transcoding;
use super::utils::typenum::Unsigned;
use super::{ParameterSet, SignatureLen, SigningKeyLen, VerifyingKeyLen};
use crate::ffi::c_int;
use transcoding::AsBytes;

/// Holds the secret key material for a given parameter set.
#[derive(Debug)]
#[repr(transparent)]
pub struct SigningKey<P: ParameterSet> {
    pub(super) sk: GenericArray<u8, <P as crate::SigningKeyLen>::LEN>,
}

/// For convenience, a `SigningKey<P>` can be used also as a
/// corresponding `&VerifyingKey<P>`, using zero-cost abstractions.
///
/// # Usage
///
/// ```rust
/// # use slhdsa_c_rs::*;
/// # use SLH_DSA_SHAKE_128s as P;
/// # let sk = SigningKey::<P>::keygen().expect("Keygen failed");
/// # let msg: &[u8] = b"Hello, world!";
/// # let sig = sk.sign(msg);
/// let sk: &SigningKey<P> = &sk;
/// let vk: &VerifyingKey<P> = sk.as_ref();
/// assert_eq!(vk.as_bytes().len(), P::VERIFYING_KEY_LEN);
///
/// assert!(vk.verify(&msg, &sig).is_ok())
/// ```
impl<P: ParameterSet> KeypairRef for SigningKey<P> {
    type VerifyingKey = super::verifying_key::VerifyingKey<P>;
}

/// For convenience, a `SigningKey<P>` can be used also as a
/// corresponding `&VerifyingKey<P>`, using zero-cost abstractions.
///
/// # Usage
///
/// ```rust
/// # use slhdsa_c_rs::*;
/// # use SLH_DSA_SHAKE_128s as P;
/// # let sk = SigningKey::<P>::keygen().expect("Keygen failed");
/// # let msg: &[u8] = b"Hello, world!";
/// # let sig = sk.sign(msg);
/// let sk: &SigningKey<P> = &sk;
/// let vk: &VerifyingKey<P> = sk.as_ref();
/// assert_eq!(vk.as_bytes().len(), P::VERIFYING_KEY_LEN);
///
/// assert!(vk.verify(&msg, &sig).is_ok())
/// ```
impl<P: ParameterSet> AsRef<super::verifying_key::VerifyingKey<P>> for SigningKey<P> {
    fn as_ref(&self) -> &super::verifying_key::VerifyingKey<P> {
        let sk = self.as_bytes();
        let pk_start = sk.len() - P::VERIFYING_KEY_LEN;
        let pk = &sk[pk_start..];
        let pk: &GenericArray<u8, <P as crate::VerifyingKeyLen>::LEN> =
            GenericArray::from_slice(pk);

        // SAFETY: this subslice is guaranteed to be a valid pk by construction,
        // and VerifyingKey is #[repr(transparent)]
        unsafe { super::verifying_key::vk_from_inner(pk) }
    }
}

impl<P: ParameterSet> signature::Signer<super::Signature<P>> for SigningKey<P> {
    fn try_sign(&self, msg: &[u8]) -> Result<super::Signature<P>, signature::Error> {
        self.try_sign_with_ctx(msg, EMPTY_CTX)
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
            KeygenError::FFIError(code) => write!(f, "FFI keygen failed with error code {code:}"),
        }
    }
}

impl<P: ParameterSet> SigningKey<P> {
    /// Generate an SLH-DSA key pair
    ///
    /// # Errors
    ///
    /// Returns a [`KeygenError`] if the underlying FFI key generation fails.
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

    /// Attempt to use [`Self`] to sign the given `message` bytestring
    /// under the associated `context` bytestring, returning a digital signature
    /// on success, or a [`signature::Error`] if something went wrong.
    ///
    /// # Errors
    ///
    /// The main intended use case for signing errors is when communicating
    /// with external signers, e.g. cloud KMS, HSMs, or other hardware tokens.
    ///
    /// This method returns a [`signature::Error`] if the underlying FFI
    /// signature generation fails.
    pub fn try_sign_with_ctx(
        &self,
        message: &[u8],
        context: &[u8],
    ) -> Result<super::Signature<P>, signature::Error> {
        type Siglen<P> = <P as SignatureLen>::LEN;
        let mut sig: GenericArray<u8, Siglen<P>> = GenericArray::default();

        let ret: usize = {
            let prm = P::prm_as_ptr();
            let sk = self.sk.as_ptr();
            let addrnd = ::core::ptr::null();

            unsafe {
                crate::ffi::slh_sign(
                    sig.as_mut_ptr(),
                    message.as_ptr(),
                    message.len(),
                    context.as_ptr(),
                    context.len(),
                    sk,
                    addrnd,
                    prm,
                )
            }
        };
        if ret != <Siglen<P>>::USIZE {
            return Err(signature::Error::new());
        }

        // SAFETY: We assume slh_sign fully initialized all bytes of the
        // array, if it returned the expected siglen.
        let s = super::Signature::<P> { sig };

        Ok(s)
    }
}

impl<P: ParameterSet> From<SigningKey<P>> for GenericArray<u8, <P as crate::SigningKeyLen>::LEN> {
    fn from(sk: SigningKey<P>) -> Self {
        sk.sk
    }
}

impl<P: ParameterSet> TryFrom<&[u8]> for SigningKey<P> {
    type Error = transcoding::TranscodingError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != <<P as crate::SigningKeyLen>::LEN>::USIZE {
            return Err(transcoding::TranscodingError {});
        }
        let arr = GenericArray::from_slice(bytes).clone();
        Ok(SigningKey { sk: arr })
    }
}

impl<P: ParameterSet> AsRef<[u8]> for SigningKey<P> {
    fn as_ref(&self) -> &[u8] {
        self.sk.as_ref()
    }
}
