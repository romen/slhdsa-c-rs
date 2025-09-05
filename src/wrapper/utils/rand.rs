use crate::ffi::c_int;
use rand::rand_core::{CryptoRng, RngCore, SeedableRng};

type ChosenRng = rand::rngs::StdRng;

// Compile-time check: fails to type-check if bounds aren’t met.
const _: () = {
    fn assert_impls<R: RngCore + CryptoRng>() {}
    let _ = assert_impls::<ChosenRng>;
};

pub(crate) unsafe extern "C" fn randombytes(out: *mut u8, outlen: usize) -> c_int {
    // C expects: 0 = OK, nonzero = error
    const SUCCESS: c_int = 0;
    const ERROR: c_int = -1;

    if out.is_null() {
        return ERROR; // never panic across FFI
    }

    // SAFETY: C guarantees `out` points to `len` writable bytes.
    let buf: &mut [u8] = core::slice::from_raw_parts_mut(out, outlen);

    let mut rng = ChosenRng::from_os_rng();
    rng.fill_bytes(buf);
    SUCCESS
}
