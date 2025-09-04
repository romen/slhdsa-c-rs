use rand::{Rng, SeedableRng};

pub unsafe extern "C" fn randombytes(x: *mut u8, xlen: usize) -> ::core::ffi::c_int {
    const SUCCESS: ::core::ffi::c_int = 0;

    let x = {
        let nonnull_pointer = core::ptr::NonNull::new(x).unwrap();
        let mut x = core::ptr::NonNull::slice_from_raw_parts(nonnull_pointer, xlen);
        let x = unsafe { x.as_mut() };
        x
    };

    let mut rng = rand::rngs::StdRng::from_os_rng();

    rng.fill(x);

    SUCCESS
}
