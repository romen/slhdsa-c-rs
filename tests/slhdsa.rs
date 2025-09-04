pub(crate) mod common {
    pub(crate) type OurError = anyhow::Error;
    pub(crate) type OurResult<T> = anyhow::Result<T>;

    //#[cfg(feature = "env_logger")]
    fn inner_try_init_logging() -> OurResult<()> {
        env_logger::Builder::from_default_env()
            //.filter_level(log::LevelFilter::Debug)
            //.format_timestamp(None) // Optional: disable timestamps
            .format_module_path(true) // Optional: disable module path
            .format_target(true) // Optional: enable target
            .format_source_path(true)
            .is_test(cfg!(test))
            .try_init()
            .map_err(OurError::from)
    }

    fn try_init_logging() -> OurResult<()> {
        use std::sync::Once;
        static INIT: Once = Once::new();

        INIT.call_once(|| {
            //#[cfg(feature = "env_logger")]
            inner_try_init_logging().expect("Failed to initialize the logging system");
        });

        Ok(())
    }

    pub(crate) fn setup() -> OurResult<()> {
        try_init_logging().expect("Failed to initialize the logging system");
        Ok(())
    }
}

mod helpers {
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
}

#[test]
fn basic_bindings_test() {
    use slhdsa_c_rs::bindings;

    common::setup().expect("Failed during initial setup");

    unsafe {
        let prm = &bindings::slh_dsa_shake_256s;

        let id = bindings::slh_alg_id(std::ptr::from_ref(prm));
        let id = core::ffi::CStr::from_ptr(id)
            .to_str()
            .expect("Invalid CStr");
        log::info!("id={:?}", id);

        let sk_sz = bindings::slh_sk_sz(std::ptr::from_ref(prm));
        log::info!("sk_sz={:?}", sk_sz);
        let pk_sz = bindings::slh_pk_sz(std::ptr::from_ref(prm));
        log::info!("pk_sz={:?}", pk_sz);
        let sig_sz = bindings::slh_sig_sz(std::ptr::from_ref(prm));
        log::info!("sig_sz={:?}", sig_sz);

        let mut sk: Vec<u8> = vec![0; sk_sz];
        let mut pk: Vec<u8> = vec![0; pk_sz];

        let rbg = helpers::randombytes;

        let ret = bindings::slh_keygen(sk.as_mut_ptr(), pk.as_mut_ptr(), Some(rbg), prm);
        assert_eq!(ret, 0);

        log::info!("sk={:x?}", sk);
        log::info!("pk={:x?}", pk);

        let msg: &[u8] = &[1, 2, 3, 4, 5];
        log::info!("msg={:?}", msg);

        let ctx: &[u8] = &[];
        log::info!("ctx={:x?}", ctx);

        let mut sig: Vec<u8> = vec![0; sig_sz];
        let addrnd = ::core::ptr::null();

        let ret = bindings::slh_sign(
            sig.as_mut_ptr(),
            msg.as_ptr(),
            msg.len(),
            ctx.as_ptr(),
            ctx.len(),
            sk.as_ptr(),
            addrnd,
            prm,
        );
        assert_eq!(ret, sig_sz);
        log::debug!("sig={:x?}", sig);

        let ret = bindings::slh_verify(
            msg.as_ptr(),
            msg.len(),
            sig.as_ptr(),
            sig.len(),
            ctx.as_ptr(),
            ctx.len(),
            pk.as_ptr(),
            prm,
        );
        log::info!("slh_verify() returned {:x?} on happy path", ret);
        assert_eq!(ret, 1);

        {
            let msg: &[u8] = &[1, 2, 3, 4, 5, 6];

            let ret = bindings::slh_verify(
                msg.as_ptr(),
                msg.len(),
                sig.as_ptr(),
                sig.len(),
                ctx.as_ptr(),
                ctx.len(),
                pk.as_ptr(),
                prm,
            );
            log::info!("slh_verify() returned {:x?} on tampered message", ret);
            assert_eq!(ret, 0);
        }

        {
            let mut sk: Vec<u8> = vec![0; sk_sz];
            let mut pk: Vec<u8> = vec![0; pk_sz];

            let ret = bindings::slh_keygen(sk.as_mut_ptr(), pk.as_mut_ptr(), Some(rbg), prm);
            assert_eq!(ret, 0);

            let ret = bindings::slh_verify(
                msg.as_ptr(),
                msg.len(),
                sig.as_ptr(),
                sig.len(),
                ctx.as_ptr(),
                ctx.len(),
                pk.as_ptr(),
                prm,
            );
            log::info!("slh_verify() returned {:x?} on wrong pk", ret);
            assert_eq!(ret, 0);
        }
    }
}
