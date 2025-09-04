use slhdsa_c_rs::bindings;

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

#[test]
fn basic_bindings_test() {
    common::setup().expect("Failed during initial setup");

    unsafe {
        let prm = &bindings::slh_dsa_shake_128f;

        let id = bindings::slh_alg_id(std::ptr::from_ref(prm));
        let id = core::ffi::CStr::from_ptr(id)
            .to_str()
            .expect("Invalid CStr");
        log::info!("id={:?}", id);

        let pk_sz = bindings::slh_pk_sz(std::ptr::from_ref(prm));
        log::info!("pk_sz={:?}", pk_sz);

        let sk_sz = bindings::slh_sk_sz(std::ptr::from_ref(prm));
        log::info!("sk_sz={:?}", sk_sz);
    }
}
