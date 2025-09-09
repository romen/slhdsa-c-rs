This crate provides safe Rust wrappers around the raw FFI bindings, if
the `wrapper` feature is enabled.

The wrappers expose ergonomic Rust APIs and memory safety, modeled using
[RustCrypto] traits to facilitate adoption in Rust projects.

[RustCrypto]: https://github.com/RustCrypto

```rust
use slhdsa_c_rs::*;

// Generate a keypair using the SLH-DSA-SHAKE-128f parameter set
let (sk, vk) = keygen::<SLH_DSA_SHAKE_128f>().expect("Keypair generation failed");

// Serialize the verifying key and distribute
let vk_bytes = vk.as_bytes().clone();

// Sign a message
let message = b"Hello world";
let sig = sk.sign(message);

// Serialize the signature and distribute
let sig_bytes = sig.as_bytes().clone();

// Deserialize a verifying key
let vk_deserialized = vk_bytes.try_into().unwrap();
assert_eq!(vk, vk_deserialized);

// Deserialize a signature
let sig_deserialized = sig_bytes.try_into().unwrap();
assert_eq!(sig, sig_deserialized);


assert!(vk_deserialized.verify(message, &sig_deserialized).is_ok())
```
