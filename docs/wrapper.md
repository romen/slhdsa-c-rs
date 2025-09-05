This crate provides safe Rust wrappers around the raw FFI bindings, if
the `wrapper` feature is enabled.

The wrappers expose ergonomic Rust APIs and memory safety, modeled using
[RustCrypto] traits to facilitate adoption in Rust projects.

[RustCrypto]: https://github.com/RustCrypto

```ignore
use slh_dsa::*;
use signature::*;

let mut rng = rand::rng();

// Generate a signing key using the SHAKE128f parameter set
let sk = SigningKey::<Shake128f>::new(&mut rng);

// Generate the corresponding public key
let vk = sk.verifying_key();

// Serialize the verifying key and distribute
let vk_bytes = vk.to_bytes();

// Sign a message
let message = b"Hello world";
let sig = sk.sign_with_rng(&mut rng, message); // .sign() can be used for deterministic signatures

// Deserialize a verifying key
let vk_deserialized = vk_bytes.try_into().unwrap();
assert_eq!(vk, vk_deserialized);

assert!(vk_deserialized.verify(message, &sig).is_ok())
```
