use glob::glob;

const SLHDSA_C_PATH: &str = &"./slhdsa-c/";

fn compile_c_sources() {
    let include_path = std::path::PathBuf::from(SLHDSA_C_PATH);

    let mut build = cc::Build::new();
    build.include(&include_path);
    build
        .flag("-Wall")
        .flag("-Wextra")
        .flag("-Werror=unused-result")
        .flag("-Wpedantic")
        .flag("-Werror")
        .flag("-Wmissing-prototypes")
        .flag("-Wshadow")
        .flag("-Wpointer-arith")
        .flag("-Wredundant-decls")
        .flag("-Wno-long-long")
        .flag("-Wno-unknown-pragmas")
        .flag("-O3")
        .flag("-fomit-frame-pointer")
        .flag("-std=c99")
        .flag("-pedantic");

    let pattern = include_path.clone().join("*.c");
    let pattern = pattern.to_str().expect("Path not valid UTF-8");

    for entry in glob(pattern).expect("Failed to read glob pattern") {
        match entry {
            Ok(path) => {
                println!("cargo:rerun-if-changed={}", path.display());
                build.file(path);
            }
            Err(e) => eprintln!("Glob error: {:?}", e),
        }
    }

    build.compile("slhdsa-c"); // creates libslhdsa-c.a
}

fn generate_bindings() {
    let include_path = std::path::PathBuf::from(SLHDSA_C_PATH);

    let mut builder = bindgen::Builder::default();
    builder = builder.clang_arg(format!("-I{}", include_path.display()));

    let pattern = include_path.clone().join("*.h");
    let pattern = pattern.to_str().expect("Path not valid UTF-8");

    for entry in glob(pattern).expect("Failed to read glob pattern") {
        match entry {
            Ok(path) => {
                println!("cargo:rerun-if-changed={}", path.display());
                let path = path.to_str().expect("Path not valid UTF-8");
                builder = builder.header(path);
            }
            Err(e) => eprintln!("Glob error: {:?}", e),
        }
    }

    // Filter relevant interfaces
    let builder = builder.allowlist_function("slh_.*")
        .allowlist_var("slh_.*");

    // Generate Rust bindings from the header
    let bindings = builder.generate().expect("Unable to generate bindings");

    // Write bindings to $OUT_DIR/bindings.rs
    let out_path = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}

fn main() {
    // Compile C sources
    compile_c_sources();

    // Generate Rust bindings from the header
    generate_bindings();
}
