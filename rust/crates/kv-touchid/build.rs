use std::{env, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=src/enclave.swift");
    println!("cargo:rerun-if-changed=Info.plist");
    println!("cargo:rerun-if-env-changed=MACOSX_DEPLOYMENT_TARGET");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    // Embed the product name so native authentication uses it instead of the helper filename.
    // This metadata is covered by the hardened executable's signature.
    let plist = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("Info.plist");
    println!(
        "cargo:rustc-link-arg-bin=kv-touchid=-Wl,-sectcreate,__TEXT,__info_plist,{}",
        plist.display()
    );
    let object = out.join("enclave.o");
    // CryptoKit's documented opaque Secure Enclave representation is a Swift-only API.
    // Keep that bridge small; the process, protocol, vault and policy remain Rust.
    let arch = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("aarch64") => "arm64",
        Ok("x86_64") => "x86_64",
        other => panic!("unsupported target arch for the Swift bridge: {other:?}"),
    };
    let deployment_target = env::var("MACOSX_DEPLOYMENT_TARGET").unwrap_or_else(|_| "14.0".into());
    assert!(Command::new("xcrun")
        .args([
            "swiftc",
            "-parse-as-library",
            "-O",
            "-emit-object",
            "-target",
            &format!("{arch}-apple-macos{deployment_target}"),
            "src/enclave.swift",
            "-o"
        ])
        .arg(&object)
        .status()
        .expect("Xcode command line tools are required")
        .success());
    assert!(Command::new("ar")
        .arg("crs")
        .arg(out.join("libkv_enclave.a"))
        .arg(object)
        .status()
        .unwrap()
        .success());
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-search=native=/usr/lib/swift");
    println!("cargo:rustc-link-lib=static=kv_enclave");
    println!("cargo:rustc-link-lib=dylib=swiftCore");
    for framework in ["Foundation", "Security", "CryptoKit", "LocalAuthentication"] {
        println!("cargo:rustc-link-lib=framework={framework}");
    }
}
