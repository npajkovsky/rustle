// Copyright The OpenSSL Project Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end test driving the built provider module through the `openssl`
//! CLI: a digest known-answer check via `openssl dgst`.
//!
//! The tests need an OpenSSL 3.x CLI. Run the top-level Makefile with
//! `OPENSSL_ROOT_DIR=/path/to/openssl` to select a custom build tree. If none
//! is available the tests skip (pass vacuously) rather than fail.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// Module name OpenSSL resolves inside the provider path (file stem of the
/// built cdylib).
const MODULE: &str = "libbc_rust";
/// Property query pinning algorithm fetches to this provider.
const PROPQUERY: &str = "provider=bc_rust";

fn openssl_bin() -> String {
    std::env::var("OPENSSL").unwrap_or_else(|_| "openssl".to_owned())
}

/// `target/<profile>/`, where cargo put both this test binary
/// (`target/<profile>/deps/...`) and the provider cdylib.
fn module_dir() -> PathBuf {
    let exe = std::env::current_exe().expect("test binary path");
    exe.parent()
        .and_then(|deps| deps.parent())
        .expect("target profile dir")
        .to_path_buf()
}

/// Returns `false` (skip) when no usable OpenSSL 3.x CLI is around.
fn openssl_available() -> bool {
    match Command::new(openssl_bin()).arg("version").output() {
        Ok(out) if out.status.success() => {
            let version = String::from_utf8_lossy(&out.stdout).into_owned();
            if version.starts_with("OpenSSL 3.") || version.starts_with("OpenSSL 4.") {
                true
            } else {
                eprintln!(
                    "skipping: `{}` is not OpenSSL 3.x/4.x: {version}",
                    openssl_bin()
                );
                false
            }
        }
        _ => {
            eprintln!(
                "skipping: `{}` not runnable; use OPENSSL_ROOT_DIR= with make",
                openssl_bin()
            );
            false
        }
    }
}

/// Args that load the provider module built by this build.
fn provider_args() -> Vec<String> {
    vec![
        "-provider-path".to_owned(),
        module_dir().display().to_string(),
        "-provider".to_owned(),
        MODULE.to_owned(),
        "-propquery".to_owned(),
        PROPQUERY.to_owned(),
    ]
}

/// Runs `openssl dgst -<alg>` over `data` with only this provider loaded and
/// returns the hex digest.
fn dgst(alg: &str, data: &[u8]) -> String {
    let mut cmd = Command::new(openssl_bin());
    cmd.arg("dgst")
        .args(provider_args())
        .arg(format!("-{alg}"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    // Print the whole command (visible with `cargo test -- --nocapture`).
    eprintln!("running: {cmd:?}");
    let mut child = cmd.spawn().expect("spawn openssl dgst");
    child
        .stdin
        .take()
        .expect("child stdin")
        .write_all(data)
        .expect("write stdin");
    let out = child.wait_with_output().expect("openssl dgst output");
    assert!(out.status.success(), "openssl dgst -{alg} failed: {out:?}");
    let stdout = String::from_utf8(out.stdout).expect("utf8 dgst output");
    // "SHA1(stdin)= a9993e36..." — take the hex after the last "= ".
    stdout
        .rsplit_once("= ")
        .expect("dgst output format")
        .1
        .trim()
        .to_owned()
}

/// The provider's digests must match the FIPS 180 known answers when fetched
/// and driven by OpenSSL itself (only this provider is loaded, so the values
/// can only have come from bc-rust).
#[test]
fn openssl_dgst_known_answers() {
    if !openssl_available() {
        return;
    }
    assert_eq!(
        dgst("sha224", b"abc"),
        "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
    );
    assert_eq!(
        dgst("sha256", b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        dgst("sha384", b"abc"),
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
    );
    assert_eq!(
        dgst("sha512", b"abc"),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    );
    assert_eq!(
        dgst("sha3-224", b"abc"),
        "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"
    );
    assert_eq!(
        dgst("sha3-256", b"abc"),
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
    );
    assert_eq!(
        dgst("sha3-384", b"abc"),
        "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"
    );
    assert_eq!(
        dgst("sha3-512", b"abc"),
        "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
    );
}
