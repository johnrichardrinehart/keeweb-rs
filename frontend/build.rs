fn main() {
    // Pass GIT_REVISION to the build if set
    if let Ok(rev) = std::env::var("GIT_REVISION") {
        println!("cargo:rustc-env=GIT_REVISION={}", rev);
    }
}
