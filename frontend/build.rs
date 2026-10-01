fn main() {
    // The Nix build sets these; the page footer shows them.
    for name in ["GIT_REVISION", "GIT_COMMITTED_AT"] {
        println!("cargo:rerun-if-env-changed={name}");
        if let Ok(value) = std::env::var(name) {
            println!("cargo:rustc-env={name}={value}");
        }
    }
}
