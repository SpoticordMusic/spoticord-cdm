fn main() {
    cc::Build::new()
        .cpp(true)
        .file("cpp/wrapper.cpp")
        .file("cpp/adapter.cpp")
        .flag_if_supported("-std=c++17")
        .compile("widevine_shim");

    println!("cargo:rerun-if-changed=cpp")
}
