fn main() {
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR");
    std::fs::copy(
        "partitions_4mb_large_app.csv",
        format!("{out_dir}/partitions_4mb_large_app.csv"),
    )
    .expect("copy partitions_4mb_large_app.csv");
    println!("cargo:rerun-if-changed=partitions_4mb_large_app.csv");
    embuild::espidf::sysenv::output();
}
