// Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::process::Command;

fn main() {
    let project_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("dtvmcore_rust project dir: {}.", project_dir);
    let target_dir = std::env::var("OUT_DIR").unwrap();
    println!("The target directory is {}.", target_dir);

    // build zetaengine C++ project
    println!("building zetaengine...");
    let mut build_cpp_lib_cmd = Command::new("bash");
    build_cpp_lib_cmd.arg("build_cpp_lib.sh");
    build_cpp_lib_cmd.arg("cache");
    build_cpp_lib_cmd.current_dir(&project_dir);
    let mut build_cpp_lib_cmd_handle = build_cpp_lib_cmd
        .spawn()
        .expect("build zetaengine C++ project failed");
    build_cpp_lib_cmd_handle.wait().unwrap();
    println!("built zetaengine done");

    // copy zetaengine static libs to rust crate project dir
    let mut copy_cpp_lib_cmd = Command::new("bash");
    copy_cpp_lib_cmd.arg("copy_deps.sh");
    copy_cpp_lib_cmd.current_dir(&project_dir);
    let mut copy_cpp_lib_cmd_handle = copy_cpp_lib_cmd
        .spawn()
        .expect("build zetaengine C++ project failed");
    copy_cpp_lib_cmd_handle.wait().unwrap();

    // copy and link zetaengine static libs
    enum LibType {
        STATIC,
        DYNAMIC,
    }
    let mut link_libs: Vec<(&str, LibType)> = vec![
        ("zetaengine", LibType::STATIC),
        ("utils_lib", LibType::STATIC),
        ("asmjit", LibType::STATIC),
        ("stdc++", LibType::DYNAMIC),
    ];
    if cfg!(target_os = "macos") {
        link_libs.push(("gcc_s.1.1", LibType::DYNAMIC));
    }

    println!("cargo:rustc-link-search={target_dir}");

    for (lib_name, lib_ty) in link_libs {
        let lib_filename = match lib_ty {
            LibType::STATIC => format!("lib{lib_name}.a"),
            LibType::DYNAMIC => format!("lib{lib_name}.dylib"),
        };
        let target_filepath = format!("{target_dir}/{lib_filename}");
        if lib_name != "stdc++" {
            println!("copying from {lib_filename} to {target_filepath}");
            // copy or overwrite
            std::fs::copy(&lib_filename, &target_filepath).unwrap();
            println!("copying lib {lib_filename} to {target_filepath} done");
        }
        let link_method = match lib_ty {
            LibType::STATIC => "static",
            LibType::DYNAMIC => "dylib",
        };
        println!("cargo:rustc-link-lib={link_method}={lib_name}");
    }
}
