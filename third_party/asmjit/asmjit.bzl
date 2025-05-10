load("@bazel_tools//tools/build_defs/repo:git.bzl", "new_git_repository")
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def load_asmjit_deps():
    http_archive(
        name = "zen_deps_asmjit",
        build_file = "@zetaengine//third_party/asmjit:asmjit.BUILD",
        # tag = "2023-06-09",
        # commit = "3577608cab0bc509f856ebf6e41b2f9d9f71acc4",
        sha256 = "4845eb9d9e6e8da34694c451a00bc3a4c02fe1f60e12dbde9f09ae5ecb690528",
        strip_prefix = "asmjit-3577608cab0bc509f856ebf6e41b2f9d9f71acc4",
        # https://github.com/asmjit/asmjit
        urls = [
            "https://codeload.github.com/asmjit/asmjit/zip/3577608cab0bc509f856ebf6e41b2f9d9f71acc4",
        ],
        type = "zip",
    )

