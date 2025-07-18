load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def load_intx_deps():
    http_archive(
        name = "intx",
        build_file = "//third_party/intx:intx.BUILD",
        sha256 = "9e71d8307f10fde019e1f7bc36831d0a41e30130dee5afbba7179fb120b2609a",
        strip_prefix = "intx-0.9.3",
        urls = [
            "https://github.com/chfast/intx/archive/v0.9.3.zip",
        ],
    )
