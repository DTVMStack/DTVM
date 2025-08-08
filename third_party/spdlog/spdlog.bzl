load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def load_spdlog_deps():
    http_archive(
        name = "zen_deps_spdlog",
        build_file = "//third_party/spdlog:spdlog.BUILD",
        sha256 = "56b90f0bd5b126cf1b623eeb19bf4369516fa68f036bbc22d9729d2da511fb5a",
        strip_prefix = "spdlog-1.4.2",
        urls = [
            "https://github.com/gabime/spdlog/archive/v1.4.2.zip",
        ],
    )
