load("//third_party/asmjit:asmjit.bzl", "load_asmjit_deps")
load("//third_party/CLI11:CLI11.bzl", "load_CLI11_deps")
load("//third_party/intx:intx.bzl", "load_intx_deps")
load("//third_party/spdlog:spdlog.bzl", "load_spdlog_deps")

def _third_party_deps(_ctx):
    load_asmjit_deps()
    load_CLI11_deps()
    load_intx_deps()
    load_spdlog_deps()

third_party_deps = module_extension(
    implementation = _third_party_deps,
)
