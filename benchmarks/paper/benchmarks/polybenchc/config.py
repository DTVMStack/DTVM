from configuration.suite_config import suite_config

class SuiteConfig(suite_config):
    testname = "POLYBENCHC-TESTSUITE"
    # WASI modules: dtvm/iwasm use _start (no -f). Wasmtime uses --invoke main.
    func = ""
    dtvm_fOption = ""
    wasmtime_fOption = "--invoke main"
    wasmer_fOption = ""
    interp_ignore = "ludcmp.wasm lu.wasm floyd-warshall.wasm cholesky.wasm nussinov.wasm seidel-2d.wasm symm.wasm syr2k.wasm syrk.wasm trmm.wasm"
    multipass_ignore = "ludcmp.wasm lu.wasm floyd-warshall.wasm cholesky.wasm"
