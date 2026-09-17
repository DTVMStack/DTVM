from configuration.suite_config import suite_config

class SuiteConfig(suite_config):
    testname = "WAPM-TESTSUITE"
    interp_ignore = "main.wasm wasm3.wasm"
    ignore_case = "sqlite.wasm"
    command = "{input_command} | {runtime} {memory_options}"
