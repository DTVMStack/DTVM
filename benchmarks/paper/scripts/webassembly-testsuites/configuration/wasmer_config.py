from runtime_config import runtime_config

class runtime_config(runtime_config):
    fOption = "-i"
    command_template = "{command} run {wasm_file} {dtvm_options} {fOption} {func} {fargsOptions} {args_list}"
