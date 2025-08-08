// Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use cty::{self};

#[repr(C)]
pub struct ZenRuntimeConfigExtern {
    _mode: i32, // 0: interp, 1: singlepass, 2: multipass
                // other fields not used now
}

#[repr(C)]
pub struct ZenRuntimeExtern {
    // avoid empty struct to be FFI-safe
    _dummy: i32,
}

#[repr(C)]
pub struct ZenModuleExtern {
    _dummy: i32,
}

#[repr(C)]
pub struct ZenIsolationExtern {
    _dummy: i32,
}

#[repr(C)]
pub struct ZenInstanceExtern {
    _dummy: i32,
}

#[repr(C)]
pub struct ZenHostFuncDescExtern {
    pub name: *const cty::c_char,
    pub num_args: cty::uint32_t,
    pub arg_types: *const cty::uint32_t, // 0: i32, 1: i64, 2: f32, 3: f64
    pub num_returns: cty::uint32_t,
    pub ret_types: *const cty::uint32_t, // 0: i32, 1: i64, 2: f32, 3: f64
    pub ptr: *const cty::c_void,         // c function pointer
}

#[repr(C)]
pub struct ZenHostModuleDescExtern {
    _dummy: i32,
}

#[repr(C)]
pub struct ZenHostModuleExtern {
    _dummy: i32,
}

#[repr(C)]
pub struct ZenValueExtern {
    pub value_type: cty::c_int, // enum ZenType, 0: i32, 1: i64, 2: f32, 3: f64
    pub value: cty::int64_t,    // union of i32/i64/f32/f64
}

#[link(name = "zetaengine", kind = "static")]
#[link(name = "utils_lib", kind = "static")]
#[link(name = "asmjit", kind = "static")]
extern "C" {
    pub fn ZenCreateRuntimeConfig(mode: cty::int32_t) -> *mut ZenRuntimeConfigExtern;
    pub fn ZenDeleteRuntimeConfig(config: *mut ZenRuntimeConfigExtern);

    pub fn ZenCreateRuntime(config: *const ZenRuntimeConfigExtern) -> *mut ZenRuntimeExtern;
    pub fn ZenDeleteRuntime(rt: *mut ZenRuntimeExtern);

    pub fn ZenCreateHostModuleDesc(
        rt: *mut ZenRuntimeExtern,
        host_mod_name: *const cty::c_char,
        host_func_descs: *mut ZenHostFuncDescExtern,
        num_host_funcs: cty::uint32_t,
    ) -> *mut ZenHostModuleDescExtern;
    pub fn ZenDeleteHostModuleDesc(
        rt: *mut ZenRuntimeExtern,
        host_module_desc: *mut ZenHostModuleDescExtern,
    );

    pub fn ZenLoadHostModule(
        rt: *mut ZenRuntimeExtern,
        host_module_desc: *mut ZenHostModuleDescExtern,
    ) -> *mut ZenHostModuleExtern;
    // return bool
    pub fn ZenMergeHostModule(
        rt: *mut ZenRuntimeExtern,
        host_module: *mut ZenHostModuleExtern,
        other_host_module_desc: *mut ZenHostModuleDescExtern,
    ) -> cty::uint8_t;
    // return bool
    pub fn ZenDeleteHostModule(
        rt: *mut ZenRuntimeExtern,
        host_module: *mut ZenHostModuleExtern,
    ) -> cty::uint8_t;
    // return bool
    pub fn ZenFilterHostFunctions(
        host_module: *mut ZenHostModuleExtern,
        func_names: *mut *mut cty::c_char,
        num_func_names: cty::uint32_t,
    ) -> cty::uint8_t;

    pub fn ZenLoadModuleFromFile(
        rt: *mut ZenRuntimeExtern,
        wasm_path: *const cty::c_char,
        error_buf: *mut cty::c_char,
        error_buf_size: cty::uint32_t,
    ) -> *mut ZenModuleExtern;

    pub fn ZenLoadModuleFromBuffer(
        rt: *mut ZenRuntimeExtern,
        module_name: *const cty::c_char,
        code: *const cty::uint8_t,
        code_size: cty::uint32_t,
        error_buf: *mut cty::c_char,
        error_buf_size: cty::uint32_t,
    ) -> *mut ZenModuleExtern;

    pub fn ZenGetNumImportFunctions(module: *mut ZenModuleExtern) -> cty::uint32_t;

    // return bool int
    pub fn ZenGetImportFuncName(
        module: *mut ZenModuleExtern,
        func_idx: cty::uint32_t,
        host_module_name_out: *mut cty::c_char,
        host_module_name_size_out: *mut cty::uint32_t,
        host_module_name_out_buf_size: cty::uint32_t,
        func_name_out: *mut cty::c_char,
        func_name_size_out: *mut cty::uint32_t,
        func_name_out_buf_size: cty::uint32_t,
    ) -> cty::uint32_t;

    pub fn ZenDeleteModule(rt: *mut ZenRuntimeExtern, module: *mut ZenModuleExtern);

    pub fn ZenCreateIsolation(rt: *mut ZenRuntimeExtern) -> *mut ZenIsolationExtern;
    pub fn ZenDeleteIsolation(rt: *mut ZenRuntimeExtern, isolation: *mut ZenIsolationExtern);

    pub fn ZenCreateInstance(
        isolation: *mut ZenIsolationExtern,
        wasm_mod: *mut ZenModuleExtern,
        error_buf: *mut cty::c_char,
        error_buf_size: cty::uint32_t,
    ) -> *mut ZenInstanceExtern;
    pub fn ZenCreateInstanceWithGas(
        isolation: *mut ZenIsolationExtern,
        wasm_mod: *mut ZenModuleExtern,
        gas_limit: u64,
        error_buf: *mut cty::c_char,
        error_buf_size: cty::uint32_t,
    ) -> *mut ZenInstanceExtern;
    pub fn ZenDeleteInstance(isolation: *mut ZenIsolationExtern, inst: *mut ZenInstanceExtern);

    // return bool
    pub fn ZenCallWasmFuncByName(
        rt: *mut ZenRuntimeExtern,
        inst: *mut ZenInstanceExtern,
        func_name: *const cty::c_char,
        in_args: *const *const cty::c_char,
        num_in_args: cty::uint32_t,
        out_results: *mut ZenValueExtern,
        out_num_results: *mut cty::uint32_t,
    ) -> cty::int8_t;

    // return bool
    pub fn ZenGetInstanceError(
        inst: *mut ZenInstanceExtern,
        error_buf: *mut cty::c_char,
        error_buf_size: cty::uint32_t,
    ) -> cty::int8_t;

    // return bool
    pub fn ZenValidateHostMemAddr(
        inst: *mut ZenInstanceExtern,
        host_addr: *const cty::c_void,
        size: cty::uint32_t,
    ) -> cty::int8_t;
    // return bool
    pub fn ZenValidateAppMemAddr(
        inst: *mut ZenInstanceExtern,
        offset: cty::uint32_t,
        size: cty::uint32_t,
    ) -> cty::int8_t;
    pub fn ZenGetHostMemAddr(
        inst: *mut ZenInstanceExtern,
        offset: cty::uint32_t,
    ) -> *mut cty::c_void;

    pub fn ZenGetAppMemOffset(
        inst: *mut ZenInstanceExtern,
        host_addr: *const cty::c_void,
    ) -> cty::uint32_t;

    pub fn ZenGetInstanceGasLeft(inst: *mut ZenInstanceExtern) -> cty::uint64_t;
    pub fn ZenSetInstanceGasLeft(inst: *mut ZenInstanceExtern, new_gas: cty::uint64_t);

    pub fn ZenSetInstanceCustomData(inst: *mut ZenInstanceExtern, custom_data: *const cty::c_void);
    pub fn ZenGetInstanceCustomData(inst: *mut ZenInstanceExtern) -> *const cty::c_void;

    pub fn ZenSetInstanceExceptionByHostapi(
        inst: *mut ZenInstanceExtern,
        error_code: cty::uint32_t,
    );

    pub fn ZenGetErrCodeEnvAbort() -> cty::uint32_t;
    pub fn ZenGetErrCodeGasLimitExceeded() -> cty::uint32_t;
    pub fn ZenGetErrCodeOutOfBoundsMemory() -> cty::uint32_t;

    pub fn ZenInstanceExit(inst: *mut ZenInstanceExtern, exit_code: cty::int32_t);

    // return bool
    pub fn ZenGetExportFunc(
        wasm_mod: *mut ZenModuleExtern,
        func_name: *const cty::c_char,
        func_idx_out: *mut cty::uint32_t,
    ) -> cty::int8_t;

    pub fn ZenEnableLogging();
    pub fn ZenDisableLogging();

    pub fn ZenInstanceProtectMemoryAgain(inst: *mut ZenInstanceExtern);
}
