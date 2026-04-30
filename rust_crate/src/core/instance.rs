// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use std::ffi::CStr;

use crate::core::r#extern::{
    ZenGetErrCodeEnvAbort, ZenGetErrCodeGasLimitExceeded, ZenGetErrCodeOutOfBoundsMemory,
    ZenInstanceProtectMemoryAgain,
};
use crate::core::runtime::ZenRuntime;
use cty::c_void;
use std::cell::RefCell;
use std::rc::Rc;

use super::{
    isolation::ZenIsolation,
    r#extern::{
        ZenCallWasmFuncByName, ZenDeleteInstance, ZenGetAppMemOffset, ZenGetHostMemAddr,
        ZenGetInstanceCustomData, ZenGetInstanceError, ZenGetInstanceGasLeft, ZenInstanceExit,
        ZenInstanceExtern, ZenSetInstanceCustomData, ZenSetInstanceExceptionByHostapi,
        ZenSetInstanceGasLeft, ZenValidateAppMemAddr, ZenValidateHostMemAddr, ZenValueExtern,
    },
    runtime::{ZenModule, ERROR_BUF_SIZE},
    types::ZenValue,
    utils::{at_least, rust_str_to_c_str, ScopedMalloc},
};

pub struct ZenInstance<T> {
    pub rt: RefCell<Option<Rc<ZenRuntime>>>,
    pub isolation: RefCell<Option<Rc<ZenIsolation>>>,
    pub wasm_mod: RefCell<Option<Rc<ZenModule>>>,
    pub ptr: *mut ZenInstanceExtern,
    // extra ctx data
    pub extra_ctx: T,
}

impl<T> Drop for ZenInstance<T> {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                ZenDeleteInstance(self.isolation.borrow().as_ref().unwrap().ptr, self.ptr);
            }
        }
        // remove ref of isolation, so the isolation can be auto-dropped after instance dropped
        *self.isolation.borrow_mut() = None;
        // remove ref of ZenModule
        *self.wasm_mod.borrow_mut() = None;
        // remove ref of ZenRuntime
        *self.rt.borrow_mut() = None;
    }
}

impl<T> ZenInstance<T> {
    // custom data in wasm instance used for keep rust ZenInstance*, so user can't use it to store other objects
    fn set_raw_custom_data<DT>(&self, custom_data: *const DT) {
        unsafe {
            ZenSetInstanceCustomData(self.ptr, custom_data as *const c_void);
        }
    }

    #[allow(dead_code)]
    fn get_raw_custom_data<DT>(&self) -> *const DT {
        unsafe { ZenGetInstanceCustomData(self.ptr) as *const DT }
    }

    pub fn set_extra_ctx(&mut self, extra_ctx: T) {
        self.extra_ctx = extra_ctx;
    }

    pub fn get_extra_ctx(&self) -> &T {
        &self.extra_ctx
    }

    /// get rust ZenInstance from c instance* pointer
    ///
    /// # Panics
    /// Panics if `c_ptr` is null or if the returned custom data pointer is
    /// null or misaligned.
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn from_raw_pointer(c_ptr: *mut ZenInstanceExtern) -> &'static ZenInstance<T> {
        assert!(!c_ptr.is_null(), "from_raw_pointer: c_ptr is null");
        let rust_ptr: *const ZenInstance<T> =
            unsafe { ZenGetInstanceCustomData(c_ptr) as *const ZenInstance<T> };
        assert!(!rust_ptr.is_null(), "from_raw_pointer: custom data pointer is null");
        assert!(
            (rust_ptr as usize) % core::mem::align_of::<ZenInstance<T>>() == 0,
            "from_raw_pointer: custom data pointer is misaligned"
        );
        unsafe { &*rust_ptr }
    }

    /// get host memory from linear memory offset
    pub fn get_host_memory(&self, offset: u32) -> *mut u8 {
        let ptr = unsafe { ZenGetHostMemAddr(self.ptr, offset) };
        ptr as *mut u8
    }

    pub fn get_wasm_addr(&self, host_addr: *mut u8) -> u32 {
        unsafe { ZenGetAppMemOffset(self.ptr, host_addr as *const cty::c_void) }
    }

    pub fn validate_wasm_addr(&self, offset: u32, size: u32) -> bool {
        let bool_int = unsafe { ZenValidateAppMemAddr(self.ptr, offset, size) };
        bool_int != 0
    }

    pub fn validate_host_addr(&self, host_addr: *const u8, size: u32) -> bool {
        let bool_int =
            unsafe { ZenValidateHostMemAddr(self.ptr, host_addr as *const cty::c_void, size) };
        bool_int != 0
    }

    pub fn get_gas_left(&self) -> u64 {
        unsafe { ZenGetInstanceGasLeft(self.ptr) }
    }

    pub fn set_gas_left(&self, new_gas: u64) {
        unsafe {
            ZenSetInstanceGasLeft(self.ptr, new_gas);
        }
    }

    pub fn raise_out_of_gas_error(&self) {
        let err_code = unsafe { ZenGetErrCodeGasLimitExceeded() };
        self.set_exception_by_hostapi(err_code)
    }

    pub fn raise_out_of_bounds_memory_error(&self) {
        let err_code = unsafe { ZenGetErrCodeOutOfBoundsMemory() };
        self.set_exception_by_hostapi(err_code)
    }

    pub fn raise_abort_error(&self) {
        let err_code = unsafe { ZenGetErrCodeEnvAbort() };
        self.set_exception_by_hostapi(err_code)
    }

    pub fn set_exception_by_hostapi(&self, error_code: u32) {
        unsafe {
            ZenSetInstanceExceptionByHostapi(self.ptr, error_code);
        }
    }

    pub fn exit(&self, exit_code: i32) {
        unsafe {
            ZenInstanceExit(self.ptr, exit_code);
        }
    }

    pub fn protect_memory_again(&self) {
        unsafe {
            ZenInstanceProtectMemoryAgain(self.ptr);
        }
    }

    /// because &ZenInstance will be get in hostapi by pointer cast
    /// so the memory of the ZenInstance should not be moved
    pub fn new(
        rt: Rc<ZenRuntime>,
        isolation: Rc<ZenIsolation>,
        wasm_mod: &Rc<ZenModule>,
        ptr: *mut ZenInstanceExtern,
        extra_ctx: T,
    ) -> Rc<ZenInstance<T>> {
        let inst = Rc::new(ZenInstance {
            rt: RefCell::new(Some(rt)),
            isolation: RefCell::new(Some(isolation)),
            wasm_mod: RefCell::new(Some(wasm_mod.clone())),
            ptr,
            extra_ctx,
        });
        inst.set_raw_custom_data(inst.as_ref() as *const ZenInstance<T>);
        inst
    }

    /// get linear memory offset by host memory pointer
    pub fn get_linear_memory_offset(&self, host_addr: *const u8) -> u32 {
        unsafe { ZenGetAppMemOffset(self.ptr, host_addr as *const cty::c_void) }
    }

    pub fn call_wasm_func(
        &self,
        func_name: &str,
        args: &[ZenValue],
    ) -> Result<Vec<ZenValue>, String> {
        let func_name_c_bytes = rust_str_to_c_str(func_name);
        let func_name_c_str = CStr::from_bytes_until_nul(&func_name_c_bytes).unwrap();
        let args_count: usize = args.len();
        // let mut func_c_args: *mut *mut cty::c_char = null_mut();
        let func_c_args: ScopedMalloc<*mut cty::c_char> =
            ScopedMalloc::new(at_least(args_count, 1));
        let func_c_args = func_c_args.data();
        // put c bytes memory in here, so items in func_c_args will ref to all_args_c_bytes(avoid str freeed before used)
        let mut all_args_c_bytes: Vec<Vec<u8>> = vec![];
        if args_count > 0 {
            // put args to func_c_args as string
            let mut cur_func_c_args_ptr = func_c_args;
            for arg in args {
                let arg0_c_bytes = arg.to_c_str_bytes();
                all_args_c_bytes.push(arg0_c_bytes);
                let arg0_c_bytes: &Vec<u8> = all_args_c_bytes.last().unwrap();
                unsafe {
                    let arg_c_str = CStr::from_bytes_until_nul(arg0_c_bytes).unwrap();
                    *cur_func_c_args_ptr = arg_c_str.as_ptr() as *mut cty::c_char;
                    cur_func_c_args_ptr = cur_func_c_args_ptr.add(1);
                }
            }
        }

        let func_c_args = func_c_args as *const *const cty::c_char;

        // zero or one output
        let output_max_count: usize = 1;
        let out_values: ScopedMalloc<ZenValueExtern> = ScopedMalloc::new(output_max_count);
        let out_values = out_values.data();

        let mut out_num_values: cty::uint32_t = 0;

        let ret_bool = unsafe {
            ZenCallWasmFuncByName(
                self.rt.borrow().as_ref().unwrap().ptr,
                self.ptr,
                func_name_c_str.as_ptr(),
                func_c_args,
                args_count as cty::uint32_t,
                out_values,
                &mut out_num_values,
            )
        };
        if ret_bool == 0 {
            let mut error_buf: [cty::c_char; ERROR_BUF_SIZE] = [0; ERROR_BUF_SIZE];
            let get_error_ret_bool = unsafe {
                ZenGetInstanceError(
                    self.ptr,
                    (&mut error_buf) as *mut cty::c_char,
                    ERROR_BUF_SIZE as u32,
                )
            };
            if get_error_ret_bool == 0 {
                return Err("call wasm func error".to_string());
            }
            let instance_error_str = unsafe { CStr::from_ptr((&error_buf) as *const cty::c_char) }
                .to_str()
                .unwrap();

            Err(instance_error_str.to_string())
        } else {
            // get result
            let mut result_values: Vec<ZenValue> = vec![];

            for i in 0..out_num_values {
                unsafe {
                    let item_ptr = out_values.add(i as usize);
                    let first_result = item_ptr.read();
                    let value = match first_result.value_type {
                        0 => ZenValue::ZenI32Value(first_result.value as i32),
                        1 => ZenValue::ZenI64Value(first_result.value),
                        2 => ZenValue::ZenF32Value(first_result.value as f32),
                        3 => ZenValue::ZenF64Value(first_result.value as f64),
                        _ => return Err("invalid wasm func return value type".to_string()),
                    };
                    result_values.push(value);
                }
            }
            Ok(result_values)
        }
    }
}
