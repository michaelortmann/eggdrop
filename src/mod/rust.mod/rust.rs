/* SPDX-License-Identifier: MIT */
/*
 * rust.c -- part of rust.mod
 *
 * Copyright (c) 2021 Michael Ortmann
 */

use std::mem::transmute;
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;

const MODULE_NAME: &str = "rust\0";

#[repr(C)]
pub struct global_funcs {
    /* 0 - 3 */
    mod_malloc: extern "C" fn(c_int, *const c_char, *const c_char, c_int) -> *mut c_void,
    mod_free: extern "C" fn(*mut c_void, *const c_char, *const c_char, c_int),
    egg_context: extern "C" fn(),
    module_rename: extern "C" fn(),
    /* 4 - 7 */
    module_register: extern "C" fn(*const c_char, &[Option<extern "C" fn()>; 4], c_int, c_int),
    module_find: extern "C" fn(),
    module_depend: extern "C" fn(),
    module_undepend: extern "C" fn(*mut c_char) -> c_int,
    /* 8 - 11 */
    add_bind_table: extern "C" fn(),
    del_bind_table: extern "C" fn(),
    find_bind_table: extern "C" fn(),
    check_tcl_bind: extern "C" fn()
}

#[no_mangle]
pub extern "C" fn rust_close() -> *const c_char {
    println!("hello from rust.mod rust_close()");
    ptr::null()
}

#[no_mangle]
pub extern "C" fn rust_start(global: &global_funcs) -> *const c_char {

    //#[repr(C)]
    const RUST_TABLE: [Option<extern "C" fn()>; 4] = [
        Some(unsafe { transmute(rust_start as extern "C" fn(_) -> _) }),
        Some(unsafe { transmute(rust_close as extern "C" fn() -> _) }),
        None,
        None];

    (global.module_register)(MODULE_NAME.as_ptr() as *const c_char, &RUST_TABLE, 0, 1);
    println!("hello from rust.mod rust_start()");

    /* return:
     *   error:
     *     "lame str error\0".as_ptr()
     *   ok:
     *     ptr::null()
     */
    ptr::null()
}
