/* SPDX-License-Identifier: MIT */
/*
 * rust.c -- part of rust.mod
 *
 * Copyright (c) 2021 Michael Ortmann
 */

use std::mem::transmute;
use std::ptr;

const MODULE_NAME: &str = "rust\0";

/* can rust-bindgen be used ? */
#[repr(C)]
pub struct global_funcs {
    /* 0 - 3 */
    mod_malloc: extern fn(),
    mod_free: extern fn(),
    egg_context: extern fn(),
    module_rename: extern fn(),
    /* 4 - 7 */
    module_register: extern fn(*const u8, &[Option<extern "C" fn()>; 4], i64, i64),
    module_find: extern fn(),
    module_depend: extern fn(),
    module_undepend: extern fn()
}

#[no_mangle]
pub extern "C" fn rust_close() -> *const u8 {
    println!("hello from rust.mod rust_close()");
    ptr::null()
}

#[no_mangle]
pub extern "C" fn rust_start(global: &global_funcs) -> *const u8 {

    //#[repr(C)]
    const RUST_TABLE: [Option<extern "C" fn()>; 4] = [
        Some(unsafe { transmute(rust_start as extern "C" fn(_) -> _) }),
        Some(unsafe { transmute(rust_close as extern "C" fn() -> _) }),
        None,
        None];

    (global.module_register)(MODULE_NAME.as_ptr(), &RUST_TABLE, 0, 1);
    println!("hello from rust.mod rust_start()");

    /* return:
     *   error:
     *     "lame str error\0".as_ptr()
     *   ok:
     *     ptr::null()
     */
    ptr::null()
}
