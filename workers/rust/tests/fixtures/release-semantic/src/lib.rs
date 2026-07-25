extern crate alloc;

use alloc::string::String;
use core::ops::Range;
use std::process::abort;
use std::vec::Vec;

pub struct Input {
    pub value: u32,
}

pub struct Output {
    pub value: u32,
}

pub fn transform(input: Input) -> Output {
    Output { value: input.value }
}

pub fn build(input: Input) -> Output {
    transform(input)
}

pub fn cycle_left(value: u32) -> u32 {
    if value == 0 {
        0
    } else {
        cycle_right(value - 1)
    }
}

pub fn cycle_right(value: u32) -> u32 {
    if value == 0 {
        0
    } else {
        cycle_left(value - 1)
    }
}

pub fn standard_call(input: Vec<u8>, abort_now: bool) -> Vec<u8> {
    if abort_now {
        abort();
    }
    input
}

pub fn standard_types(name: String, range: Range<usize>) -> String {
    let _ = range;
    name
}
