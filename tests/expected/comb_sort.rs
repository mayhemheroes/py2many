//! ```cargo
//! [package]
//! edition = "2018"
//! [dependencies]
//! anyhow = "*"
//! ```

#![allow(clippy::collapsible_else_if)]
#![allow(clippy::double_parens)] // https://github.com/adsharma/py2many/issues/17
#![allow(clippy::map_identity)]
#![allow(clippy::needless_return)]
#![allow(clippy::print_literal)]
#![allow(clippy::ptr_arg)]
#![allow(clippy::redundant_static_lifetimes)] // https://github.com/adsharma/py2many/issues/266
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::useless_vec)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(unused_imports)]
#![allow(unused_mut)]
#![allow(unused_parens)]

extern crate anyhow;
use anyhow::Result;
use std::cmp;
use std::collections;

pub fn comb_sort(seq: &mut Vec<i32>) -> Vec<i32> {
    let mut gap = seq.len() as i32;
    let mut swap: bool = true;
    while (gap as i32) > 1 || swap {
        gap = cmp::max(1, ((gap as f64) / 1.25).floor() as i32);
        swap = false;
        for i in (0..(seq.len() as i32 - gap)) {
            if seq[i as usize] > seq[(i + gap) as usize] {
                ({
                    let (__tmp1, __tmp2) = (seq[(i + gap) as usize], seq[i as usize]);
                    seq[i as usize] = __tmp1;
                    seq[(i + gap) as usize] = __tmp2;
                });
                swap = true;
            }
        }
    }
    return seq.to_vec();
}

pub fn main() -> Result<()> {
    let mut unsorted: &mut Vec<i32> = &mut vec![14, 11, 19, 5, 16, 10, 19, 12, 5, 12];
    let expected: &Vec<i32> = &vec![5, 5, 10, 11, 12, 12, 14, 16, 19, 19];
    assert!(comb_sort(unsorted) == *expected);
    println!("{}", "OK");
    Ok(())
}
