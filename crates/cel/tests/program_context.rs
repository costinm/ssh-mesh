#![cfg(feature = "program")]

use micro_cel::{Code, program::Context};

#[test]
fn context_replaces_inserts_and_rejects_invalid_updates_atomically() {
    let mut c = Context::new(&[0xa1, 1, 2], 8, 2).unwrap();
    assert_eq!(c.get(1), Some(&[2][..]));
    c.set(1, &[3]).unwrap();
    c.set(2, &[0xf5]).unwrap();
    assert_eq!(c.encoded(), &[0xa2, 1, 3, 2, 0xf5]);
    let old = c.encoded().to_vec();
    assert_eq!(c.set(3, &[0x82]), Err(Code::Malformed));
    assert_eq!(c.set(3, &[0x42, 1, 2]), Err(Code::Size));
    assert_eq!(c.encoded(), old);
}

#[test]
fn context_rejects_duplicate_and_non_integer_keys() {
    assert!(Context::new(&[0xa2, 1, 0, 1, 1], 16, 8).is_err());
    assert!(Context::new(&[0xa1, 0x61, b'x', 0], 16, 8).is_err());
}

#[test]
fn context_rejects_129th_entry_atomically() {
    let mut context = Context::new(&[0xa0], 4096, 64).unwrap();
    for tag in 0..128 {
        context.set(tag, &[0]).unwrap();
    }
    let before = context.encoded().to_vec();
    assert_eq!(context.set(128, &[0]), Err(Code::Size));
    assert_eq!(context.encoded(), before);
    context.set(127, &[1]).unwrap();
    assert_eq!(context.get(127), Some(&[1][..]));
}

#[test]
fn context_checks_depth_after_wrapping_and_preserves_old_value() {
    let mut context = Context::new(&[0xa1, 1, 0], 4096, 128).unwrap();
    let mut boundary = vec![0x81; 31];
    boundary.push(0);
    context.set(1, &boundary).unwrap();
    let before = context.encoded().to_vec();
    let mut too_deep = vec![0x81; 32];
    too_deep.push(0);
    assert_eq!(context.set(1, &too_deep), Err(Code::Depth));
    assert_eq!(context.encoded(), before);
    assert_eq!(context.get(1), Some(boundary.as_slice()));
}
