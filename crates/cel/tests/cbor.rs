use mesh_api::cbor::{Item, Reader, Writer, get_int, get_text};

#[test]
fn integer_boundaries_and_nonminimal_heads() {
    for value in [0, 23, 24, 255, 256, 65535, 65536, u32::MAX as u64, u64::MAX] {
        let mut buf = [0; 16];
        let mut writer = Writer::new(&mut buf);
        writer.uint(value);
        let bytes = writer.finish().unwrap();
        let item = Reader::new(bytes).next().unwrap();
        assert_eq!(item, Item::Uint(value));
        assert_eq!(item.as_uint(), Some(value));
        assert_eq!(item.as_int(), i64::try_from(value).ok());
        for n in 0..bytes.len() {
            assert_eq!(Reader::new(&bytes[..n]).next(), None);
        }
    }
    for value in [
        i64::MIN,
        -1,
        0,
        23,
        24,
        255,
        256,
        65535,
        65536,
        u32::MAX as i64,
    ] {
        let mut buf = [0; 16];
        let mut writer = Writer::new(&mut buf);
        writer.int(value);
        let bytes = writer.finish().unwrap();
        assert_eq!(Reader::new(bytes).next().unwrap().as_int(), Some(value));
        for n in 0..bytes.len() {
            assert_eq!(Reader::new(&bytes[..n]).next(), None);
        }
    }
    assert_eq!(Reader::new(&[0x19, 1, 0]).next(), Some(Item::Uint(256)));
    assert_eq!(Item::Neg(u64::MAX).as_int(), None);
}

#[test]
fn raw_text_null_and_helpers() {
    let mut buf = [0; 64];
    let mut writer = Writer::new(&mut buf);
    writer
        .map(3)
        .uint(1)
        .text_raw(b"\xffx")
        .uint(2)
        .null()
        .uint(3)
        .int(i64::MIN);
    let data = writer.finish().unwrap();
    assert_eq!(get_text(data, 1), Ok(Some(&b"\xffx"[..])));
    assert_eq!(get_int(data, 3), Ok(Some(i64::MIN)));
    assert!(data.contains(&0xf6));
    assert_eq!(Reader::new(&[0xf6]).next(), Some(Item::Null));
    assert_eq!(
        micro_cel::validate_data(&[0xf7], 32),
        Err(micro_cel::Code::Malformed)
    );
    assert_eq!(
        Reader::new(&[0x41, 0xf7]).next(),
        Some(Item::Bytes(&[0xf7]))
    );
}

#[test]
fn malformed_and_truncated_inputs() {
    for bytes in [
        &[0x5f][..],
        &[0x9f],
        &[0xbf],
        &[0xff],
        &[0x65, b'a'],
        &[0x82, 0],
        &[0xa1, 0],
    ] {
        let mut reader = Reader::new(bytes);
        assert_eq!(reader.next(), None, "{bytes:x?}");
        assert_eq!(reader.rest(), bytes);
    }
    for major in [0x5b, 0x7b, 0x9b, 0xbb] {
        let data = [major, 255, 255, 255, 255, 255, 255, 255, 255];
        assert_eq!(Reader::new(&data).next(), None);
        assert!(!Reader::new(&data).skip());
    }
    let nested = [0x82, 0x62, b'a', b'b', 0xa1, 1, 0xf6];
    for end in 0..nested.len() {
        assert!(!Reader::new(&nested[..end]).skip());
    }
    assert!(Reader::new(&nested).skip());
}

#[test]
fn deep_skip_uses_no_call_stack() {
    let thread = std::thread::Builder::new()
        .stack_size(64 * 1024)
        .spawn(|| {
            let mut bytes = vec![0x81; 12_000];
            bytes.push(0xf6);
            let mut reader = Reader::new(&bytes);
            assert!(!reader.skip());
        })
        .unwrap();
    thread.join().unwrap();
}

#[test]
fn overflow_is_sticky_for_all_write_paths() {
    for size in 0..8 {
        let mut buf = vec![0; size];
        let mut writer = Writer::new(&mut buf);
        writer.text("longer than buffer").uint(1).null().raw(&[1]);
        assert!(writer.finish().is_none());
    }
    let mut buf = [0; 1];
    let mut writer = Writer::new(&mut buf);
    writer.raw(&[1, 2]).boolean(true);
    assert!(writer.finish().is_none());
}

#[test]
fn generic_skip_accepts_extended_items_but_cel_rejects_them() {
    for bytes in [&[0xf7][..], &[0xf9, 0, 0], &[0xc0, 0], &[0x9f, 0xff]] {
        assert!(Reader::new(bytes).skip(), "{bytes:x?}");
        assert!(micro_cel::validate_data(bytes, 32).is_err(), "{bytes:x?}");
    }
}
