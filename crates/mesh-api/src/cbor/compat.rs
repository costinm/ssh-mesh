//! Compatibility API for fixed-buffer embedded consumers.
use super::{Decoder, Encoder};

/// Fluent fixed-buffer encoder with sticky failure.
pub struct Writer<'a> {
    encoder: Encoder<'a>,
    failed: bool,
}
impl<'a> Writer<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self {
            encoder: Encoder::new(buf),
            failed: false,
        }
    }
    fn apply(&mut self, f: impl FnOnce(&mut Encoder<'a>) -> Option<()>) -> &mut Self {
        if !self.failed && f(&mut self.encoder).is_none() {
            self.failed = true;
        }
        self
    }
    pub fn uint(&mut self, v: u64) -> &mut Self {
        self.apply(|e| e.uint(v))
    }
    pub fn int(&mut self, v: i64) -> &mut Self {
        self.apply(|e| e.int(v))
    }
    pub fn bytes(&mut self, v: &[u8]) -> &mut Self {
        self.apply(|e| e.bytes(v))
    }
    pub fn text_raw(&mut self, v: &[u8]) -> &mut Self {
        self.apply(|e| e.text_value(v))
    }
    pub fn text(&mut self, v: &str) -> &mut Self {
        self.text_raw(v.as_bytes())
    }
    pub fn raw(&mut self, v: &[u8]) -> &mut Self {
        self.apply(|e| e.raw(v))
    }
    pub fn array(&mut self, n: usize) -> &mut Self {
        self.apply(|e| e.array(n as u64))
    }
    pub fn map(&mut self, n: usize) -> &mut Self {
        self.apply(|e| e.map(n as u64))
    }
    pub fn boolean(&mut self, v: bool) -> &mut Self {
        self.apply(|e| e.boolean(v))
    }
    pub fn null(&mut self) -> &mut Self {
        self.apply(|e| e.null())
    }
    pub fn finish(self) -> Option<&'a [u8]> {
        if self.failed {
            None
        } else {
            Some(self.encoder.finish())
        }
    }
}
/// One typed item; container heads do not consume their children.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Item<'a> {
    Uint(u64),
    Neg(u64),
    Bytes(&'a [u8]),
    Text(&'a [u8]),
    Array(usize),
    Map(usize),
    Bool(bool),
    Null,
}
impl Item<'_> {
    pub fn as_int(&self) -> Option<i64> {
        match *self {
            Self::Uint(n) => i64::try_from(n).ok(),
            Self::Neg(n) => i64::try_from(n).ok().map(|n| -1 - n),
            _ => None,
        }
    }
    pub fn as_uint(&self) -> Option<u64> {
        if let Self::Uint(n) = *self {
            Some(n)
        } else {
            None
        }
    }
}
/// Copyable borrowing typed reader.
#[derive(Clone, Copy)]
pub struct Reader<'a> {
    data: &'a [u8],
}
impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }
    pub fn rest(&self) -> &'a [u8] {
        self.data
    }
    pub fn next(&mut self) -> Option<Item<'a>> {
        let first = *self.data.first()?;
        let mut d = Decoder::new(self.data);
        let (major, n) = d.head()?;
        let item = match major {
            0 => Item::Uint(n),
            1 => Item::Neg(n),
            2 | 3 => {
                let b = d.take(usize::try_from(n).ok()?)?;
                if major == 2 {
                    Item::Bytes(b)
                } else {
                    Item::Text(b)
                }
            }
            4 | 5 => {
                let count = usize::try_from(n).ok()?;
                let required = if major == 5 {
                    count.checked_mul(2)?
                } else {
                    count
                };
                if required > self.data.len().checked_sub(d.position())? {
                    return None;
                }
                if major == 4 {
                    Item::Array(count)
                } else {
                    Item::Map(count)
                }
            }
            7 => match first {
                0xf4 => Item::Bool(false),
                0xf5 => Item::Bool(true),
                0xf6 => Item::Null,
                _ => return None,
            },
            _ => return None,
        };
        self.data = &self.data[d.position()..];
        Some(item)
    }
    /// Skip a complete extended CBOR item using the shared limits.
    pub fn skip(&mut self) -> bool {
        let mut d = Decoder::new(self.data);
        if d.skip().is_none() {
            return false;
        }
        self.data = &self.data[d.position()..];
        true
    }
}
/// Find an unsigned key in a definite map.
pub fn get(data: &[u8], key: u64) -> Result<Option<Reader<'_>>, ()> {
    let mut r = Reader::new(data);
    let Some(Item::Map(pairs)) = r.next() else {
        return Err(());
    };
    for _ in 0..pairs {
        let k = r.next().ok_or(())?;
        if matches!(k, Item::Array(_) | Item::Map(_)) {
            return Err(());
        }
        if k == Item::Uint(key) {
            return Ok(Some(r));
        }
        if !r.skip() {
            return Err(());
        }
    }
    Ok(None)
}
/// Find a signed integer value.
pub fn get_int(data: &[u8], key: u64) -> Result<Option<i64>, ()> {
    match get(data, key)? {
        None => Ok(None),
        Some(mut r) => r.next().and_then(|i| i.as_int()).map(Some).ok_or(()),
    }
}
/// Find a text value, without UTF-8 validation.
pub fn get_text(data: &[u8], key: u64) -> Result<Option<&[u8]>, ()> {
    match get(data, key)? {
        None => Ok(None),
        Some(mut r) => match r.next() {
            Some(Item::Text(t)) => Ok(Some(t)),
            _ => Err(()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::{DEFAULT_MAX_DEPTH, encode};
    #[test]
    fn boundaries_and_facade() {
        for n in [255, 256, 65535, 65536, u64::MAX] {
            let mut buf = [0; 16];
            let mut w = Writer::new(&mut buf);
            w.uint(n);
            let bytes = w.finish().unwrap();
            let mut v = alloc::vec::Vec::new();
            encode::uint(n, &mut v);
            assert_eq!(bytes, &v);
            assert_eq!(Reader::new(bytes).next(), Some(Item::Uint(n)));
        }
        let mut buf = [0; 64];
        let mut w = Writer::new(&mut buf);
        w.map(2).uint(1).int(i64::MIN).uint(2).bytes(&[0xf7]);
        let data = w.finish().unwrap();
        assert_eq!(get_int(data, 1), Ok(Some(i64::MIN)));
        assert_eq!(
            get(data, 2).unwrap().unwrap().next(),
            Some(Item::Bytes(&[0xf7]))
        );
        assert_eq!(
            Decoder::new(&[0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).int(),
            Some(i64::MIN)
        );
        let mut small = [0; 1];
        let mut w = Writer::new(&mut small);
        w.text("long").uint(1);
        assert!(w.finish().is_none());
    }
    #[test]
    fn bounded_extended_skip() {
        for bad in [
            &[0xff][..],
            &[0x1f],
            &[0x9b, 255, 255, 255, 255, 255, 255, 255, 255, 0xff],
            &[0xa1, 1],
            &[0x42, 1],
            &[0x5f, 0x61, 0, 0xff],
            &[0xbf, 1, 0xff],
            &[0xf8, 24],
        ] {
            assert!(Decoder::new(bad).skip().is_none(), "{bad:?}");
            let mut out = [0; 32];
            assert!(Encoder::new(&mut out).encoded_value(bad).is_none());
        }
        for good in [
            &[0xf7][..],
            &[0xf9, 0, 0],
            &[0xc1, 0],
            &[0x9f, 1, 0xff],
            &[0x5f, 0x41, 0xf7, 0xff],
            &[0xbf, 1, 2, 0xff],
        ] {
            let mut d = Decoder::new(good);
            assert!(d.skip().is_some(), "{good:?}");
            assert!(d.is_finished());
        }
        assert_eq!(Reader::new(&[0xf7]).next(), None);
        assert_eq!(Reader::new(&[0xf6]).next(), Some(Item::Null));
        let mut nested = alloc::vec![0x81; DEFAULT_MAX_DEPTH + 1];
        nested.push(0);
        assert!(Decoder::new(&nested).skip().is_none());
        assert!(
            Decoder::new(&[0x82, 1, 2])
                .skip_with_limits(64, 2)
                .is_none()
        );
    }
}
