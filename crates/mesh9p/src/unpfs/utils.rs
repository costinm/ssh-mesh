use {
    crate::fcall::*,
    std::{fs::Metadata, os::unix::prelude::*, path::Path},
    tokio::fs,
};

#[macro_export]
macro_rules! INVALID_FID {
    () => {
        io_err!(InvalidInput, "Invalid fid")
    };
}

pub fn create_buffer(size: usize) -> Vec<u8> {
    vec![0; size]
}

pub async fn get_qid<T: AsRef<Path> + ?Sized>(path: &T) -> crate::Result<Qid> {
    Ok(qid_from_attr(&fs::symlink_metadata(path.as_ref()).await?))
}

pub fn qid_from_attr(attr: &Metadata) -> Qid {
    Qid {
        typ: From::from(attr.file_type()),
        version: 0,
        path: attr.ino(),
    }
}
