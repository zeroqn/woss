use blake2b_ref::{Blake2b, Blake2bBuilder};

pub fn blake2b_hasher() -> Blake2b {
    Blake2bBuilder::new(32).personal(b"woss").build()
}

pub fn blake2b<'a>(data: impl IntoIterator<Item = &'a [u8]>) -> [u8; 32] {
    let mut buf = [0u8; 32];
    let mut blake2b = Blake2bBuilder::new(32).personal(b"woss").build();
    data.into_iter().for_each(|d| blake2b.update(d));
    blake2b.finalize(&mut buf);
    buf
}
