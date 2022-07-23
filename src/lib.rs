use openssl::{error, symm};
use paste::paste;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Internal(#[from] error::ErrorStack),
}

pub trait Crypter {
    fn key_length() -> usize;

    fn iv_length() -> Option<usize>;

    fn encrypt(key: &[u8], iv: Option<&[u8]>, pt: &[u8], ct: &mut [u8]);

    fn onetime_encrypt(key: &[u8], pt: &[u8], ct: &mut [u8]);

    fn decrypt(key: &[u8], iv: Option<&[u8]>, ct: &[u8], pt: &mut [u8]);

    fn onetime_decrypt(key: &[u8], ct: &[u8], pt: &mut [u8]);
}

macro_rules! crypter_bulk_impl {
    ($($crypter:ident),*$(,)?) => {
        $(paste! {
            pub struct [<$crypter:camel>];

            impl Crypter for [<$crypter:camel>] {
                fn key_length() -> usize {
                    symm::Cipher::$crypter().key_len()
                }

                fn iv_length() -> Option<usize> {
                    symm::Cipher::$crypter().iv_len()
                }

                fn encrypt(key: &[u8], iv: Option<&[u8]>, pt: &[u8], ct: &mut [u8]) {
                    let mut crypter = symm::Crypter::new(
                        symm::Cipher::$crypter(),
                        symm::Mode::Encrypt,
                        key,
                        iv,
                    ).unwrap();

                    let bytes = crypter.update(pt, ct).unwrap();
                    crypter.finalize(&mut ct[bytes..]).unwrap();
                }

                fn onetime_encrypt(key: &[u8], pt: &[u8], ct: &mut [u8]) {
                    if let Some(length) = Self::iv_length() {
                        Self::encrypt(key, Some(vec![0; length].as_ref()), pt, ct)
                    } else {
                        Self::encrypt(key, None, pt, ct)
                    }
                }

                fn decrypt(key: &[u8], iv: Option<&[u8]>, ct: &[u8], pt: &mut [u8]) {
                    let mut crypter = symm::Crypter::new(
                        symm::Cipher::$crypter(),
                        symm::Mode::Decrypt,
                        key,
                        iv,
                    ).unwrap();

                    let bytes = crypter.update(ct, pt).unwrap();
                    crypter.finalize(&mut pt[bytes..]).unwrap();
                }

                fn onetime_decrypt(key: &[u8], ct: &[u8], pt: &mut [u8]) {
                    if let Some(length) = Self::iv_length() {
                        Self::decrypt(key, Some(vec![0; length].as_ref()), ct, pt)
                    } else {
                        Self::decrypt(key, None, ct, pt)
                    }
                }
            }
        })*
    };
}

crypter_bulk_impl!(
    aes_128_ctr,
    aes_128_xts,
    aes_128_ofb,
    aes_256_ctr,
    aes_256_ofb,
);

pub mod prelude {
    pub use crate::*;
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{thread_rng, RngCore};

    macro_rules! crypter_test_bulk_impl {
        ($($crypter:ident),*$(,)?) => {
            $(paste! {
                #[test]
                fn $crypter() {
                    let mut key = vec![0; [<$crypter:camel>]::key_length()];
                    thread_rng().fill_bytes(&mut key);

                    let pt = b"this is a super secret message";
                    let mut ct = vec![0; pt.len()];
                    let mut xt = vec![0; pt.len()];

                    [<$crypter:camel>]::onetime_encrypt(&key, pt, &mut ct);
                    [<$crypter:camel>]::onetime_decrypt(&key, &ct, &mut xt);

                    assert_eq!(&pt[..], &xt[..]);
                }
            })*
        };
    }

    crypter_test_bulk_impl!(
        aes_128_ctr,
        aes_128_xts,
        aes_128_ofb,
        aes_256_ctr,
        aes_256_ofb,
    );
}
