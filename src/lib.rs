use openssl::{cipher::Cipher, cipher_ctx::CipherCtx, error};
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

    fn iv_length() -> usize;

    fn encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>>;

    fn onetime_encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>>;

    fn decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>>;

    fn onetime_decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>>;
}

macro_rules! crypter_bulk_impl {
    ($($crypter:ident),*$(,)?) => {
        $(paste! {
            pub struct [<$crypter:camel>];

            impl Crypter for [<$crypter:camel>] {
                fn key_length() -> usize {
                    Cipher::$crypter().key_length()
                }

                fn iv_length() -> usize {
                    Cipher::$crypter().iv_length()
                }

                fn encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
                    let cipher = Cipher::$crypter();
                    let mut ctx = CipherCtx::new()?;
                    ctx.encrypt_init(Some(cipher), Some(key), Some(iv))?;

                    let mut output = Vec::with_capacity(data.len());
                    ctx.cipher_update_vec(data, &mut output)?;
                    ctx.cipher_final_vec(&mut output)?;

                    Ok(output)
                }

                fn onetime_encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
                    let iv = vec![0; Self::iv_length()];
                    Self::encrypt(key, &iv, data)
                }

                fn decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
                    let cipher = Cipher::$crypter();
                    let mut ctx = CipherCtx::new()?;
                    ctx.decrypt_init(Some(cipher), Some(key), Some(iv))?;

                    let mut output = Vec::with_capacity(data.len());
                    ctx.cipher_update_vec(data, &mut output)?;
                    ctx.cipher_final_vec(&mut output)?;

                    Ok(output)
                }

                fn onetime_decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
                    let iv = vec![0; Self::iv_length()];
                    Self::decrypt(key, &iv, data)
                }
            }
        })*
    };
}

crypter_bulk_impl!(
    aes_128_cbc,
    aes_128_ctr,
    aes_128_xts,
    aes_128_ofb,
    aes_256_cbc,
    aes_256_ctr,
    aes_256_ofb,
);

pub mod prelude {
    pub use crate::*;
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use rand::{thread_rng, RngCore};

    macro_rules! crypter_test_bulk_impl {
        ($($crypter:ident),*$(,)?) => {
            $(paste! {
                #[test]
                fn $crypter() -> Result<()> {
                    let mut key = vec![0; [<$crypter:camel>]::key_length()];
                    thread_rng().fill_bytes(&mut key);

                    let mut iv = vec![0; [<$crypter:camel>]::iv_length()];
                    thread_rng().fill_bytes(&mut iv);

                    let pt = b"this is a super secret message";
                    let ct = [<$crypter:camel>]::encrypt(&key, &iv, pt)?;
                    let xt = [<$crypter:camel>]::decrypt(&key, &iv, &ct)?;

                    assert_eq!(&pt[..], &xt[..]);

                    Ok(())
                }
            })*
        };
    }

    crypter_test_bulk_impl!(
        aes_128_cbc,
        aes_128_ctr,
        aes_128_xts,
        aes_128_ofb,
        aes_256_cbc,
        aes_256_ctr,
        aes_256_ofb,
    );
}
