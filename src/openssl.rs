use crate::Crypter;
use openssl::{cipher::Cipher, cipher_ctx::CipherCtx, error::ErrorStack};
use paste::paste;

macro_rules! crypter_bulk_impl {
    ($($crypter:ident),*$(,)?) => {
        $(paste! {
            pub struct [<$crypter:camel>];

            impl Crypter for [<$crypter:camel>] {
                type Error = ErrorStack;

                fn key_length() -> usize {
                    Cipher::$crypter().key_length()
                }

                fn iv_length() -> usize {
                    Cipher::$crypter().iv_length()
                }

                fn encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
                    let cipher = Cipher::$crypter();
                    let mut ctx = CipherCtx::new()?;
                    ctx.encrypt_init(Some(cipher), Some(key), Some(iv))?;

                    let mut output = Vec::with_capacity(data.len());
                    ctx.cipher_update_vec(data, &mut output)?;
                    ctx.cipher_final_vec(&mut output)?;

                    Ok(output)
                }

                fn onetime_encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
                    Self::encrypt(key, &vec![0; Self::iv_length()], data)
                }

                fn decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
                    let cipher = Cipher::$crypter();
                    let mut ctx = CipherCtx::new()?;
                    ctx.decrypt_init(Some(cipher), Some(key), Some(iv))?;

                    let mut output = Vec::with_capacity(data.len());
                    ctx.cipher_update_vec(data, &mut output)?;
                    ctx.cipher_final_vec(&mut output)?;

                    Ok(output)
                }

                fn onetime_decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
                    Self::decrypt(key, &vec![0; Self::iv_length()], data)
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

#[cfg(test)]
mod tests {
    use crate::{openssl::*, Crypter};
    use anyhow::Result;
    use paste::paste;
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
