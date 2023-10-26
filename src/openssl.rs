use crate::{Crypter, StatefulCrypter};
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

                fn decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
                    let cipher = Cipher::$crypter();
                    let mut ctx = CipherCtx::new()?;
                    ctx.decrypt_init(Some(cipher), Some(key), Some(iv))?;

                    let mut output = Vec::with_capacity(data.len());
                    ctx.cipher_update_vec(data, &mut output)?;
                    ctx.cipher_final_vec(&mut output)?;

                    Ok(output)
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

macro_rules! stateful_crypter_bulk_impl {
    ($(($crypter:ident,$keylen:expr,$ivlen:expr)),*$(,)?) => {
        $(paste! {
            pub struct [<Stateful $crypter:camel>] {
                ctx: CipherCtx,
            }

            impl [<Stateful $crypter:camel>] {
                pub fn new() -> Self {
                    let mut ctx = CipherCtx::new().unwrap();

                    ctx.encrypt_init(Some(Cipher::$crypter()), None, None).unwrap();
                    ctx.decrypt_init(Some(Cipher::$crypter()), None, None).unwrap();

                    Self {
                        ctx,
                    }
                }
            }

            impl Default for [<Stateful $crypter:camel>] {
                fn default() -> Self {
                    Self::new()
                }
            }

            impl StatefulCrypter for [<Stateful $crypter:camel>] {
                type Error = ErrorStack;

                fn key_length() -> usize {
                    $keylen
                }

                fn iv_length() -> usize {
                    $ivlen
                }

                fn encrypt(&mut self, key: &[u8], iv: &[u8], data: &mut [u8]) -> Result<(), Self::Error> {
                    self.ctx.encrypt_init(None, Some(key), Some(iv))?;
                    let n = self.ctx.cipher_update_inplace(data, data.len())?;
                    self.ctx.cipher_final(&mut data[n..])?;
                    Ok(())
                }

                fn decrypt(&mut self, key: &[u8], iv: &[u8], data: &mut [u8]) -> Result<(), Self::Error> {
                    self.ctx.decrypt_init(None, Some(key), Some(iv))?;
                    let n = self.ctx.cipher_update_inplace(data, data.len())?;
                    self.ctx.cipher_final(&mut data[n..])?;
                    Ok(())
                }
            }
        })*
    };
}

stateful_crypter_bulk_impl![(aes_128_ctr, 16, 16), (aes_256_ctr, 32, 16),];

#[cfg(test)]
mod tests {
    use crate::{openssl::*, Crypter, StatefulCrypter};
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

    crypter_test_bulk_impl![
        aes_128_cbc,
        aes_128_ctr,
        aes_128_xts,
        aes_128_ofb,
        aes_256_cbc,
        aes_256_ctr,
        aes_256_ofb,
    ];

    macro_rules! stateful_crypter_test_bulk_impl {
        ($($crypter:ident),*$(,)?) => {
            $(paste! {
                #[test]
                fn $crypter() -> Result<()> {
                    let mut key = vec![0; [<$crypter:camel>]::key_length()];
                    thread_rng().fill_bytes(&mut key);

                    let mut iv = vec![0; [<$crypter:camel>]::iv_length()];
                    thread_rng().fill_bytes(&mut iv);

                    let mut crypter = [<$crypter:camel>]::new();
                    let pt = b"this is a super secret message";
                    let mut ct = pt.to_vec();

                    crypter.encrypt(&key, &iv, &mut ct)?;
                    assert_ne!(&pt[..], &ct[..]);

                    crypter.decrypt(&key, &iv, &mut ct)?;
                    assert_eq!(&pt[..], &ct[..]);

                    Ok(())
                }
            })*
        };
    }

    stateful_crypter_test_bulk_impl![stateful_aes128_ctr, stateful_aes256_ctr];
}
