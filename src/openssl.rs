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

                fn block_length() -> usize {
                    Cipher::$crypter().block_size()
                }

                fn iv_length() -> usize {
                    Cipher::$crypter().iv_length()
                }

                fn encrypt(key: &[u8], iv: &[u8], data: &mut [u8]) -> Result<(), Self::Error> {
                    let cipher = Cipher::$crypter();
                    let mut ctx = CipherCtx::new()?;
                    ctx.encrypt_init(Some(cipher), Some(key), Some(iv))?;

                    let n = ctx.cipher_update_inplace(data, data.len())?;
                    ctx.cipher_final(&mut data[n..])?;

                    Ok(())
                }

                fn decrypt(key: &[u8], iv: &[u8], data: &mut [u8]) -> Result<(), Self::Error> {
                    let cipher = Cipher::$crypter();
                    let mut ctx = CipherCtx::new()?;
                    ctx.decrypt_init(Some(cipher), Some(key), Some(iv))?;

                    let n = ctx.cipher_update_inplace(data, data.len())?;
                    ctx.cipher_final(&mut data[n..])?;

                    Ok(())
                }
            }
        })*
    };
}

crypter_bulk_impl![aes_128_ctr, aes_256_ctr];

macro_rules! stateful_crypter_bulk_impl {
    ($(($crypter:ident,$blklen:expr,$keylen:expr,$ivlen:expr)),*$(,)?) => {
        $(paste! {
            pub struct [<Stateful $crypter:camel>] {
                encrypt_ctx: CipherCtx,
                decrypt_ctx: CipherCtx,
            }

            impl [<Stateful $crypter:camel>] {
                pub fn new() -> Self {
                    let mut encrypt_ctx = CipherCtx::new().unwrap();
                    let mut decrypt_ctx = CipherCtx::new().unwrap();

                    encrypt_ctx.encrypt_init(Some(Cipher::$crypter()), None, None).unwrap();
                    decrypt_ctx.decrypt_init(Some(Cipher::$crypter()), None, None).unwrap();

                    encrypt_ctx.set_iv_length($ivlen).unwrap();
                    decrypt_ctx.set_iv_length($ivlen).unwrap();

                    encrypt_ctx.set_key_length($keylen).unwrap();
                    decrypt_ctx.set_key_length($keylen).unwrap();

                    Self {
                        encrypt_ctx,
                        decrypt_ctx,
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

                fn block_length() -> usize {
                    $blklen
                }

                fn key_length() -> usize {
                    $keylen
                }

                fn iv_length() -> usize {
                    $ivlen
                }

                fn encrypt(&mut self, key: &[u8], iv: &[u8], data: &mut [u8]) -> Result<(), Self::Error> {
                    // let cipher = Cipher::$crypter();
                    // let mut ctx = CipherCtx::new()?;
                    // ctx.encrypt_init(Some(cipher), Some(key), Some(iv))?;

                    // let n = ctx.cipher_update_inplace(data, data.len())?;
                    // ctx.cipher_final(&mut data[n..])?;

                    // Ok(())

                    // ctx.encrypt_init(Some(Cipher::$crypter()), None, None).unwrap();
                    // self.ctx.encrypt_init(Some(Cipher::$crypter()), Some(key), Some(iv))?;
                    self.encrypt_ctx.encrypt_init(None, Some(key), Some(iv))?;
                    let n = self.encrypt_ctx.cipher_update_inplace(data, data.len())?;
                    self.encrypt_ctx.cipher_final(&mut data[n..])?;
                    Ok(())
                }

                fn decrypt(&mut self, key: &[u8], iv: &[u8], data: &mut [u8]) -> Result<(), Self::Error> {
                    // let cipher = Cipher::$crypter();
                    // let mut ctx = CipherCtx::new()?;
                    // ctx.decrypt_init(Some(cipher), Some(key), Some(iv))?;

                    // let n = ctx.cipher_update_inplace(data, data.len())?;
                    // ctx.cipher_final(&mut data[n..])?;

                    // Ok(())

                    // self.ctx.decrypt_init(None, Some(key), Some(iv))?;
                    // self.ctx.decrypt_init(Some(Cipher::$crypter()), Some(key), Some(iv))?;
                    self.decrypt_ctx.decrypt_init(None, Some(key), Some(iv))?;
                    let n = self.decrypt_ctx.cipher_update_inplace(data, data.len())?;
                    self.decrypt_ctx.cipher_final(&mut data[n..])?;
                    Ok(())
                }
            }
        })*
    };
}

stateful_crypter_bulk_impl![(aes_128_ctr, 16, 16, 16), (aes_256_ctr, 16, 32, 16),];

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
                    let mut ct = pt.to_vec();

                    [<$crypter:camel>]::encrypt(&key, &iv, &mut ct)?;
                    assert_ne!(&pt[..], &ct[..]);

                    [<$crypter:camel>]::decrypt(&key, &iv, &mut ct)?;
                    assert_eq!(&pt[..], &ct[..]);

                    Ok(())
                }
            })*
        };
    }

    crypter_test_bulk_impl![aes_128_ctr, aes_256_ctr];

    macro_rules! stateful_crypter_test_bulk_impl {
        ($($crypter:ident),*$(,)?) => {
            $(paste! {
                #[test]
                fn $crypter() -> Result<()> {
                    let mut key = vec![0; [<$crypter:camel>]::key_length()];
                    thread_rng().fill_bytes(&mut key);

                    let mut iv = vec![0; [<$crypter:camel>]::iv_length()];
                    thread_rng().fill_bytes(&mut iv);

                    let mut crypter = [<$crypter:camel>]::default();
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
