use crate::Crypter;
use openssl::{cipher::Cipher, cipher_ctx::CipherCtx, error::ErrorStack};
use paste::paste;

macro_rules! crypter_bulk_impl {
    ($(($crypter:ident,$keylen:expr,$ivlen:expr)),*$(,)?) => {
        $(paste! {
            pub struct [<$crypter:camel>] {
                ctx: CipherCtx,
            }

            impl [<$crypter:camel>] {
                pub fn new() -> Self {
                    let mut ctx = CipherCtx::new().unwrap();

                    ctx.encrypt_init(Some(Cipher::$crypter()), None, None).unwrap();
                    ctx.decrypt_init(Some(Cipher::$crypter()), None, None).unwrap();

                    Self {
                        ctx,
                    }
                }
            }

            impl Crypter for [<$crypter:camel>] {
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

crypter_bulk_impl![(aes_128_ctr, 16, 16), (aes_256_ctr, 32, 16)];

// pub struct StatefulAes128Ctr {
//     ctx: CipherCtx,
// }

// impl StatefulAes128Ctr {
//     pub fn new() -> Self {
//         let mut ctx = CipherCtx::new();

//         let cipher = Cipher::aes_128_ctr();
//         ctx.encrypt_init(Some(cipher))
//     }
// }

// impl StatefulCrypter for StatefulAes128Ctr {
//     type Error = ErrorStack;

//     fn key_length(&self) -> usize;

//     fn iv_length(&self) -> usize;

//     fn encrypt(&self, key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error>;

//     fn onetime_encrypt(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error>;

//     fn decrypt(&self, key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error>;

//     fn onetime_decrypt(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error>;
// }

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

    crypter_test_bulk_impl![aes_128_ctr, aes_256_ctr];
}
