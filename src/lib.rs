pub trait Crypter {
    type Error;

    fn key_length() -> usize;

    fn iv_length() -> usize;

    fn encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error>;

    fn onetime_encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error>;

    fn decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error>;

    fn onetime_decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

#[cfg(feature = "openssl")]
pub mod openssl;

#[cfg(feature = "chacha20poly1305")]
pub mod chacha20poly1305;

#[cfg(feature = "aes-gcm")]
pub mod aes_gcm;

#[cfg(feature = "aes-gcm-siv")]
pub mod aes_gcm_siv;
