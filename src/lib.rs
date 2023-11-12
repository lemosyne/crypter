pub trait Crypter {
    type Error: std::error::Error;

    fn key_length() -> usize;

    fn block_length() -> usize;

    fn iv_length() -> usize;

    fn encrypt(key: &[u8], iv: &[u8], data: &mut [u8]) -> Result<(), Self::Error>;

    fn onetime_encrypt(key: &[u8], data: &mut [u8]) -> Result<(), Self::Error> {
        Self::encrypt(key, &vec![0; Self::iv_length()], data)
    }

    fn decrypt(key: &[u8], iv: &[u8], data: &mut [u8]) -> Result<(), Self::Error>;

    fn onetime_decrypt(key: &[u8], data: &mut [u8]) -> Result<(), Self::Error> {
        Self::decrypt(key, &vec![0; Self::iv_length()], data)
    }
}

pub trait StatefulCrypter {
    type Error;

    fn key_length() -> usize;

    fn block_length() -> usize;

    fn iv_length() -> usize;

    fn encrypt(&mut self, key: &[u8], iv: &[u8], data: &mut [u8]) -> Result<(), Self::Error>;

    fn onetime_encrypt(&mut self, key: &[u8], data: &mut [u8]) -> Result<(), Self::Error> {
        self.encrypt(key, &vec![0; Self::iv_length()], data)
    }

    fn decrypt(&mut self, key: &[u8], iv: &[u8], data: &mut [u8]) -> Result<(), Self::Error>;

    fn onetime_decrypt(&mut self, key: &[u8], data: &mut [u8]) -> Result<(), Self::Error> {
        self.decrypt(key, &vec![0; Self::iv_length()], data)
    }
}

pub mod aes;

#[cfg(feature = "openssl")]
pub mod openssl;

// #[cfg(feature = "chacha20poly1305")]
// pub mod chacha20poly1305;

// #[cfg(feature = "aes-gcm")]
// pub mod aes_gcm;

// #[cfg(feature = "aes-gcm-siv")]
// pub mod aes_gcm_siv;
