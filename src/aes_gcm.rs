use crate::Crypter;
use aes_gcm::{
    aead::AeadMut, Aes128Gcm as LibAes128Gcm, Aes256Gcm as LibAes256Gcm, Error, KeyInit,
    KeySizeUser,
};
use generic_array::GenericArray;

pub struct Aes128Gcm;

impl Crypter for Aes128Gcm {
    type Error = Error;

    fn key_length() -> usize {
        LibAes128Gcm::key_size()
    }

    fn iv_length() -> usize {
        12 // 96-bit nonce
    }

    fn encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let key = GenericArray::from_slice(key);
        let nonce = GenericArray::from_slice(iv);
        let mut cipher = LibAes128Gcm::new(key);
        Ok(cipher.encrypt(&nonce, data)?)
    }

    fn onetime_encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Self::encrypt(key, &vec![0; Self::iv_length()], data)
    }

    fn decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let key = GenericArray::from_slice(key);
        let nonce = GenericArray::from_slice(iv);
        let mut cipher = LibAes128Gcm::new(key);
        Ok(cipher.decrypt(&nonce, data)?)
    }

    fn onetime_decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Self::decrypt(key, &vec![0; Self::iv_length()], data)
    }
}

pub struct Aes256Gcm;

impl Crypter for Aes256Gcm {
    type Error = Error;

    fn key_length() -> usize {
        LibAes256Gcm::key_size()
    }

    fn iv_length() -> usize {
        12 // 96-bit nonce
    }

    fn encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let key = GenericArray::from_slice(key);
        let nonce = GenericArray::from_slice(iv);
        let mut cipher = LibAes256Gcm::new(key);
        Ok(cipher.encrypt(&nonce, data)?)
    }

    fn onetime_encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Self::encrypt(key, &vec![0; Self::iv_length()], data)
    }

    fn decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let key = GenericArray::from_slice(key);
        let nonce = GenericArray::from_slice(iv);
        let mut cipher = LibAes256Gcm::new(key);
        Ok(cipher.decrypt(&nonce, data)?)
    }

    fn onetime_decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Self::decrypt(key, &vec![0; Self::iv_length()], data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{thread_rng, RngCore};

    #[test]
    fn aes128gcm_works() -> Result<(), aes_gcm::Error> {
        let mut key = vec![0; Aes128Gcm::key_length()];
        thread_rng().fill_bytes(&mut key);

        let mut iv = vec![0; Aes128Gcm::iv_length()];
        thread_rng().fill_bytes(&mut iv);

        let pt = b"this is a super secret message";
        let ct = Aes128Gcm::encrypt(&key, &iv, pt)?;
        let xt = Aes128Gcm::decrypt(&key, &iv, &ct)?;

        assert_eq!(&pt[..], &xt[..]);

        Ok(())
    }

    #[test]
    fn aes256gcm_works() -> Result<(), aes_gcm::Error> {
        let mut key = vec![0; Aes256Gcm::key_length()];
        thread_rng().fill_bytes(&mut key);

        let mut iv = vec![0; Aes256Gcm::iv_length()];
        thread_rng().fill_bytes(&mut iv);

        let pt = b"this is a super secret message";
        let ct = Aes256Gcm::encrypt(&key, &iv, pt)?;
        let xt = Aes256Gcm::decrypt(&key, &iv, &ct)?;

        assert_eq!(&pt[..], &xt[..]);

        Ok(())
    }
}
