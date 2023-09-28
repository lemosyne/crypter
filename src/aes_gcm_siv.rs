use crate::Crypter;
use aes_gcm_siv::{
    aead::AeadMut, Aes128GcmSiv as LibAes128GcmSiv, Aes256GcmSiv as LibAes256GcmSiv, Error,
    KeyInit, KeySizeUser,
};
use generic_array::GenericArray;

pub struct Aes128GcmSiv;

impl Crypter for Aes128GcmSiv {
    type Error = Error;

    fn key_length() -> usize {
        LibAes128GcmSiv::key_size()
    }

    fn iv_length() -> usize {
        12 // 96-bit nonce
    }

    fn encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let key = GenericArray::from_slice(key);
        let nonce = GenericArray::from_slice(iv);
        let mut cipher = LibAes128GcmSiv::new(key);
        Ok(cipher.encrypt(&nonce, data)?)
    }

    fn onetime_encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Self::encrypt(key, &vec![0; Self::iv_length()], data)
    }

    fn decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let key = GenericArray::from_slice(key);
        let nonce = GenericArray::from_slice(iv);
        let mut cipher = LibAes128GcmSiv::new(key);
        Ok(cipher.decrypt(&nonce, data)?)
    }

    fn onetime_decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Self::decrypt(key, &vec![0; Self::iv_length()], data)
    }
}

pub struct Aes256GcmSiv;

impl Crypter for Aes256GcmSiv {
    type Error = Error;

    fn key_length() -> usize {
        LibAes256GcmSiv::key_size()
    }

    fn iv_length() -> usize {
        12 // 96-bit nonce
    }

    fn encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let key = GenericArray::from_slice(key);
        let nonce = GenericArray::from_slice(iv);
        let mut cipher = LibAes256GcmSiv::new(key);
        Ok(cipher.encrypt(&nonce, data)?)
    }

    fn onetime_encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Self::encrypt(key, &vec![0; Self::iv_length()], data)
    }

    fn decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let key = GenericArray::from_slice(key);
        let nonce = GenericArray::from_slice(iv);
        let mut cipher = LibAes256GcmSiv::new(key);
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
    fn aes128gcm_works() -> Result<(), aes_gcm_siv::Error> {
        let mut key = vec![0; Aes128GcmSiv::key_length()];
        thread_rng().fill_bytes(&mut key);

        let mut iv = vec![0; Aes128GcmSiv::iv_length()];
        thread_rng().fill_bytes(&mut iv);

        let pt = b"this is a super secret message";
        let ct = Aes128GcmSiv::encrypt(&key, &iv, pt)?;
        let xt = Aes128GcmSiv::decrypt(&key, &iv, &ct)?;

        assert_eq!(&pt[..], &xt[..]);

        Ok(())
    }

    #[test]
    fn aes256gcm_works() -> Result<(), aes_gcm_siv::Error> {
        let mut key = vec![0; Aes256GcmSiv::key_length()];
        thread_rng().fill_bytes(&mut key);

        let mut iv = vec![0; Aes256GcmSiv::iv_length()];
        thread_rng().fill_bytes(&mut iv);

        let pt = b"this is a super secret message";
        let ct = Aes256GcmSiv::encrypt(&key, &iv, pt)?;
        let xt = Aes256GcmSiv::decrypt(&key, &iv, &ct)?;

        assert_eq!(&pt[..], &xt[..]);

        Ok(())
    }
}
