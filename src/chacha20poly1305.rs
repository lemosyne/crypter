use crate::Crypter;
use chacha20poly1305::{
    aead::AeadMut, ChaCha20Poly1305 as LibChaCha20Poly1305, Error, KeyInit, KeySizeUser,
    XChaCha20Poly1305 as LibXChaCha20Poly1305,
};
use generic_array::GenericArray;

pub struct ChaCha20Poly1305;

impl Crypter for ChaCha20Poly1305 {
    type Error = Error;

    fn key_length() -> usize {
        LibChaCha20Poly1305::key_size()
    }

    fn iv_length() -> usize {
        12 // 96-bit nonce
    }

    fn encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let key = GenericArray::from_slice(key);
        let nonce = GenericArray::from_slice(iv);
        let mut cipher = LibChaCha20Poly1305::new(key);
        Ok(cipher.encrypt(&nonce, data)?)
    }

    fn onetime_encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Self::encrypt(key, &vec![0; Self::iv_length()], data)
    }

    fn decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let key = GenericArray::from_slice(key);
        let nonce = GenericArray::from_slice(iv);
        let mut cipher = LibChaCha20Poly1305::new(key);
        Ok(cipher.decrypt(&nonce, data)?)
    }

    fn onetime_decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Self::decrypt(key, &vec![0; Self::iv_length()], data)
    }
}

pub struct XChaCha20Poly1305;

impl Crypter for XChaCha20Poly1305 {
    type Error = Error;

    fn key_length() -> usize {
        LibChaCha20Poly1305::key_size()
    }

    fn iv_length() -> usize {
        24 // 192-bit nonce
    }

    fn encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let key = GenericArray::from_slice(key);
        let nonce = GenericArray::from_slice(iv);
        let mut cipher = LibXChaCha20Poly1305::new(key);
        Ok(cipher.encrypt(&nonce, data)?)
    }

    fn onetime_encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Self::encrypt(key, &vec![0; Self::iv_length()], data)
    }

    fn decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let key = GenericArray::from_slice(key);
        let nonce = GenericArray::from_slice(iv);
        let mut cipher = LibXChaCha20Poly1305::new(key);
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
    fn chacha20poly1305_works() -> Result<(), chacha20poly1305::Error> {
        let mut key = vec![0; ChaCha20Poly1305::key_length()];
        thread_rng().fill_bytes(&mut key);

        let mut iv = vec![0; ChaCha20Poly1305::iv_length()];
        thread_rng().fill_bytes(&mut iv);

        let pt = b"this is a super secret message";
        let ct = ChaCha20Poly1305::encrypt(&key, &iv, pt)?;
        let xt = ChaCha20Poly1305::decrypt(&key, &iv, &ct)?;

        assert_eq!(&pt[..], &xt[..]);

        Ok(())
    }

    #[test]
    fn xchacha20poly1305_works() -> Result<(), chacha20poly1305::Error> {
        let mut key = vec![0; XChaCha20Poly1305::key_length()];
        thread_rng().fill_bytes(&mut key);

        let mut iv = vec![0; XChaCha20Poly1305::iv_length()];
        thread_rng().fill_bytes(&mut iv);

        let pt = b"this is a super secret message";
        let ct = XChaCha20Poly1305::encrypt(&key, &iv, pt)?;
        let xt = XChaCha20Poly1305::decrypt(&key, &iv, &ct)?;

        assert_eq!(&pt[..], &xt[..]);

        Ok(())
    }
}
