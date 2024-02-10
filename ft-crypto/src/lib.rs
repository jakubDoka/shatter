#![feature(slice_take)]

use std::collections::HashMap;

use base64::engine::GeneralPurpose;
use base64::Engine;
use crypto::{SharedSecret, TransmutationCircle};
use rand_core::{CryptoRng, OsRng, RngCore};
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

const BASE64: GeneralPurpose = base64::engine::general_purpose::STANDARD;

#[wasm_bindgen]
pub fn hash_password(password: &str, salt: &str) -> String {
    let mut salt_bytes = [0xffu8; 32];
    salt_bytes[..salt.len().min(32)].copy_from_slice(salt.as_bytes());
    let mut to_hash = [0u8; 32];
    argon2::Argon2::default()
        .hash_password_into(password.as_bytes(), &salt_bytes, &mut to_hash)
        .expect("us to not fuck up");
    let hash = crypto::hash::from_slice(&to_hash);
    BASE64.encode(hash)
}

#[wasm_bindgen]
#[derive(Default)]
pub struct Vault {
    chat_keys: HashMap<String, SecretKey>,
}

#[wasm_bindgen]
impl Vault {
    #[wasm_bindgen(constructor)]
    pub fn new(serialized: &[u8]) -> Self {
        Self::try_deserialize(serialized).unwrap_or_default()
    }

    pub fn get_chat_key(&self, name: &str) -> Option<SecretKey> {
        self.chat_keys.get(name).cloned()
    }

    pub fn save_chat_key(&mut self, name: String, secret: SecretKey) {
        self.chat_keys.insert(name, secret);
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.serialize()
    }
}

impl Vault {
    const VERSION: u32 = 0;

    fn try_deserialize(mut buffer: &[u8]) -> Option<Self> {
        _ = u32::from_le_bytes(buffer.take(..4)?.try_into().unwrap());

        let chat_keys_len = u32::from_le_bytes(buffer.take(..4)?.try_into().unwrap());
        let mut keys = HashMap::with_capacity(chat_keys_len as _);
        for _ in 0..chat_keys_len {
            let len = *buffer.take_first()?;
            let str = std::str::from_utf8(buffer.take(..len as usize)?).ok()?;
            let key: SharedSecret = buffer.take(..32)?.try_into().unwrap();
            keys.insert(str.to_owned(), SecretKey { inner: key });
        }

        Some(Self { chat_keys: keys })
    }

    fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(4 + 4 + self.chat_keys.len() * (1 + 32 + 16));
        buffer.extend_from_slice(&Self::VERSION.to_le_bytes());
        buffer.extend_from_slice(&(self.chat_keys.len() as u32).to_le_bytes());
        for (name, key) in &self.chat_keys {
            buffer.push(name.len() as u8);
            buffer.extend_from_slice(name.as_bytes());
            buffer.extend_from_slice(key.inner.as_slice());
        }
        buffer
    }
}

#[wasm_bindgen]
pub struct UserSecrets {
    enc: EncKeypair,
    master_secret: SecretKey,
}

#[wasm_bindgen]
impl UserSecrets {
    #[wasm_bindgen(constructor)]
    pub fn new(password: &str, salt: &str) -> Self {
        let mut salt_bytes = [0xffu8; 32];
        salt_bytes[..salt.len().min(32)].copy_from_slice(salt.as_bytes());
        let mut entropy = [0u8; 32 + 64 + 32];
        argon2::Argon2::default()
            .hash_password_into(password.as_bytes(), &salt_bytes, &mut entropy)
            .expect("us to not fuck up");

        let mut rng = Rng { bytes: &entropy };
        let enc = crypto::enc::Keypair::new(&mut rng);
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);

        Self {
            enc: EncKeypair { inner: enc },
            master_secret: SecretKey { inner: secret },
        }
    }

    #[wasm_bindgen(getter)]
    pub fn enc(&self) -> EncKeypair {
        self.enc.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn master_secret(&self) -> SecretKey {
        self.master_secret
    }
}

struct Rng<'a> {
    bytes: &'a [u8],
}

impl<'a> RngCore for Rng<'a> {
    fn next_u32(&mut self) -> u32 {
        todo!()
    }

    fn next_u64(&mut self) -> u64 {
        todo!()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let subslice = self
            .bytes
            .take(..dest.len())
            .expect("us to have enough entropy");
        dest.copy_from_slice(subslice);
    }

    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), rand_core::Error> {
        todo!()
    }
}

impl CryptoRng for Rng<'_> {}

#[wasm_bindgen]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecretKey {
    inner: crypto::SharedSecret,
}

#[wasm_bindgen]
impl SecretKey {
    #[wasm_bindgen(constructor)]
    pub fn new() -> SecretKey {
        SecretKey {
            inner: crypto::new_secret(OsRng),
        }
    }

    pub fn encrypt(&self, mut message: Vec<u8>) -> Vec<u8> {
        let peyload = crypto::encrypt(&mut message, self.inner, OsRng);
        message.extend_from_slice(&peyload);
        message
    }

    /**
     * @throw if decrypting failed
     */
    pub fn decrypt(&self, mut message: Vec<u8>) -> Result<Vec<u8>, JsValue> {
        let len = crypto::decrypt(&mut message, self.inner)
            .ok_or("Decrypting failed.")?
            .len();
        message.truncate(len);
        Ok(message)
    }

    pub fn from_base64(base64: &str) -> Result<SecretKey, JsValue> {
        let bytes = BASE64.decode(base64.as_bytes());
        let bytes = bytes.map_err(err_as_jsvalue)?;
        let inner = crypto::SharedSecret::try_from(bytes)
            .ok()
            .ok_or("SharedSecret has invalid size")?;
        Ok(SecretKey { inner })
    }

    pub fn as_base64(&self) -> String {
        BASE64.encode(self.inner)
    }
}

impl Default for SecretKey {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct EncKeypair {
    inner: crypto::enc::Keypair,
}

#[wasm_bindgen]
impl EncKeypair {
    #[wasm_bindgen(constructor)]
    pub fn new() -> EncKeypair {
        EncKeypair {
            inner: crypto::enc::Keypair::new(OsRng),
        }
    }

    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> EncPublicKey {
        EncPublicKey {
            inner: self.inner.public_key(),
        }
    }

    pub fn as_base64(&self) -> String {
        as_base64(&self.inner)
    }

    pub fn encapsulate(&self, public_key: EncPublicKey, secret: SecretKey) -> String {
        let inner = self
            .inner
            .encapsulate_choosen(&public_key.inner, secret.inner, OsRng);
        as_base64(&inner)
    }

    /// @throw if base64 is not valid or string has invalid length or decapsulation failed
    pub fn decapsulate(&self, ciphertext: &str) -> Result<SecretKey, JsValue> {
        self.inner
            .decapsulate_choosen(&from_base64(ciphertext)?)
            .map(|inner| SecretKey { inner })
            .map_err(err_as_jsvalue)
    }

    /// @throw if base64 is not valid or string has invalid length
    pub fn from_base64(base64: &str) -> Result<EncKeypair, JsValue> {
        Ok(EncKeypair {
            inner: from_base64::<crypto::enc::Keypair>(base64)?.clone(),
        })
    }
}

impl Default for EncKeypair {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
pub struct EncPublicKey {
    inner: crypto::enc::PublicKey,
}

#[wasm_bindgen]
impl EncPublicKey {
    pub fn as_base64(&self) -> String {
        as_base64(&self.inner)
    }

    /// @throw if base64 is not valid of string has invalid length
    pub fn from_base64(base64: &str) -> Result<EncPublicKey, JsValue> {
        Ok(EncPublicKey {
            inner: from_base64(base64)?,
        })
    }

    pub fn hash(&self) -> String {
        let hash = crypto::hash::from_slice(self.inner.as_bytes());
        BASE64.encode(hash)
    }

    /// @throw if base64 is not valid or string has invalid length
    pub fn verify_with_hash(&self, base64_hash: &str) -> Result<bool, JsValue> {
        let mut hash = [0u8; 33]; // because of a bug in base64 engine
        let len = BASE64
            .decode_slice(base64_hash, &mut hash)
            .map_err(err_as_jsvalue)?;
        if len != 32 {
            return Err("Invalid hash length".into());
        }
        Ok(crypto::hash::from_slice(self.inner.as_bytes()) == hash[..32])
    }
}

fn as_base64<T: TransmutationCircle>(bytes: &T) -> String {
    let bytes = bytes.as_bytes();
    BASE64.encode(bytes)
}

fn from_base64<T: TransmutationCircle + Clone>(base64: &str) -> Result<T, JsValue> {
    let bytes = BASE64.decode(base64.as_bytes());
    let bytes = bytes.map_err(err_as_jsvalue)?;
    let inner = T::try_from_slice(&bytes).ok_or("Invalid size")?;
    Ok(inner.clone())
}

fn err_as_jsvalue<E: std::fmt::Debug>(e: E) -> JsValue {
    JsValue::from_str(&format!("{:?}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_user_secrets() {
        let password = "password";
        let salt = "salt";
        _ = UserSecrets::new(password, salt);
    }
}
