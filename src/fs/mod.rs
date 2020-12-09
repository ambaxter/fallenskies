mod model;
mod routes;
use anyhow::Result;
use argon2::Config;
use std::sync::Arc;

#[derive(Default)]
struct Argon2Inner {
    associated_data: Vec<u8>,
    secret: Vec<u8>,
    salt: Vec<u8>,
    config: Config<'static>,
}

#[derive(Default)]
pub struct Argon2Builder {
    inner: Argon2Inner,
}

impl Argon2Builder {
    pub fn new() -> Argon2Builder {
        Default::default()
    }

    pub fn associated_data(mut self, associated_data: Vec<u8>) -> Argon2Builder {
        self.inner.associated_data = associated_data;
        self
    }

    pub fn secret(mut self, secret: Vec<u8>) -> Argon2Builder {
        self.inner.secret = secret;
        self
    }

    pub fn salt(mut self, salt: Vec<u8>) -> Argon2Builder {
        self.inner.salt = salt;
        self
    }

    pub fn build(self) -> Argon2Config {
        Argon2Config {
            inner: Arc::new(self.inner),
        }
    }
}

#[derive(Clone)]
pub struct Argon2Config {
    inner: Arc<Argon2Inner>,
}

impl Argon2Config {
    fn config(&self) -> Config {
        let mut config = self.inner.config.clone();
        config.ad = &self.inner.associated_data;
        config.secret = &self.inner.secret;
        config
    }

    fn inner_hash_encoded(&self, password: &[u8]) -> Result<String> {
        let config = self.config();
        let encoded = argon2::hash_encoded(password, &self.inner.salt, &config)?;
        Ok(encoded)
    }

    pub fn hash_encoded<T: AsRef<[u8]>>(&self, password: T) -> Result<String> {
        self.inner_hash_encoded(password.as_ref())
    }

    fn inner_verify_encoded(&self, hash: &str, password: &[u8]) -> Result<bool> {
        let result = argon2::verify_encoded_ext(
            hash,
            password,
            &self.inner.secret,
            &self.inner.associated_data,
        )?;
        Ok(result)
    }

    pub fn verify_encoded<T: AsRef<[u8]>>(&self, hash: &str, password: T) -> Result<bool> {
        self.inner_verify_encoded(hash, password.as_ref())
    }
}

pub use model::*;
pub use routes::init;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
