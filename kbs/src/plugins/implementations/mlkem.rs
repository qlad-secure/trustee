use actix_web::http::Method;
use anyhow::anyhow;
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
// use crypto::mlkem::mlkem_decrypt;
use hybrid_array::typenum::U32;
use hybrid_array::Array;
use ml_kem::kem::EncapsulationKey;
use ml_kem::kem::Kem as MlKem;
use ml_kem::kem::{Decapsulate, DecapsulationKey};
use ml_kem::EncodedSizeUser;
use ml_kem::KemCore;
use ml_kem::MlKem768Params;
use rand_chacha::ChaCha8Rng;
use rand_core::{RngCore, SeedableRng};
use serde::Deserialize;
use std::str;
use std::sync::Arc;

use super::super::plugin_manager::ClientPlugin;

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct MLKEMConfig {
    #[serde(default)]
    pub r#type: Option<String>,
}

pub struct MLKEMParams {
    pub cfg: MLKEMConfig,
    pub resource_client: Arc<dyn ClientPlugin>,
}

pub struct MLKEMBackend {
    resource_client: Arc<dyn ClientPlugin>,
}

impl TryFrom<MLKEMParams> for MLKEMBackend {
    type Error = anyhow::Error;

    fn try_from(params: MLKEMParams) -> anyhow::Result<Self> {
        Ok(Self {
            resource_client: params.resource_client,
        })
    }
}

#[async_trait::async_trait]
impl ClientPlugin for MLKEMBackend {
    async fn handle(
        &self,
        body: &[u8],
        query: &str,
        path: &str,
        method: &Method,
    ) -> Result<Vec<u8>> {
        println!(
            "[DEBUG] MLKEM plugin handling request: path={}, method={}",
            path, method
        );

        let desc = path
            .strip_prefix('/')
            .context("accessed path is illegal, should start with '/'")?;

        let (action, params) = match desc.split_once('/') {
            Some((a, p)) => (a, p),
            None => (desc, ""), // Allow endpoints without params
        };

        match action {
            "pub-key" => {
                let resource_path = format!("/{}", params);
                let sk = self
                    .resource_client
                    .handle(body, query, &resource_path, method)
                    .await?;
                let pk = Self::get_pk_from_sk(&sk).context("get pk from sk failed")?;

                Ok(pk)
            }
            "generate" => {
                let (pk, sk) = Self::generate_key().context("generate key failed")?;
                let resource_path = format!("/{}", params);
                self.resource_client
                    .handle(&sk, query, &resource_path, method)
                    .await?;

                Ok(pk)
            }
            "decapsulate" => {
                let resource_path = format!("/{}", params);
                let sk = self
                    .resource_client
                    .handle(body, query, &resource_path, &Method::GET)
                    .await?;

                // Parse query string to get encapsulated_ss
                let params = serde_qs::from_str::<std::collections::HashMap<String, String>>(query)
                    .context("Failed to parse query string")?;
                let encapsulated_ss = params
                    .get("encapsulated_ss")
                    .context("Missing 'encapsulated_ss' in query")?;

                log::debug!("Decapsulating with encapsulated_ss: {}", encapsulated_ss);

                // Decode base64
                let encapsulated_ss_bytes = base64::engine::general_purpose::URL_SAFE
                    .decode(encapsulated_ss)
                    .context("Failed to decode encapsulated_ss")?;

                let unwrapped = Self::mlkem_decrypt(&sk, encapsulated_ss_bytes)
                    .context("generate key failed")?;

                Ok(unwrapped)
            }
            _ => bail!("invalid path: {}", action),
        }
    }

    async fn validate_auth(
        &self,
        _body: &[u8],
        _query: &str,
        _path: &str,
        method: &Method,
    ) -> Result<bool> {
        if method.as_str() == "POST" {
            return Ok(true);
        }

        Ok(false)
    }

    async fn encrypted(
        &self,
        _body: &[u8],
        _query: &str,
        _path: &str,
        _method: &Method,
    ) -> Result<bool> {
        Ok(true)
    }
}

impl MLKEMBackend {
    fn get_pk_from_sk(sk_input: &[u8]) -> Result<Vec<u8>> {
        let sk_bytes = match BASE64.decode(sk_input) {
            Ok(decoded) => decoded,
            Err(_e) => sk_input.to_vec(),
        };

        let mut seed = vec![0u8; 64];
        let bytes_to_copy = std::cmp::min(sk_bytes.len(), 64);
        seed[..bytes_to_copy].copy_from_slice(&sk_bytes[..bytes_to_copy]);

        let (_, ek) = Self::init_from_seed(&seed)?;
        let pk_bytes = ek.as_bytes().to_vec();

        Ok(BASE64.encode(&pk_bytes).into_bytes())
    }

    pub fn from_secret_key(
        sk_input: &str,
    ) -> Result<(
        DecapsulationKey<MlKem768Params>,
        EncapsulationKey<MlKem768Params>,
    )> {
        let sk_bytes = match BASE64.decode(sk_input) {
            Ok(decoded) => decoded,
            Err(_) => sk_input.as_bytes().to_vec(),
        };

        let mut seed = vec![0u8; 64];
        let bytes_to_copy = std::cmp::min(sk_bytes.len(), 64);
        seed[..bytes_to_copy].copy_from_slice(&sk_bytes[..bytes_to_copy]);

        Self::init_from_seed(&seed)
    }

    fn init_from_seed(
        seed: &[u8],
    ) -> Result<(
        DecapsulationKey<MlKem768Params>,
        EncapsulationKey<MlKem768Params>,
    )> {
        if seed.len() != 64 {
            bail!("Seed must be exactly 64 bytes (32+32 for d and z)");
        }
        let (d, z) = seed.split_at(32);
        let mut d_bytes = [0u8; 32];
        d_bytes.copy_from_slice(d);
        let mut z_bytes = [0u8; 32];
        z_bytes.copy_from_slice(z);

        let (dk, ek) = MlKem::<MlKem768Params>::generate_deterministic(
            &Array::from(d_bytes),
            &Array::from(z_bytes),
        );
        Ok((dk, ek))
    }

    fn generate_key() -> Result<(Vec<u8>, Vec<u8>)> {
        let mut rng = ChaCha8Rng::from_rng(rand::thread_rng())?;

        let mut d: Array<u8, U32> = Array::default();
        rng.fill_bytes(&mut d);
        let mut z: Array<u8, U32> = Array::default();
        rng.fill_bytes(&mut z);

        let mut seed_bytes = [0u8; 64];
        seed_bytes[..32].copy_from_slice(d.as_slice());
        seed_bytes[32..].copy_from_slice(z.as_slice());

        let (_dk, ek) = MlKem::<MlKem768Params>::generate_deterministic(&d, &z);

        let pk_bytes = ek.as_bytes().to_vec();

        Ok((
            BASE64.encode(&pk_bytes).into_bytes(),
            BASE64.encode(&seed_bytes).into_bytes(),
        ))
    }

    /// Decrypt data using a shared secret derived from the decapsulation key.
    pub fn mlkem_decrypt(sk_input: &[u8], encapsulated_ss: Vec<u8>) -> Result<Vec<u8>> {
        let (dk, _ek) = Self::from_secret_key(str::from_utf8(sk_input)?)?;
        let ct_array: [u8; 1088] = encapsulated_ss
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("Invalid CT length"))?;
        let shared_secret = Decapsulate::decapsulate(&dk, &Array::from(ct_array))?;
        Ok(shared_secret.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;

    use crate::plugins::implementations::mlkem::MLKEMBackend;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use ml_kem::EncodedSizeUser;

    #[test]
    fn test_mlkem_key_compatibility() {
        let (pk, seed) = MLKEMBackend::generate_key().expect("failed to generate key");

        let pk_64 = String::from_utf8(pk).expect("invalid pk value");
        let seed_str = String::from_utf8(seed).expect("invalid seed value");

        let (_, ek) = MLKEMBackend::from_secret_key(seed_str.as_str())
            .expect("failed to initialize from seed");

        let pk_from_seed = BASE64.encode(ek.as_bytes().to_vec());

        assert_eq!(pk_64, pk_from_seed);
    }
}
