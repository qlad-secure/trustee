use super::resource::ResourceStorage;
use crate::plugins::implementations::resource::{ResourceDesc, StorageBackend};
use actix_web::http::Method;
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use hybrid_array::typenum::Unsigned;
use hybrid_array::typenum::U32;
use hybrid_array::Array;
use ml_kem::kem::DecapsulationKey;
use ml_kem::kem::EncapsulationKey;
use ml_kem::kem::Kem as MlKem;
use ml_kem::EncodedSizeUser;
use ml_kem::KemCore;
use ml_kem::MlKem768Params;
use rand_chacha::ChaCha8Rng;
use rand_core::{RngCore, SeedableRng};
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock; // Added for U32::USIZE

use super::super::plugin_manager::ClientPlugin;

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct MLKEMConfig {
    // Type field to match ResourceStorage config
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
                let pk = self.get_pk_from_sk(&sk).context("get pk from sk failed")?;

                Ok(pk)
            }
            "generate" => {
                let (pk, sk) = self.generate_key(params).context("generate key failed")?;
                let resource_path = format!("/{}", params);
                self.resource_client
                    .handle(&sk, query, &resource_path, method)
                    .await?;

                Ok(pk)
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
        match *method {
            Method::GET => Ok(true),
            // Method::GET => Ok(false),
            Method::POST => Ok(true),
            _ => bail!("invalid method"),
        }
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
    fn get_pk_from_sk(&self, sk_input: &[u8]) -> Result<Vec<u8>> {
        let sk_bytes = match base64::engine::general_purpose::STANDARD.decode(sk_input) {
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

    fn generate_key(&self, key_id: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        println!("[DEBUG] Generating MLKEM key: {}", key_id);

        let mut rng = ChaCha8Rng::from_rng(rand::thread_rng())?;
        let (_dk, ek) = MlKem::<MlKem768Params>::generate(&mut rng);

        let seed = Self::get_seed_from_dk(&_dk)?;
        let pk_bytes = ek.as_bytes().to_vec();

        Ok((
            BASE64.encode(&pk_bytes).into_bytes(),
            BASE64.encode(&seed).into_bytes(),
        ))
    }

    fn get_seed_from_dk(dk: &DecapsulationKey<MlKem768Params>) -> Result<Vec<u8>> {
        let dk_bytes_array = dk.as_bytes();
        let dk_bytes_slice: &[u8] = dk_bytes_array.as_slice();

        const EK_SIZE: usize =
            <EncapsulationKey<MlKem768Params> as EncodedSizeUser>::EncodedSize::USIZE;
        const H_SIZE: usize = <MlKem<MlKem768Params> as KemCore>::SharedKeySize::USIZE;
        const D_SIZE: usize = U32::USIZE;
        const Z_SIZE: usize = U32::USIZE;

        let d_offset = EK_SIZE + H_SIZE;
        let z_offset = d_offset + D_SIZE;

        let required_len_for_extraction = z_offset + Z_SIZE;
        if dk_bytes_slice.len() < required_len_for_extraction {
            bail!(
                "DecapsulationKey byte slice is too short for the extraction. Expected at least {} bytes to access up to offset {}, got {}.",
                required_len_for_extraction,
                required_len_for_extraction -1,
                dk_bytes_slice.len()
            );
        }

        let d_part = &dk_bytes_slice[d_offset..(d_offset + D_SIZE)];
        let z_part = &dk_bytes_slice[z_offset..(z_offset + Z_SIZE)];

        let mut seed = Vec::with_capacity(D_SIZE + Z_SIZE);
        seed.extend_from_slice(d_part);
        seed.extend_from_slice(z_part);

        Ok(seed)
    }
}
