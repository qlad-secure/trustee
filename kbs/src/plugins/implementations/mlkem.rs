use crate::plugins::implementations::resource::{ResourceDesc, StorageBackend};
use actix_web::http::Method;
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::{PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use ml_kem::kem::{Kem as MlKem};
use ml_kem::MlKem768Params;
use ml_kem::KemCore;
use ml_kem::EncodedSizeUser;
use rand_chacha::ChaCha8Rng;
use rand_core::{RngCore, SeedableRng};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

use super::super::plugin_manager::ClientPlugin;

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct MLKEMConfig {
    // Storage path for MLKEM keys can be added if needed
    #[serde(default)]
    pub storage_path: Option<String>,
    
    // Type field to match ResourceStorage config
    #[serde(default)]
    pub r#type: Option<String>,
}

pub struct MLKEMBackend {
    storage: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    storage_path: Option<PathBuf>,
}

impl TryFrom<MLKEMConfig> for MLKEMBackend {
    type Error = anyhow::Error;

    fn try_from(config: MLKEMConfig) -> anyhow::Result<Self> {
        // Create the storage directory if it doesn't exist
        if let Some(path) = &config.storage_path {
            let path_buf = PathBuf::from(path);
            if !path_buf.exists() {
                fs::create_dir_all(&path_buf)?;
            }
        }

        Ok(Self {
            storage: Arc::new(RwLock::new(HashMap::new())),
            storage_path: config.storage_path.map(PathBuf::from),
        })
    }
}

#[async_trait::async_trait]
impl ClientPlugin for MLKEMBackend {
    async fn handle(
        &self,
        body: &[u8],
        _query: &str,
        path: &str,
        method: &Method,
    ) -> Result<Vec<u8>> {
        println!("[DEBUG] MLKEM plugin handling request: path={}, method={}", path, method);
        
        let desc = path
            .strip_prefix('/')
            .context("accessed path is illegal, should start with '/'")?;

        let (action, params) = match desc.split_once('/') {
            Some((a, p)) => (a, p),
            None => (desc, ""), // Allow endpoints without params
        };

        match action {
            "resource" => self.resource_handle(params, body, method).await,
            "generate" => self.generate_key(params).await,
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
            Method::GET => Ok(true),  // Use admin auth for GET requests too
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

#[async_trait::async_trait]
impl StorageBackend for MLKEMBackend {
    async fn read_secret_resource(&self, resource_desc: ResourceDesc) -> Result<Vec<u8>> {
        println!("[DEBUG] Reading MLKEM key: {}", resource_desc.to_string());
        
        // First check in-memory storage
        let storage = self.storage.read().await;
        if let Some(data) = storage.get(&resource_desc.to_string()) {
            return Ok(data.clone());
        }
        
        // Then check filesystem storage if configured
        if let Some(storage_path) = &self.storage_path {
            let key_path = storage_path.join(resource_desc.to_string());
            if key_path.exists() {
                return Ok(fs::read(key_path)?);
            }
        }
        
        bail!("Key not found: {}", resource_desc.to_string())
    }

    async fn write_secret_resource(&self, resource_desc: ResourceDesc, data: &[u8]) -> Result<()> {
        println!("[DEBUG] Writing MLKEM key: {}", resource_desc.to_string());
        
        // Store in memory
        let mut storage = self.storage.write().await;
        storage.insert(resource_desc.to_string(), data.to_vec());
        
        // Also store on disk if configured
        if let Some(storage_path) = &self.storage_path {
            let key_path = storage_path.join(resource_desc.to_string());
            // Create parent directories if they don't exist
            if let Some(parent) = key_path.parent() {
                if !parent.exists() {
                    fs::create_dir_all(parent)?;
                }
            }
            fs::write(key_path, data)?;
        }
        
        Ok(())
    }
}

impl MLKEMBackend {
    async fn resource_handle(&self, tag: &str, body: &[u8], method: &Method) -> Result<Vec<u8>> {
        println!("[DEBUG] MLKEM resource handle: tag={}, method={}", tag, method);
        
        let tag = ResourceDesc::try_from(tag).context("invalid path")?;

        match *method {
            Method::GET => self.read_secret_resource(tag).await,
            Method::POST => {
                self.write_secret_resource(tag, body).await?;
                Ok(vec![])
            }
            _ => bail!("Illegal HTTP method. Only supports `GET` and `POST`"),
        }
    }
    
    async fn generate_key(&self, key_id: &str) -> Result<Vec<u8>> {
        println!("[DEBUG] Generating MLKEM key: {}", key_id);
        
        // Generate a new MLKEM key pair
        let mut rng = ChaCha8Rng::from_rng(rand::thread_rng())?;
        let (dk, ek) = MlKem::<MlKem768Params>::generate(&mut rng);
        
        // Extract the private key bytes (we're using a deterministic seed approach)
        // Create a random 64-byte seed (32 bytes for d, 32 bytes for z)
        let mut seed = vec![0u8; 64];
        rand::thread_rng().fill_bytes(&mut seed);
        
        // Store the seed as the private key
        let sk_tag = ResourceDesc::try_from(&format!("{}/sk", key_id)[..])?;
        self.write_secret_resource(sk_tag, &seed).await?;
        
        // Also store the public key separately
        let pk_bytes = ek.as_bytes().to_vec();
        let pk_tag = ResourceDesc::try_from(&format!("{}/pk", key_id)[..])?;
        self.write_secret_resource(pk_tag, &pk_bytes).await?;
        
        // Return base64-encoded public key
        Ok(BASE64.encode(&pk_bytes).into_bytes())
    }
}