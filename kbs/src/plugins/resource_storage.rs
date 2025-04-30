use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[async_trait]
pub trait ResourceStorageInterface: Send + Sync {
    async fn store(&self, key: String, value: Value) -> Result<()>;
    async fn get(&self, key: String) -> Result<Option<Value>>;
    async fn delete(&self, key: String) -> Result<()>;
    async fn list(&self) -> Result<Vec<String>>;
}

#[derive(Clone)]
pub struct ResourceStorage {
    storage: Arc<RwLock<HashMap<String, Value>>>,
}

impl ResourceStorage {
    pub fn new() -> Self {
        ResourceStorage {
            storage: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl ResourceStorageInterface for ResourceStorage {
    async fn store(&self, key: String, value: Value) -> Result<()> {
        let mut storage = self.storage.write().await;
        storage.insert(key, value);
        Ok(())
    }

    async fn get(&self, key: String) -> Result<Option<Value>> {
        let storage = self.storage.read().await;
        Ok(storage.get(&key).cloned())
    }

    async fn delete(&self, key: String) -> Result<()> {
        let mut storage = self.storage.write().await;
        storage.remove(&key);
        Ok(())
    }

    async fn list(&self) -> Result<Vec<String>> {
        let storage = self.storage.read().await;
        Ok(storage.keys().cloned().collect())
    }
}