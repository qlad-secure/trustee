// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

pub mod plugin_manager;

pub mod implementations;
pub use implementations::*;

pub use plugin_manager::{PluginManager, PluginsConfig};

pub mod resource_storage;

// Re-export the plugins
pub use self::implementations::mlkem::{MLKEMBackend, MLKEMConfig};
#[cfg(feature = "pkcs11")]
pub use self::implementations::pkcs11::{Pkcs11Backend, Pkcs11Config};

use anyhow::Result;
use async_trait::async_trait;
use actix_web::http::Method;

#[async_trait]
pub trait Plugin: Send + Sync {
    async fn validate_auth(&self, body: &[u8], query: &str, path: &str, method: &Method) -> Result<bool>;
    async fn handle(&self, body: &[u8], query: &str, path: &str, method: &Method) -> Result<Vec<u8>>;
    async fn encrypted(&self, body: &[u8], query: &str, path: &str, method: &Method) -> Result<bool>;
}
