// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, fmt::Display, sync::Arc};

use actix_web::http::Method;
use anyhow::{Context, Error, Result};
use serde::Deserialize;

use super::implementations::resource::{RepositoryConfig, ResourceStorage};
use super::implementations::sample::{Sample, SampleConfig};
use super::implementations::mlkem::{MLKEMBackend, MLKEMConfig};

#[cfg(feature = "nebula-ca-plugin")]
use super::implementations::nebula_ca::{NebulaCaPlugin, NebulaCaPluginConfig};

#[cfg(feature = "pkcs11")]
use super::implementations::pkcs11::{Pkcs11Backend, Pkcs11Config};

type ClientPluginInstance = Arc<dyn ClientPlugin>;

#[async_trait::async_trait]
pub trait ClientPlugin: Send + Sync {
    /// This function is the entry to a client plugin. The function
    /// marks `&self` rather than `&mut self`, because it will leave
    /// state and synchronization issues down to the concrete plugin.
    ///
    /// TODO: change body from Vec slice into Reader to apply for large
    /// body stream.
    async fn handle(
        &self,
        body: &[u8],
        query: &str,
        path: &str,
        method: &Method,
    ) -> Result<Vec<u8>>;

    /// Whether the concrete request needs to validate the admin auth.
    /// If returns `Ok(true)`, the KBS server will perform an admin auth
    /// validation before handle the request.
    async fn validate_auth(
        &self,
        body: &[u8],
        query: &str,
        path: &str,
        method: &Method,
    ) -> Result<bool>;

    /// Whether the body needs to be encrypted via TEE key pair.
    /// If returns `Ok(true)`, the KBS server will encrypt the whole body
    /// with TEE key pair and use KBS protocol's Response format.
    async fn encrypted(
        &self,
        body: &[u8],
        query: &str,
        path: &str,
        method: &Method,
    ) -> Result<bool>;
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "name")]
pub enum PluginsConfig {
    #[serde(alias = "sample")]
    Sample(SampleConfig),

    #[serde(alias = "resource")]
    ResourceStorage(RepositoryConfig),

    #[cfg(feature = "nebula-ca-plugin")]
    #[serde(alias = "nebula-ca")]
    NebulaCaPlugin(NebulaCaPluginConfig),

    #[cfg(feature = "pkcs11")]
    #[serde(alias = "pkcs11")]
    Pkcs11(Pkcs11Config),
    
    #[serde(alias = "mlkem")]
    MLKEM(MLKEMConfig),
}

impl Display for PluginsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PluginsConfig::Sample(_) => f.write_str("sample"),
            PluginsConfig::ResourceStorage(_) => f.write_str("resource"),
            #[cfg(feature = "nebula-ca-plugin")]
            PluginsConfig::NebulaCaPlugin(_) => f.write_str("nebula-ca"),
            #[cfg(feature = "pkcs11")]
            PluginsConfig::Pkcs11(_) => f.write_str("pkcs11"),
            PluginsConfig::MLKEM(_) => f.write_str("mlkem"),
        }
    }
}

impl TryInto<ClientPluginInstance> for PluginsConfig {
    type Error = Error;

    fn try_into(self) -> Result<ClientPluginInstance> {
        let plugin = match self {
            PluginsConfig::Sample(cfg) => {
                let sample_plugin =
                    Sample::try_from(cfg).context("Initialize 'Sample' plugin failed")?;
                Arc::new(sample_plugin) as _
            }
            PluginsConfig::ResourceStorage(repository_config) => {
                let resource_storage = ResourceStorage::try_from(repository_config)
                    .context("Initialize 'Resource' plugin failed")?;
                Arc::new(resource_storage) as _
            }
            #[cfg(feature = "nebula-ca-plugin")]
            PluginsConfig::NebulaCaPlugin(nebula_ca_config) => {
                let nebula_ca = NebulaCaPlugin::try_from(nebula_ca_config)
                    .context("Initialize 'nebula-ca-plugin' failed")?;
                Arc::new(nebula_ca) as _
            }
            #[cfg(feature = "pkcs11")]
            PluginsConfig::Pkcs11(pkcs11_config) => {
                let pkcs11 = Pkcs11Backend::try_from(pkcs11_config)
                    .context("Initialize 'pkcs11' plugin failed")?;
                Arc::new(pkcs11) as _
            }
            PluginsConfig::MLKEM(mlkem_config) => {
                let mlkem = MLKEMBackend::try_from(mlkem_config)
                    .context("Initialize 'mlkem' plugin failed")?;
                Arc::new(mlkem) as _
            }
        };

        Ok(plugin)
    }
}

#[derive(Deserialize, Clone, Debug, PartialEq, Default)]
pub struct PluginConfig {
    #[serde(default)]
    pub sample: Option<SampleConfig>,
    #[serde(default)]
    pub resource: Option<RepositoryConfig>,
    #[cfg(feature = "pkcs11")]
    #[serde(default)]
    pub pkcs11: Option<Pkcs11Config>,
    #[cfg(feature = "nebula-ca-plugin")]
    #[serde(default)]
    pub nebula: Option<NebulaCaPluginConfig>,
    #[serde(default)]
    pub mlkem: Option<MLKEMConfig>,
}

/// [`PluginManager`] manages different kinds of plugins.
#[derive(Clone)]
pub struct PluginManager {
    plugins: HashMap<String, ClientPluginInstance>,
}

impl TryFrom<Vec<PluginsConfig>> for PluginManager {
    type Error = Error;

    fn try_from(value: Vec<PluginsConfig>) -> Result<Self> {
        let plugins = value
            .into_iter()
            .map(|cfg| {
                let name = cfg.to_string();
                let plugin: ClientPluginInstance = cfg.try_into()?;
                Ok((name, plugin))
            })
            .collect::<Result<HashMap<String, ClientPluginInstance>>>()?;
        Ok(Self { plugins })
    }
}

impl PluginManager {
    pub fn get(&self, name: &str) -> Option<ClientPluginInstance> {
        self.plugins.get(name).cloned()
    }
}
