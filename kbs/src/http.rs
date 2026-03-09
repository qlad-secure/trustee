// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use rustls::ServerConfig;
use rustls_pemfile::{certs, private_key};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use crate::config::HttpServerConfig;

/// Build a rustls ServerConfig with aws-lc-rs provider for pqtls support.
pub fn tls_config(config: &HttpServerConfig) -> Result<ServerConfig> {
    let cert_file = config
        .certificate
        .as_ref()
        .ok_or_else(|| anyhow!("Missing certificate"))?;

    let key_file = config
        .private_key
        .as_ref()
        .ok_or_else(|| anyhow!("Missing private key"))?;

    let cert_chain = certs(&mut BufReader::new(File::open(cert_file)?))
        .collect::<Result<Vec<_>, _>>()?;

    let key = private_key(&mut BufReader::new(File::open(key_file)?))?
        .ok_or_else(|| anyhow!("No private key found in {:?}", key_file))?;

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());

    let server_config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;

    Ok(server_config)
}
