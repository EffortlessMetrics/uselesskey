use clap::ValueEnum;

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum Kind {
    Rsa,
    Ecdsa,
    Ed25519,
    Hmac,
    Token,
    X509,
    Jwk,
    Jwks,
}

impl Kind {
    pub(crate) const fn manifest_name(self) -> &'static str {
        match self {
            Self::Rsa => "rsa",
            Self::Ecdsa => "ecdsa",
            Self::Ed25519 => "ed25519",
            Self::Hmac => "hmac",
            Self::Token => "token",
            Self::X509 => "x509",
            Self::Jwk => "jwk",
            Self::Jwks => "jwks",
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum Format {
    Pem,
    Der,
    Jwk,
    Jwks,
    #[value(name = "json-manifest")]
    JsonManifest,
    #[value(name = "bundle-dir")]
    BundleDir,
}

impl Format {
    pub(crate) const fn manifest_name(self) -> &'static str {
        match self {
            Self::Pem => "pem",
            Self::Der => "der",
            Self::Jwk => "jwk",
            Self::Jwks => "jwks",
            Self::JsonManifest => "json-manifest",
            Self::BundleDir => "bundle-dir",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum BundleProfile {
    ScannerSafe,
    Oidc,
    Tls,
    Webhook,
    Runtime,
}

impl BundleProfile {
    pub(crate) const fn manifest_name(self) -> &'static str {
        match self {
            Self::ScannerSafe => "scanner-safe",
            Self::Oidc => "oidc",
            Self::Tls => "tls",
            Self::Webhook => "webhook",
            Self::Runtime => "runtime",
        }
    }

    pub(crate) const fn output_dir_hint(self) -> &'static str {
        match self {
            Self::ScannerSafe => "target/uselesskey-bundle",
            Self::Oidc => "target/uselesskey-oidc",
            Self::Tls => "target/uselesskey-tls",
            Self::Webhook => "target/uselesskey-webhook",
            Self::Runtime => "target/uselesskey-runtime",
        }
    }
}

pub(crate) const DISCOVERABLE_PROFILES: [BundleProfile; 5] = [
    BundleProfile::ScannerSafe,
    BundleProfile::Tls,
    BundleProfile::Oidc,
    BundleProfile::Webhook,
    BundleProfile::Runtime,
];
