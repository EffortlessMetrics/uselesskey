use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct Receipt {
    pub timestamp: u64,
    pub steps: Vec<StepReceipt>,
    pub feature_matrix: Vec<FeatureMatrixEntry>,
    pub bdd_counts: BTreeMap<String, usize>,
}

#[derive(Debug, Serialize)]
pub struct StepReceipt {
    pub name: String,
    pub status: String,
    pub duration_ms: u64,
    pub details: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct FeatureMatrixEntry {
    pub features: String,
    pub status: String,
}

pub struct Runner {
    receipt: Receipt,
    path: PathBuf,
}

impl Runner {
    pub fn new(path: impl AsRef<Path>) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        Self {
            receipt: Receipt {
                timestamp: now,
                steps: Vec::new(),
                feature_matrix: Vec::new(),
                bdd_counts: BTreeMap::new(),
            },
            path: path.as_ref().to_path_buf(),
        }
    }

    pub fn step<F>(&mut self, name: &str, details: Option<String>, f: F) -> Result<()>
    where
        F: FnOnce() -> Result<()>,
    {
        let start = Instant::now();
        match f() {
            Ok(()) => {
                self.receipt.steps.push(StepReceipt {
                    name: name.to_string(),
                    status: "ok".to_string(),
                    duration_ms: start.elapsed().as_millis() as u64,
                    details,
                });
                Ok(())
            }
            Err(err) => {
                let mut detail = details.unwrap_or_default();
                if !detail.is_empty() {
                    detail.push_str("; ");
                }
                detail.push_str(&err.to_string());

                self.receipt.steps.push(StepReceipt {
                    name: name.to_string(),
                    status: "failed".to_string(),
                    duration_ms: start.elapsed().as_millis() as u64,
                    details: Some(detail),
                });
                Err(err)
            }
        }
    }

    pub fn skip(&mut self, name: &str, details: Option<String>) {
        self.receipt.steps.push(StepReceipt {
            name: name.to_string(),
            status: "skipped".to_string(),
            duration_ms: 0,
            details,
        });
    }

    pub fn add_feature_matrix(&mut self, features: &str, status: &str) {
        self.receipt.feature_matrix.push(FeatureMatrixEntry {
            features: features.to_string(),
            status: status.to_string(),
        });
    }

    pub fn set_bdd_counts(&mut self, counts: BTreeMap<String, usize>) {
        self.receipt.bdd_counts = counts;
    }

    pub fn write(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create receipt dir {:?}", parent))?;
        }
        let json = serde_json::to_string_pretty(&self.receipt)
            .context("failed to serialize receipt")?;
        fs::write(&self.path, json).context("failed to write receipt")?;
        Ok(())
    }
}
