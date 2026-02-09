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
    pub bdd_matrix: Vec<BddMatrixEntry>,
    pub bdd_counts: BTreeMap<String, usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coverage_lcov_path: Option<String>,
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

#[derive(Debug, Serialize)]
pub struct BddMatrixEntry {
    pub feature_set: String,
    pub status: String,
}

pub struct Runner {
    receipt: Receipt,
    path: PathBuf,
    start: Instant,
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
                bdd_matrix: Vec::new(),
                bdd_counts: BTreeMap::new(),
                coverage_lcov_path: None,
            },
            path: path.as_ref().to_path_buf(),
            start: Instant::now(),
        }
    }

    pub fn step<F>(&mut self, name: &str, details: Option<String>, f: F) -> Result<()>
    where
        F: FnOnce() -> Result<()>,
    {
        eprintln!("==> {name}");
        let start = Instant::now();
        match f() {
            Ok(()) => {
                let secs = start.elapsed().as_secs_f64();
                eprintln!("==> {name} [ok, {secs:.1}s]");
                self.receipt.steps.push(StepReceipt {
                    name: name.to_string(),
                    status: "ok".to_string(),
                    duration_ms: start.elapsed().as_millis() as u64,
                    details,
                });
                Ok(())
            }
            Err(err) => {
                let secs = start.elapsed().as_secs_f64();
                eprintln!("==> {name} [FAILED, {secs:.1}s]");
                eprintln!("    {err}");
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
        eprintln!("==> {name} [skipped]");
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

    pub fn add_bdd_matrix(&mut self, feature_set: &str, status: &str) {
        self.receipt.bdd_matrix.push(BddMatrixEntry {
            feature_set: feature_set.to_string(),
            status: status.to_string(),
        });
    }

    pub fn set_bdd_counts(&mut self, counts: BTreeMap<String, usize>) {
        self.receipt.bdd_counts = counts;
    }

    pub fn set_coverage_lcov_path(&mut self, path: String) {
        self.receipt.coverage_lcov_path = Some(path);
    }

    pub fn summary(&self) {
        let mut ok = 0usize;
        let mut failed = 0usize;
        let mut skipped = 0usize;
        for step in &self.receipt.steps {
            match step.status.as_str() {
                "ok" => ok += 1,
                "failed" => failed += 1,
                "skipped" => skipped += 1,
                _ => {}
            }
        }
        let total = self.start.elapsed().as_secs_f64();
        eprintln!("{ok} passed, {failed} failed, {skipped} skipped ({total:.1}s total)");
    }

    pub fn write(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create receipt dir {:?}", parent))?;
        }
        let json =
            serde_json::to_string_pretty(&self.receipt).context("failed to serialize receipt")?;
        fs::write(&self.path, json).context("failed to write receipt")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;

    #[test]
    fn runner_records_steps_and_writes_receipt() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("receipt.json");

        let mut runner = Runner::new(&path);
        runner
            .step("ok-step", Some("details".to_string()), || Ok(()))
            .expect("ok step");

        let err = runner.step("fail-step", None, || Err(anyhow!("boom")));
        assert!(err.is_err());

        runner.skip("skipped-step", Some("not needed".to_string()));
        runner.add_feature_matrix("default", "ok");

        let mut counts = BTreeMap::new();
        counts.insert("rsa.feature".to_string(), 2);
        runner.set_bdd_counts(counts);

        runner.summary();

        assert_eq!(runner.receipt.steps.len(), 3);
        assert_eq!(runner.receipt.feature_matrix.len(), 1);
        assert_eq!(runner.receipt.bdd_counts.get("rsa.feature"), Some(&2));

        runner.write().expect("write receipt");
        let json = fs::read_to_string(&path).expect("read receipt");
        assert!(json.contains("\"steps\""));
    }
}
