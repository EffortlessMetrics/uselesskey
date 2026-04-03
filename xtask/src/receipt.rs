use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Receipt {
    /// Schema version for downstream compatibility (current: 2).
    pub schema_version: u32,
    /// Unix timestamp (milliseconds).
    pub timestamp: u64,
    /// Git SHA of the commit being tested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_sha: Option<String>,
    /// Set of crates included in this run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crate_set: Option<String>,
    pub steps: Vec<StepReceipt>,
    pub feature_matrix: Vec<FeatureMatrixEntry>,
    pub bdd_matrix: Vec<BddMatrixEntry>,
    pub bdd_counts: BTreeMap<String, usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coverage_lcov_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coverage_percent: Option<f64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StepReceipt {
    pub name: String,
    pub status: String,
    pub duration_ms: u64,
    pub details: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FeatureMatrixEntry {
    pub features: String,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BddMatrixEntry {
    pub feature_set: String,
    pub status: String,
}

impl Receipt {
    /// Produce a human-readable timing breakdown of all steps.
    ///
    /// Steps are sorted longest-first. Each line shows the step name, duration,
    /// a Unicode bar chart proportional to the total time, and the percentage of
    /// total wall-clock time that step consumed.
    pub fn timing_report(&self) -> String {
        const BAR_WIDTH: usize = 10;

        // Collect (name, duration_ms) pairs and sort descending by duration.
        let mut entries: Vec<(&str, u64)> = self
            .steps
            .iter()
            .map(|s| (s.name.as_str(), s.duration_ms))
            .collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1));

        let total_ms: u64 = entries.iter().map(|(_, ms)| *ms).sum();

        // Determine the longest step name for alignment.
        let max_name_len = entries
            .iter()
            .map(|(name, _)| name.len())
            .max()
            .unwrap_or(0)
            .max(4); // at least 4 chars wide

        let mut out = String::new();
        writeln!(out, "\n--- Timing Breakdown ---").unwrap();

        for (name, ms) in &entries {
            let secs = *ms as f64 / 1000.0;
            let pct = if total_ms > 0 {
                (*ms as f64 / total_ms as f64) * 100.0
            } else {
                0.0
            };

            // Build bar: filled blocks proportional to percentage.
            let filled = if total_ms > 0 {
                ((pct / 100.0) * BAR_WIDTH as f64).round() as usize
            } else {
                0
            };
            let filled = filled.min(BAR_WIDTH);
            let empty = BAR_WIDTH - filled;

            let bar: String = "\u{2588}".repeat(filled) + &"\u{2591}".repeat(empty);

            writeln!(
                out,
                "{:<width$}  {:>6.1}s {} {:>3.0}%",
                name,
                secs,
                bar,
                pct,
                width = max_name_len,
            )
            .unwrap();
        }

        let total_secs = total_ms as f64 / 1000.0;
        writeln!(out, "{:->width$}", "", width = max_name_len + 26).unwrap();
        writeln!(
            out,
            "{:<width$}  {:>6.1}s",
            "total",
            total_secs,
            width = max_name_len,
        )
        .unwrap();

        out
    }

    /// Produce a SARIF 2.1.0 JSON string from this receipt.
    ///
    /// Failed steps become results with level `"error"`, skipped steps become
    /// results with level `"note"`. Failed feature-matrix and BDD-matrix
    /// entries are also emitted as `"error"` results.
    #[allow(dead_code)]
    pub fn to_sarif(&self) -> String {
        let mut results: Vec<serde_json::Value> = Vec::new();
        let mut rules: Vec<serde_json::Value> = Vec::new();
        let mut rule_index: BTreeMap<String, usize> = BTreeMap::new();

        // Helper: ensure a rule exists and return its index.
        let mut ensure_rule =
            |id: &str, short_desc: &str, rules: &mut Vec<serde_json::Value>| -> usize {
                if let Some(&idx) = rule_index.get(id) {
                    return idx;
                }
                let idx = rules.len();
                rules.push(serde_json::json!({
                    "id": id,
                    "shortDescription": { "text": short_desc },
                }));
                rule_index.insert(id.to_string(), idx);
                idx
            };

        // Steps: failed and skipped.
        for step in &self.steps {
            let level = match step.status.as_str() {
                "failed" => "error",
                "skipped" => "note",
                _ => continue,
            };
            let rule_id = format!("xtask/{}", step.name);
            let short_desc = format!("xtask step: {}", step.name);
            let idx = ensure_rule(&rule_id, &short_desc, &mut rules);

            let fallback = format!("Step '{}' {}", step.name, step.status);
            let message_text = step.details.as_deref().unwrap_or(&fallback);
            results.push(serde_json::json!({
                "ruleId": rule_id,
                "ruleIndex": idx,
                "level": level,
                "message": { "text": message_text },
            }));
        }

        // Feature-matrix failures.
        for entry in &self.feature_matrix {
            if entry.status != "failed" {
                continue;
            }
            let rule_id = format!("xtask/feature-matrix/{}", entry.features);
            let short_desc = format!("feature-matrix: {}", entry.features);
            let idx = ensure_rule(&rule_id, &short_desc, &mut rules);
            results.push(serde_json::json!({
                "ruleId": rule_id,
                "ruleIndex": idx,
                "level": "error",
                "message": { "text": format!("Feature-matrix check failed for '{}'", entry.features) },
            }));
        }

        // BDD-matrix failures.
        for entry in &self.bdd_matrix {
            if entry.status != "failed" {
                continue;
            }
            let rule_id = format!("xtask/bdd-matrix/{}", entry.feature_set);
            let short_desc = format!("bdd-matrix: {}", entry.feature_set);
            let idx = ensure_rule(&rule_id, &short_desc, &mut rules);
            results.push(serde_json::json!({
                "ruleId": rule_id,
                "ruleIndex": idx,
                "level": "error",
                "message": { "text": format!("BDD-matrix check failed for '{}'", entry.feature_set) },
            }));
        }

        let sarif = serde_json::json!({
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "uselesskey-xtask",
                            "rules": rules,
                        }
                    },
                    "results": results,
                }
            ]
        });

        serde_json::to_string_pretty(&sarif).expect("SARIF serialization should not fail")
    }
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
                schema_version: 2,
                timestamp: now,
                git_sha: None,
                crate_set: None,
                steps: Vec::new(),
                feature_matrix: Vec::new(),
                bdd_matrix: Vec::new(),
                bdd_counts: BTreeMap::new(),
                coverage_lcov_path: None,
                coverage_percent: None,
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

    pub fn set_coverage_percent(&mut self, percent: f64) {
        self.receipt.coverage_percent = Some(percent);
    }

    #[allow(dead_code)]
    pub fn set_git_sha(&mut self, sha: String) {
        self.receipt.git_sha = Some(sha);
    }

    #[allow(dead_code)]
    pub fn set_crate_set(&mut self, set: String) {
        self.receipt.crate_set = Some(set);
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
        eprint!("{}", self.receipt.timing_report());
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

    /// Write a SARIF 2.1.0 file from the current receipt state.
    #[allow(dead_code)]
    pub fn write_sarif(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create SARIF dir {:?}", parent))?;
        }
        let sarif = self.receipt.to_sarif();
        fs::write(path, sarif).context("failed to write SARIF file")?;
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
        let path = dir.path().join("nested").join("receipt.json");

        let mut runner = Runner::new(&path);
        runner
            .step("ok-step", Some("details".to_string()), || Ok(()))
            .expect("ok step");

        let err = runner.step("fail-step", Some("extra".to_string()), || {
            Err(anyhow!("boom"))
        });
        assert!(err.is_err());

        runner.skip("skipped-step", Some("not needed".to_string()));
        runner.add_feature_matrix("default", "ok");
        runner.set_coverage_lcov_path("coverage/lcov.info".to_string());

        let mut counts = BTreeMap::new();
        counts.insert("rsa.feature".to_string(), 2);
        runner.set_bdd_counts(counts);

        runner.receipt.steps.push(StepReceipt {
            name: "other-step".to_string(),
            status: "other".to_string(),
            duration_ms: 0,
            details: None,
        });

        runner.summary();

        assert_eq!(runner.receipt.steps.len(), 4);
        assert_eq!(runner.receipt.feature_matrix.len(), 1);
        assert_eq!(runner.receipt.bdd_counts.get("rsa.feature"), Some(&2));
        assert_eq!(
            runner.receipt.coverage_lcov_path.as_deref(),
            Some("coverage/lcov.info")
        );

        runner.write().expect("write receipt");
        let json = fs::read_to_string(&path).expect("read receipt");
        assert!(json.contains("\"steps\""));
    }

    #[test]
    fn runner_records_coverage_percent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("receipt.json");

        let mut runner = Runner::new(&path);
        runner.set_coverage_percent(82.5);
        assert_eq!(runner.receipt.coverage_percent, Some(82.5));

        runner.write().expect("write receipt");
        let json = fs::read_to_string(&path).expect("read receipt");
        assert!(
            json.contains("\"coverage_percent\": 82.5"),
            "receipt JSON should contain coverage_percent"
        );
    }

    #[test]
    fn runner_omits_coverage_percent_when_not_set() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("receipt.json");

        let runner = Runner::new(&path);
        assert!(runner.receipt.coverage_percent.is_none());

        runner.write().expect("write receipt");
        let json = fs::read_to_string(&path).expect("read receipt");
        assert!(
            !json.contains("coverage_percent"),
            "receipt JSON should omit coverage_percent when None"
        );
    }

    #[test]
    fn timing_report_format() {
        let receipt = Receipt {
            schema_version: 2,
            timestamp: 0,
            git_sha: None,
            crate_set: None,
            steps: vec![
                StepReceipt {
                    name: "tests".to_string(),
                    status: "ok".to_string(),
                    duration_ms: 42_300,
                    details: None,
                },
                StepReceipt {
                    name: "bdd".to_string(),
                    status: "ok".to_string(),
                    duration_ms: 23_100,
                    details: None,
                },
                StepReceipt {
                    name: "fmt".to_string(),
                    status: "ok".to_string(),
                    duration_ms: 1_200,
                    details: None,
                },
                StepReceipt {
                    name: "clippy".to_string(),
                    status: "ok".to_string(),
                    duration_ms: 27_000,
                    details: None,
                },
            ],
            feature_matrix: Vec::new(),
            bdd_matrix: Vec::new(),
            bdd_counts: BTreeMap::new(),
            coverage_lcov_path: None,
            coverage_percent: None,
        };

        let report = receipt.timing_report();

        // Should contain the header.
        assert!(
            report.contains("--- Timing Breakdown ---"),
            "should have timing header, got:\n{report}"
        );

        // Should contain the total line.
        assert!(
            report.contains("total"),
            "should have total line, got:\n{report}"
        );
        assert!(
            report.contains("93.6s"),
            "total should be 93.6s, got:\n{report}"
        );

        // Steps should appear sorted by duration (longest first).
        let tests_pos = report.find("tests").expect("should contain 'tests'");
        let clippy_pos = report.find("clippy").expect("should contain 'clippy'");
        let bdd_pos = report.find("bdd").expect("should contain 'bdd'");
        let fmt_pos = report.find("fmt").expect("should contain 'fmt'");
        assert!(
            tests_pos < clippy_pos,
            "tests (42.3s) should appear before clippy (27.0s)"
        );
        assert!(
            clippy_pos < bdd_pos,
            "clippy (27.0s) should appear before bdd (23.1s)"
        );
        assert!(
            bdd_pos < fmt_pos,
            "bdd (23.1s) should appear before fmt (1.2s)"
        );

        // Should contain bar chart characters.
        assert!(
            report.contains('\u{2588}'),
            "should contain filled block char, got:\n{report}"
        );
        assert!(
            report.contains('\u{2591}'),
            "should contain light shade char, got:\n{report}"
        );

        // Should contain percentage signs.
        assert!(
            report.contains('%'),
            "should contain percentage, got:\n{report}"
        );

        // Each step line should show its duration.
        assert!(
            report.contains("42.3s"),
            "should show tests duration, got:\n{report}"
        );
        assert!(
            report.contains("23.1s"),
            "should show bdd duration, got:\n{report}"
        );
        assert!(
            report.contains("1.2s"),
            "should show fmt duration, got:\n{report}"
        );

        // Should contain a separator line (dashes).
        assert!(
            report.contains("------"),
            "should have separator line, got:\n{report}"
        );
    }

    #[test]
    fn timing_report_empty_steps() {
        let receipt = Receipt {
            schema_version: 2,
            timestamp: 0,
            git_sha: None,
            crate_set: None,
            steps: Vec::new(),
            feature_matrix: Vec::new(),
            bdd_matrix: Vec::new(),
            bdd_counts: BTreeMap::new(),
            coverage_lcov_path: None,
            coverage_percent: None,
        };

        let report = receipt.timing_report();

        assert!(
            report.contains("--- Timing Breakdown ---"),
            "should have timing header even with no steps"
        );
        assert!(
            report.contains("total"),
            "should have total line even with no steps"
        );
        assert!(
            report.contains("0.0s"),
            "total should be 0.0s with no steps, got:\n{report}"
        );
    }
}
