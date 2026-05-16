mod classify;
mod scan;

pub(crate) use scan::walk_for_blobs;
#[cfg(test)]
pub(crate) use classify::{classify_by_content, classify_pem_label, looks_like_jwt};
#[cfg(test)]
pub(crate) use scan::{classify_blob, contains_pem_markers, is_secret_extension, should_scan_path};

use anyhow::{Result, bail};

pub(crate) fn gate() -> Result<()> {
    let offenders = scan::find_secret_blobs()?;
    if offenders.is_empty() {
        return Ok(());
    }
    let mut msg = String::from("found secret-shaped fixtures:\n");
    for hit in &offenders {
        msg.push_str(&format!(
            "\n  {}\n    kind: {}\n    fix:  {}\n",
            hit.rel_path, hit.kind, hit.suggestion
        ));
    }
    bail!("{msg}");
}

pub(crate) fn migrate() -> Result<()> {
    scan::migrate()
}
