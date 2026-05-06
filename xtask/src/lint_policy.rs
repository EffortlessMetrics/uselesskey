use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use chrono::{NaiveDate, Utc};
use toml::Value;

const ROOT_MANIFEST: &str = "Cargo.toml";
const CLIPPY_TOML: &str = "clippy.toml";
const CLIPPY_POLICY: &str = "policy/clippy-lints.toml";
const CLIPPY_DEBT: &str = "policy/clippy-debt.toml";
const NO_PANIC_ALLOWLIST: &str = "policy/no-panic-allowlist.toml";
const NON_RUST_ALLOWLIST: &str = "policy/non-rust-allowlist.toml";

const TEST_CARVEOUTS: &[&str] = &[
    "allow-unwrap-in-tests",
    "allow-expect-in-tests",
    "allow-panic-in-tests",
    "allow-indexing-slicing-in-tests",
    "allow-dbg-in-tests",
];

const REQUIRED_RUST_LINTS: &[(&str, &str)] = &[
    ("unsafe_code", "forbid"),
    ("unsafe_op_in_unsafe_fn", "deny"),
    ("unused_must_use", "deny"),
    ("unexpected_cfgs", "warn"),
    ("const_item_interior_mutations", "deny"),
    ("function_casts_as_integer", "deny"),
];

const REQUIRED_CLIPPY_LINTS: &[(&str, &str)] = &[
    ("dbg_macro", "deny"),
    ("todo", "deny"),
    ("unimplemented", "deny"),
    ("panic", "deny"),
    ("unreachable", "deny"),
    ("unwrap_used", "deny"),
    ("expect_used", "deny"),
    ("get_unwrap", "deny"),
    ("unwrap_in_result", "deny"),
    ("panic_in_result_fn", "deny"),
    ("string_slice", "deny"),
    ("indexing_slicing", "deny"),
    ("out_of_bounds_indexing", "deny"),
    ("unchecked_time_subtraction", "deny"),
    ("char_indices_as_byte_indices", "deny"),
    ("sliced_string_as_bytes", "deny"),
    ("index_refutable_slice", "deny"),
    ("let_underscore_future", "deny"),
    ("let_underscore_must_use", "deny"),
    ("let_underscore_lock", "deny"),
    ("unused_result_ok", "deny"),
    ("map_err_ignore", "deny"),
    ("assertions_on_result_states", "deny"),
    ("lines_filter_map_ok", "deny"),
    ("await_holding_lock", "deny"),
    ("await_holding_refcell_ref", "deny"),
    ("await_holding_invalid_type", "deny"),
    ("future_not_send", "warn"),
    ("large_futures", "warn"),
    ("arc_with_non_send_sync", "deny"),
    ("rc_mutex", "deny"),
    ("mut_mutex_lock", "deny"),
    ("readonly_write_lock", "deny"),
    ("mem_forget", "deny"),
    ("forget_non_drop", "deny"),
    ("drop_non_drop", "deny"),
    ("undocumented_unsafe_blocks", "deny"),
    ("multiple_unsafe_ops_per_block", "deny"),
    ("repr_packed_without_abi", "deny"),
    ("float_cmp", "deny"),
    ("float_cmp_const", "deny"),
    ("float_equality_without_abs", "deny"),
    ("lossy_float_literal", "deny"),
    ("cast_sign_loss", "deny"),
    ("cast_possible_wrap", "warn"),
    ("cast_possible_truncation", "warn"),
    ("cast_precision_loss", "warn"),
    ("invalid_upcast_comparisons", "deny"),
    ("cast_abs_to_unsigned", "deny"),
    ("cast_enum_truncation", "deny"),
    ("cast_nan_to_int", "deny"),
    ("manual_midpoint", "warn"),
    ("manual_is_multiple_of", "warn"),
    ("manual_div_ceil", "warn"),
    ("arithmetic_side_effects", "warn"),
    ("suspicious_open_options", "deny"),
    ("nonsensical_open_options", "deny"),
    ("ineffective_open_options", "deny"),
    ("path_buf_push_overwrite", "deny"),
    ("join_absolute_paths", "deny"),
    ("read_line_without_trim", "warn"),
    ("exit", "deny"),
    ("iter_not_returning_iterator", "deny"),
    ("expl_impl_clone_on_copy", "deny"),
    ("infallible_try_from", "deny"),
    ("fallible_impl_from", "deny"),
    ("error_impl_error", "deny"),
    ("result_unit_err", "warn"),
    ("result_large_err", "warn"),
    ("format_in_format_args", "deny"),
    ("to_string_in_format_args", "deny"),
    ("unused_format_specs", "deny"),
    ("unnecessary_debug_formatting", "warn"),
    ("uninlined_format_args", "warn"),
    ("manual_let_else", "warn"),
    ("manual_ok_or", "warn"),
    ("manual_strip", "warn"),
    ("manual_split_once", "warn"),
    ("manual_is_variant_and", "warn"),
    ("filter_map_next", "warn"),
    ("flat_map_option", "warn"),
    ("match_result_ok", "deny"),
    ("cloned_instead_of_copied", "warn"),
    ("iter_cloned_collect", "warn"),
    ("iter_overeager_cloned", "warn"),
    ("needless_collect", "warn"),
    ("redundant_closure", "warn"),
    ("redundant_closure_for_method_calls", "warn"),
    ("missing_panics_doc", "deny"),
    ("missing_errors_doc", "warn"),
    ("allow_attributes", "deny"),
    ("allow_attributes_without_reason", "deny"),
    ("blanket_clippy_restriction_lints", "deny"),
    ("ignore_without_reason", "deny"),
    ("should_panic_without_expect", "deny"),
];

const EXPECTED_PLANNED: &[(&str, &str, &str)] = &[
    ("clippy::same_length_and_capacity", "deny", "1.94"),
    ("clippy::manual_ilog2", "warn", "1.94"),
    ("clippy::decimal_bitwise_operands", "warn", "1.94"),
    ("clippy::needless_type_cast", "warn", "1.94"),
    ("clippy::disallowed_fields", "deny", "1.95"),
    ("clippy::manual_checked_ops", "warn", "1.95"),
    ("clippy::manual_take", "warn", "1.95"),
    ("clippy::manual_pop_if", "warn", "1.95"),
    ("clippy::duration_suboptimal_units", "warn", "1.95"),
    ("clippy::unnecessary_trailing_comma", "warn", "1.95"),
];

pub fn check_lint_policy() -> Result<()> {
    let root = read_toml(ROOT_MANIFEST)?;
    let policy = read_toml(CLIPPY_POLICY)?;

    check_msrv(&root, &policy)?;
    check_workspace_lints(&root)?;
    check_member_lint_inheritance(&root)?;
    check_no_test_carveouts()?;
    check_planned_lints(&root, &policy)?;
    check_debt_file()?;
    check_allowlist_schema(NO_PANIC_ALLOWLIST, AllowlistKind::NoPanic)?;
    check_allowlist_schema(NON_RUST_ALLOWLIST, AllowlistKind::NonRust)?;

    println!("lint policy: ok");
    Ok(())
}

pub fn check_no_panic_family() -> Result<()> {
    check_allowlist_schema(NO_PANIC_ALLOWLIST, AllowlistKind::NoPanic)?;
    println!("no-panic allowlist schema: ok");
    Ok(())
}

pub fn check_file_policy() -> Result<()> {
    check_allowlist_schema(NON_RUST_ALLOWLIST, AllowlistKind::NonRust)?;
    println!("non-rust file policy schema: ok");
    Ok(())
}

pub fn policy_report() -> Result<()> {
    let policy = read_toml(CLIPPY_POLICY)?;
    let planned = policy
        .get("planned")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let debt = read_toml(CLIPPY_DEBT)?
        .get("debt")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let no_panic = read_toml(NO_PANIC_ALLOWLIST)?
        .get("allow")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let non_rust = read_toml(NON_RUST_ALLOWLIST)?
        .get("allow")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);

    println!("policy report");
    println!("  clippy planned flips: {planned}");
    println!("  clippy debt entries: {debt}");
    println!("  panic exceptions: {no_panic}");
    println!("  non-rust exceptions: {non_rust}");
    Ok(())
}

fn check_msrv(root: &Value, policy: &Value) -> Result<()> {
    let manifest_msrv = root
        .get("workspace")
        .and_then(|v| v.get("package"))
        .and_then(|v| v.get("rust-version"))
        .and_then(Value::as_str)
        .context("missing workspace.package.rust-version")?;
    let policy_msrv = policy
        .get("msrv")
        .and_then(Value::as_str)
        .context("missing policy/clippy-lints.toml msrv")?;
    if manifest_msrv != policy_msrv {
        bail!("workspace MSRV {manifest_msrv} does not match clippy policy MSRV {policy_msrv}");
    }

    let clippy = fs::read_to_string(CLIPPY_TOML).context("failed to read clippy.toml")?;
    if !clippy.contains(&format!("msrv = \"{policy_msrv}\"")) {
        bail!("clippy.toml msrv must match policy MSRV {policy_msrv}");
    }
    Ok(())
}

fn check_workspace_lints(root: &Value) -> Result<()> {
    let rust_lints = root
        .get("workspace")
        .and_then(|v| v.get("lints"))
        .and_then(|v| v.get("rust"))
        .and_then(Value::as_table)
        .context("missing [workspace.lints.rust]")?;
    for (lint, level) in REQUIRED_RUST_LINTS {
        require_lint_level(rust_lints, lint, level, "workspace.lints.rust")?;
    }

    let clippy_lints = root
        .get("workspace")
        .and_then(|v| v.get("lints"))
        .and_then(|v| v.get("clippy"))
        .and_then(Value::as_table)
        .context("missing [workspace.lints.clippy]")?;
    for (lint, level) in REQUIRED_CLIPPY_LINTS {
        require_lint_level(clippy_lints, lint, level, "workspace.lints.clippy")?;
    }
    Ok(())
}

fn check_member_lint_inheritance(root: &Value) -> Result<()> {
    let members = root
        .get("workspace")
        .and_then(|v| v.get("members"))
        .and_then(Value::as_array)
        .context("missing workspace.members")?;

    let mut missing = Vec::new();
    for member in members {
        let member = member
            .as_str()
            .context("workspace.members must contain strings")?;
        let manifest_path = Path::new(member).join("Cargo.toml");
        let manifest = read_toml(&manifest_path)?;
        let inherits = manifest
            .get("lints")
            .and_then(|v| v.get("workspace"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !inherits {
            missing.push(manifest_path.display().to_string());
        }
    }

    if !missing.is_empty() {
        bail!(
            "workspace members missing `[lints] workspace = true`: {}",
            missing.join(", ")
        );
    }
    Ok(())
}

fn check_no_test_carveouts() -> Result<()> {
    let clippy = fs::read_to_string(CLIPPY_TOML).context("failed to read clippy.toml")?;
    for carveout in TEST_CARVEOUTS {
        if clippy.contains(carveout) {
            bail!("clippy.toml must not configure test carveout `{carveout}`");
        }
    }
    Ok(())
}

fn check_planned_lints(root: &Value, policy: &Value) -> Result<()> {
    let planned = policy
        .get("planned")
        .and_then(Value::as_array)
        .context("policy/clippy-lints.toml must contain [[planned]] entries")?;

    for (name, level, msrv) in EXPECTED_PLANNED {
        let found = planned.iter().any(|entry| {
            entry.get("name").and_then(Value::as_str) == Some(*name)
                && entry.get("level").and_then(Value::as_str) == Some(*level)
                && entry.get("activate_when_msrv").and_then(Value::as_str) == Some(*msrv)
                && entry
                    .get("reason")
                    .and_then(Value::as_str)
                    .is_some_and(non_empty)
        });
        if !found {
            bail!("missing planned lint `{name}` at {level} for MSRV {msrv}");
        }
    }

    let clippy_lints = root
        .get("workspace")
        .and_then(|v| v.get("lints"))
        .and_then(|v| v.get("clippy"))
        .and_then(Value::as_table)
        .context("missing [workspace.lints.clippy]")?;
    for entry in planned {
        let name = required_str(entry, "name")?;
        let short_name = name.strip_prefix("clippy::").unwrap_or(name);
        if clippy_lints.contains_key(short_name) {
            bail!("planned lint `{name}` is active before its MSRV flip");
        }
    }
    Ok(())
}

fn check_debt_file() -> Result<()> {
    let debt = read_toml(CLIPPY_DEBT)?;
    if let Some(entries) = debt.get("debt").and_then(Value::as_array) {
        for entry in entries {
            for field in ["lint", "path", "owner", "reason", "expires"] {
                required_str(entry, field)
                    .with_context(|| format!("invalid clippy debt entry: missing {field}"))?;
            }
            check_not_expired(required_str(entry, "expires")?, "clippy debt")?;
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum AllowlistKind {
    NoPanic,
    NonRust,
}

fn check_allowlist_schema(path: impl AsRef<Path>, kind: AllowlistKind) -> Result<()> {
    let value = read_toml(path.as_ref())?;
    let entries = value
        .get("allow")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    for entry in &entries {
        match kind {
            AllowlistKind::NoPanic => check_no_panic_entry(entry)?,
            AllowlistKind::NonRust => check_non_rust_entry(entry)?,
        }
    }
    Ok(())
}

fn check_no_panic_entry(entry: &Value) -> Result<()> {
    for field in ["path", "family", "classification", "owner", "explanation"] {
        required_str(entry, field)
            .with_context(|| format!("invalid no-panic allow entry: missing {field}"))?;
    }
    let selector = entry
        .get("selector")
        .and_then(Value::as_table)
        .context("invalid no-panic allow entry: missing selector")?;
    for field in ["kind", "container"] {
        require_table_str(selector, field)
            .with_context(|| format!("invalid no-panic selector: missing {field}"))?;
    }
    if let Some(expires) = entry.get("expires").and_then(Value::as_str) {
        check_not_expired(expires, "no-panic allow entry")?;
    }
    Ok(())
}

fn check_non_rust_entry(entry: &Value) -> Result<()> {
    let has_path = entry
        .get("path")
        .and_then(Value::as_str)
        .is_some_and(non_empty);
    let has_glob = entry
        .get("glob")
        .and_then(Value::as_str)
        .is_some_and(non_empty);
    if has_path == has_glob {
        bail!("non-rust allow entry must set exactly one of path or glob");
    }
    for field in ["kind", "owner", "reason", "surface", "classification"] {
        required_str(entry, field)
            .with_context(|| format!("invalid non-rust allow entry: missing {field}"))?;
    }
    let covered_by = entry
        .get("covered_by")
        .and_then(Value::as_array)
        .context("invalid non-rust allow entry: missing covered_by")?;
    if covered_by
        .iter()
        .filter_map(Value::as_str)
        .all(|item| item.trim().is_empty())
    {
        bail!("non-rust allow entry must have at least one non-empty covered_by command");
    }
    if let Some(expires) = entry.get("expires").and_then(Value::as_str) {
        check_not_expired(expires, "non-rust allow entry")?;
    }
    Ok(())
}

fn check_not_expired(expires: &str, label: &str) -> Result<()> {
    let expires = NaiveDate::parse_from_str(expires, "%Y-%m-%d")
        .with_context(|| format!("invalid {label} expiry date `{expires}`"))?;
    let today = Utc::now().date_naive();
    if expires < today {
        bail!("expired {label} entry with expiry {expires}");
    }
    Ok(())
}

fn require_lint_level(
    table: &toml::map::Map<String, Value>,
    lint: &str,
    expected: &str,
    table_name: &str,
) -> Result<()> {
    let actual = table
        .get(lint)
        .and_then(Value::as_str)
        .with_context(|| format!("missing lint `{lint}` in {table_name}"))?;
    if actual != expected {
        bail!("lint `{lint}` in {table_name} must be `{expected}`, found `{actual}`");
    }
    Ok(())
}

fn required_str<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    let value = value
        .get(field)
        .and_then(Value::as_str)
        .with_context(|| format!("missing string field `{field}`"))?;
    if value.trim().is_empty() {
        bail!("field `{field}` must not be empty");
    }
    Ok(value)
}

fn require_table_str<'a>(table: &'a toml::map::Map<String, Value>, field: &str) -> Result<&'a str> {
    let value = table
        .get(field)
        .and_then(Value::as_str)
        .with_context(|| format!("missing string field `{field}`"))?;
    if value.trim().is_empty() {
        bail!("field `{field}` must not be empty");
    }
    Ok(value)
}

fn read_toml(path: impl AsRef<Path>) -> Result<Value> {
    let path = path.as_ref();
    let raw =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    toml::from_str::<Value>(&raw).with_context(|| format!("failed to parse {}", path.display()))
}

fn non_empty(value: &str) -> bool {
    !value.trim().is_empty()
}
