# Run all tests sequentially and capture results
$ErrorActionPreference = "Continue"

Write-Host "=== Step 1: cargo fmt --all ===" -ForegroundColor Green
cargo fmt --all
Write-Host "Format complete`n" -ForegroundColor Cyan

Write-Host "=== Step 2: cargo test -p uselesskey-test-grid --all-features ===" -ForegroundColor Green
cargo test -p uselesskey-test-grid --all-features
$test1Exit = $LASTEXITCODE
Write-Host "`nTest 1 Exit Code: $test1Exit`n" -ForegroundColor Cyan

Write-Host "=== Step 3: cargo test -p uselesskey-feature-grid --all-features ===" -ForegroundColor Green
cargo test -p uselesskey-feature-grid --all-features
$test2Exit = $LASTEXITCODE
Write-Host "`nTest 2 Exit Code: $test2Exit`n" -ForegroundColor Cyan

Write-Host "=== Step 4: cargo test -p uselesskey-core-x509-derive --all-features ===" -ForegroundColor Green
cargo test -p uselesskey-core-x509-derive --all-features
$test3Exit = $LASTEXITCODE
Write-Host "`nTest 3 Exit Code: $test3Exit`n" -ForegroundColor Cyan

Write-Host "=== Step 5: cargo test -p uselesskey-core-x509-chain-negative --all-features ===" -ForegroundColor Green
cargo test -p uselesskey-core-x509-chain-negative --all-features
$test4Exit = $LASTEXITCODE
Write-Host "`nTest 4 Exit Code: $test4Exit`n" -ForegroundColor Cyan

Write-Host "=== Step 6: cargo test -p uselesskey-core-rustls-pki --all-features ===" -ForegroundColor Green
cargo test -p uselesskey-core-rustls-pki --all-features
$test5Exit = $LASTEXITCODE
Write-Host "`nTest 5 Exit Code: $test5Exit`n" -ForegroundColor Cyan

Write-Host "=== ALL TESTS COMPLETE ===" -ForegroundColor Green
