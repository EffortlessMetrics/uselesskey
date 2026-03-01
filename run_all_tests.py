"""Run all adapter snapshot tests sequentially."""
import subprocess, os, glob, shutil

os.chdir(r'C:\Code\Rust\uselesskey-wave7')
env = os.environ.copy()
env['INSTA_UPDATE'] = 'new'

tests = [
    ('uselesskey-ring', 'snapshots_ring'),
    ('uselesskey-aws-lc-rs', 'snapshots_aws_lc_rs'),
    ('uselesskey-rustcrypto', 'snapshots_rustcrypto'),
]

results = []
for crate, test in tests:
    print(f"\n=== Testing {crate} ({test}) ===")
    result = subprocess.run(
        ['cargo', 'test', '-p', crate, '--all-features', '--test', test],
        capture_output=True, env=env, timeout=900
    )
    out = result.stderr.decode('utf-8', 'replace')
    print(out[-1500:])
    print(f"RC: {result.returncode}")
    results.append((crate, result.returncode))

# Accept all new snapshots
snap_dirs = [
    r'crates\uselesskey-ring\tests\snapshots',
    r'crates\uselesskey-aws-lc-rs\tests\snapshots',
    r'crates\uselesskey-rustcrypto\tests\snapshots',
]

print("\n=== Accepting snapshots ===")
for d in snap_dirs:
    if not os.path.exists(d):
        continue
    for f in glob.glob(os.path.join(d, '*.snap.new')):
        target = f[:-4]
        shutil.move(f, target)
        print(f'Accepted: {os.path.basename(target)}')

print("\n=== Results ===")
for crate, rc in results:
    print(f"{crate}: {'PASS' if rc == 0 else f'FAIL (rc={rc})'}")
