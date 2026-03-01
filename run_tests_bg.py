"""Run all adapter tests and write output files."""
import subprocess, os, glob, shutil, sys

os.chdir(r'C:\Code\Rust\uselesskey-wave7')
env = os.environ.copy()
env['INSTA_UPDATE'] = 'new'

tests = [
    ('uselesskey-ring', 'snapshots_ring', 'ring-out.txt'),
    ('uselesskey-aws-lc-rs', 'snapshots_aws_lc_rs', 'awslc-out.txt'),
    ('uselesskey-rustcrypto', 'snapshots_rustcrypto', 'rustcrypto-out.txt'),
]

for crate, test, outfile in tests:
    result = subprocess.run(
        ['cargo', 'test', '-p', crate, '--all-features', '--test', test],
        capture_output=True, env=env, timeout=900
    )
    with open(outfile, 'wb') as f:
        f.write(result.stdout + b'\n---STDERR---\n' + result.stderr)
        f.write(f'\n---RC: {result.returncode}---\n'.encode())

# Accept snapshots
for d in ['crates\\uselesskey-ring\\tests\\snapshots',
          'crates\\uselesskey-aws-lc-rs\\tests\\snapshots',
          'crates\\uselesskey-rustcrypto\\tests\\snapshots']:
    if not os.path.exists(d):
        continue
    for f in glob.glob(os.path.join(d, '*.snap.new')):
        shutil.move(f, f[:-4])

with open('all-done.txt', 'w') as f:
    f.write('DONE\n')
