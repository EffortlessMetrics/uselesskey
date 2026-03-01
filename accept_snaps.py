import glob, os, shutil

dirs = [
    r'C:\Code\Rust\uselesskey-wave7\crates\uselesskey-jsonwebtoken\tests\snapshots',
    r'C:\Code\Rust\uselesskey-wave7\crates\uselesskey-ring\tests\snapshots',
    r'C:\Code\Rust\uselesskey-wave7\crates\uselesskey-aws-lc-rs\tests\snapshots',
    r'C:\Code\Rust\uselesskey-wave7\crates\uselesskey-rustcrypto\tests\snapshots',
]

for base in dirs:
    if not os.path.exists(base):
        continue
    for f in glob.glob(os.path.join(base, '*.snap.new')):
        target = f[:-4]
        shutil.move(f, target)
        print(f'Accepted: {os.path.basename(target)}')

print("Done")
