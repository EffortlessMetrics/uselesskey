import subprocess, os, sys

os.chdir(r'C:\Code\Rust\uselesskey-wave7')
env = os.environ.copy()
env['INSTA_UPDATE'] = 'new'

crate = sys.argv[1]
test_name = sys.argv[2]
out_file = sys.argv[3]

result = subprocess.run(
    ['cargo', 'test', '-p', crate, '--all-features', '--test', test_name],
    capture_output=True, env=env, timeout=900
)

with open(out_file, 'wb') as f:
    f.write(result.stdout)
    f.write(b'\n---STDERR---\n')
    f.write(result.stderr)
    f.write(f'\n---RC: {result.returncode}---\n'.encode())

print(f"Done: RC={result.returncode}")
