import sys, os

f = r'C:\Code\Rust\uselesskey-wave7\jwt-out.txt'
if os.path.exists(f):
    with open(f, 'rb') as fh:
        data = fh.read()
    text = data[-3000:].decode('utf-8', 'replace')
    print(f"File size: {len(data)}")
    print(text)
else:
    print("File not found")
