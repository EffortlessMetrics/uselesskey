import re

with open(r"C:\Users\steven\AppData\Local\Temp\copilot-tool-output-1772447353110-qngsoo.txt") as f:
    content = f.read()

# Find all steps and test results
results = re.findall(r"=== Step \d.*|test result:.*", content)
for r in results:
    print(r)
