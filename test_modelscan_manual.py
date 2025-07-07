#!/usr/bin/env python3
"""Run modelscan manually on each test file and save raw outputs."""

import subprocess
import json
from pathlib import Path

TEST_DIR = Path("test_models")
OUTPUT_DIR = Path("test_outputs/modelscan_raw")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Test files to scan
test_files = [
    "pickle_os_system.pkl",
    "pickle_base64_payload.pkl", 
    "pickle_obfuscated.pkl",
    "pickle_legitimate_ml.pkl",
    "pickle_with_binary.pkl",
    "config_malicious.json",
    "config_malicious.yaml",
    "config_blacklisted.json",
    "zip_path_traversal.zip",
    "zip_with_executable.zip",
    "model.pmml"
]

print("Running manual modelscan tests...")
print("="*60)

for test_file in test_files:
    file_path = TEST_DIR / test_file
    output_path = OUTPUT_DIR / f"{test_file}.out"
    
    if not file_path.exists():
        print(f"❌ {test_file}: File not found")
        continue
        
    print(f"\n📄 Testing: {test_file}")
    
    # Run modelscan and capture all output
    cmd = f"modelscan scan -p {file_path} -r json"
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        # Save raw output (stdout + stderr)
        with open(output_path, "w") as f:
            f.write(f"=== COMMAND: {cmd} ===\n")
            f.write(f"=== RETURN CODE: {result.returncode} ===\n")
            f.write("=== STDOUT ===\n")
            f.write(result.stdout)
            f.write("\n=== STDERR ===\n")
            f.write(result.stderr)
            f.write("\n=== END ===\n")
        
        # Try to parse JSON from stdout
        stdout = result.stdout.strip()
        if stdout:
            # Find JSON part
            json_start = stdout.find('{')
            if json_start >= 0:
                try:
                    json_data = json.loads(stdout[json_start:])
                    issues = json_data.get("issues", [])
                    print(f"   Return code: {result.returncode}")
                    print(f"   Issues found: {len(issues)}")
                    if issues:
                        for issue in issues:
                            print(f"   - {issue.get('severity', 'N/A')}: {issue.get('description', 'N/A')}")
                except json.JSONDecodeError as e:
                    print(f"   ❌ JSON parse error: {e}")
                    print(f"   Raw output saved to: {output_path}")
            else:
                print(f"   ❌ No JSON output found")
                print(f"   Raw output saved to: {output_path}")
        else:
            print(f"   ❌ No output")
            if result.stderr:
                print(f"   Error: {result.stderr[:100]}...")
            print(f"   Raw output saved to: {output_path}")
                
    except Exception as e:
        print(f"   ❌ Exception: {e}")
        with open(output_path, "w") as f:
            f.write(f"Exception: {e}\n")

print("\n" + "="*60)
print(f"✅ Raw outputs saved to: {OUTPUT_DIR}/")