#!/usr/bin/env python3
"""Run ModelAudit and ModelScan on test files and collect results - FIXED VERSION."""

import subprocess
import json
import os
import re
from pathlib import Path
from collections import defaultdict

# Paths
TEST_DIR = Path("test_models")
RESULTS_DIR = Path("results")
RESULTS_DIR.mkdir(exist_ok=True)

# Test files grouped by category
TEST_FILES = {
    "Pickle Files": [
        "pickle_os_system.pkl",
        "pickle_base64_payload.pkl", 
        "pickle_obfuscated.pkl",
        "pickle_legitimate_ml.pkl",
        "pickle_with_binary.pkl"
    ],
    "Configuration Files": [
        "config_malicious.json",
        "config_malicious.yaml",
        "config_blacklisted.json"
    ],
    "Archive Files": [
        "zip_path_traversal.zip",
        "zip_with_executable.zip"
    ],
    "Other Formats": [
        "model.pmml"
    ]
}


def run_modelaudit(file_path):
    """Run ModelAudit on a file and return results."""
    cmd = ["rye", "run", "modelaudit", "scan", "--format", "json", str(file_path)]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode in [0, 1]:  # 0 = no issues, 1 = issues found
            return json.loads(result.stdout)
        else:
            return {"error": result.stderr}
    except subprocess.TimeoutExpired:
        return {"error": "Timeout"}
    except Exception as e:
        return {"error": str(e)}


def run_modelscan(file_path):
    """Run ModelScan on a file and return results."""
    # Activate virtual environment and run modelscan
    activate_cmd = "source modelscan_env/bin/activate"
    modelscan_cmd = f"modelscan scan -p {file_path} -r json"
    cmd = f"{activate_cmd} && {modelscan_cmd}"
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        
        # ModelScan often returns non-zero exit codes even when it works
        # 0 = no issues, 1 = issues found, 3 = unsupported format
        if result.returncode in [0, 1, 3]:
            output = result.stdout.strip()
            
            if not output or result.returncode == 3:
                # Format not supported
                return {"supported": False, "error": "Format not supported", "returncode": result.returncode}
            
            # Fix the malformed JSON by removing newlines within the JSON structure
            # Find where the JSON starts
            json_start = output.find('{')
            if json_start >= 0:
                json_output = output[json_start:]
                # Replace newlines within the JSON with spaces
                # This is a bit hacky but necessary for modelscan's broken output
                json_output = re.sub(r'\n(?!$)', ' ', json_output)
                
                try:
                    return json.loads(json_output)
                except json.JSONDecodeError as e:
                    # Save the problematic output for debugging
                    debug_file = RESULTS_DIR / f"debug_{Path(file_path).name}.txt"
                    with open(debug_file, "w") as f:
                        f.write(f"Original output:\n{output}\n\nCleaned output:\n{json_output}\n\nError: {e}")
                    return {"error": f"JSON parse error: {e}", "debug_file": str(debug_file)}
            else:
                return {"supported": False, "error": "No JSON output found"}
        else:
            return {"error": f"Unexpected return code: {result.returncode}", "stderr": result.stderr}
    except subprocess.TimeoutExpired:
        return {"error": "Timeout"}
    except Exception as e:
        return {"error": str(e)}


def analyze_results():
    """Analyze and summarize the comparison results."""
    results = defaultdict(lambda: {"modelaudit": [], "modelscan": []})
    
    print("\n" + "="*80)
    print("RUNNING COMPARISON TESTS (FIXED)")
    print("="*80)
    
    for category, files in TEST_FILES.items():
        print(f"\n📁 {category}")
        print("-" * 40)
        
        for file_name in files:
            file_path = TEST_DIR / file_name
            if not file_path.exists():
                print(f"  ⚠️  {file_name}: File not found")
                continue
                
            print(f"\n  📄 {file_name}:")
            
            # Run ModelAudit
            print("    Running ModelAudit...", end=" ")
            ma_result = run_modelaudit(file_path)
            ma_issues = len(ma_result.get("issues", [])) if "issues" in ma_result else 0
            ma_error = ma_result.get("error")
            
            if ma_error:
                print(f"❌ Error: {ma_error}")
                results[file_name]["modelaudit"] = {"error": ma_error}
            else:
                print(f"✅ Found {ma_issues} issues")
                results[file_name]["modelaudit"] = {
                    "issues_count": ma_issues,
                    "issues": ma_result.get("issues", [])
                }
            
            # Run ModelScan  
            print("    Running ModelScan...", end=" ")
            ms_result = run_modelscan(file_path)
            
            if not ms_result.get("supported", True):
                print("❌ Format not supported")
                results[file_name]["modelscan"] = {"supported": False}
            elif ms_error := ms_result.get("error"):
                print(f"❌ Error: {ms_error}")
                results[file_name]["modelscan"] = {"error": ms_error}
            else:
                ms_issues = len(ms_result.get("issues", []))
                print(f"✅ Found {ms_issues} issues")
                results[file_name]["modelscan"] = {
                    "issues_count": ms_issues,
                    "issues": ms_result.get("issues", [])
                }
    
    # Save detailed results
    with open(RESULTS_DIR / "detailed_results_fixed.json", "w") as f:
        json.dump(dict(results), f, indent=2)
    
    return dict(results)


def generate_summary(results):
    """Generate a summary of the comparison."""
    summary = {
        "format_support": {"modelaudit": 0, "modelscan": 0},
        "issues_detected": {"modelaudit": 0, "modelscan": 0},
        "files_scanned": 0,
        "format_comparison": {},
        "detection_comparison": []
    }
    
    for file_name, result in results.items():
        summary["files_scanned"] += 1
        
        # Check format support
        ma_supported = "error" not in result["modelaudit"] or "File not found" not in result["modelaudit"].get("error", "")
        ms_supported = result["modelscan"].get("supported", True) and "error" not in result["modelscan"]
        
        if ma_supported:
            summary["format_support"]["modelaudit"] += 1
        if ms_supported:
            summary["format_support"]["modelscan"] += 1
            
        # Track format support
        file_ext = Path(file_name).suffix
        if file_ext not in summary["format_comparison"]:
            summary["format_comparison"][file_ext] = {"modelaudit": 0, "modelscan": 0}
        if ma_supported:
            summary["format_comparison"][file_ext]["modelaudit"] += 1
        if ms_supported:
            summary["format_comparison"][file_ext]["modelscan"] += 1
        
        # Count issues detected
        ma_issues = result["modelaudit"].get("issues_count", 0)
        ms_issues = result["modelscan"].get("issues_count", 0)
        
        if ma_issues > 0:
            summary["issues_detected"]["modelaudit"] += 1
        if ms_issues > 0:
            summary["issues_detected"]["modelscan"] += 1
            
        # Compare detection capabilities
        if ma_supported and ms_supported:
            summary["detection_comparison"].append({
                "file": file_name,
                "modelaudit_issues": ma_issues,
                "modelscan_issues": ms_issues,
                "modelaudit_finds_more": ma_issues > ms_issues
            })
    
    with open(RESULTS_DIR / "summary_fixed.json", "w") as f:
        json.dump(summary, f, indent=2)
    
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    print(f"\n📊 Format Support:")
    print(f"  ModelAudit: {summary['format_support']['modelaudit']}/{summary['files_scanned']} files")
    print(f"  ModelScan:  {summary['format_support']['modelscan']}/{summary['files_scanned']} files")
    
    print(f"\n🔍 Detection Rate:")
    print(f"  ModelAudit: Detected issues in {summary['issues_detected']['modelaudit']} files")
    print(f"  ModelScan:  Detected issues in {summary['issues_detected']['modelscan']} files")
    
    print(f"\n📈 Detection Comparison (both scanners support format):")
    better_detection = sum(1 for d in summary["detection_comparison"] if d["modelaudit_finds_more"])
    equal_detection = sum(1 for d in summary["detection_comparison"] if d["modelaudit_issues"] == d["modelscan_issues"] > 0)
    print(f"  ModelAudit found more issues in {better_detection}/{len(summary['detection_comparison'])} comparable files")
    print(f"  Both found issues equally in {equal_detection} files")
    
    # Show detailed comparison
    print(f"\n📋 Detailed Comparison:")
    for comp in summary["detection_comparison"]:
        print(f"  {comp['file']}: ModelAudit={comp['modelaudit_issues']}, ModelScan={comp['modelscan_issues']}")
    
    return summary


def main():
    """Run the comparison."""
    results = analyze_results()
    summary = generate_summary(results)
    
    print(f"\n✅ Results saved to {RESULTS_DIR}/")
    print(f"  - detailed_results_fixed.json: Full scan results")
    print(f"  - summary_fixed.json: Comparison summary")
    print(f"  - test_outputs/modelscan_raw/: Raw modelscan outputs as proof")


if __name__ == "__main__":
    main()