# ML Model Security Scanner Comparison

This directory contains a comprehensive security analysis comparing Promptfoo's ModelAudit and Protect AI's ModelScan through empirical testing.

## Contents

### Test Infrastructure

Located in `comparisons/` subdirectory:

- **generate_test_models.py** - Generates 11 test files with documented vulnerabilities
- **run_comparison_fixed.py** - Automated comparison script with JSON parsing fixes
- **test_modelscan_manual.py** - Manual verification script

### Test Data

- **test_models/** - 11 test files covering various attack vectors
- **test_outputs/modelscan_raw/** - Raw ModelScan outputs for verification
- **results/** - JSON results from automated comparison

## Key Findings

Based on testing with 11 files containing documented security vulnerabilities:

| Metric | ModelAudit | ModelScan |
|--------|------------|-----------|
| Format support | 11/11 (100%) | 6/11 (55%) |
| Issues detected | 16 | 3 |
| Files with detections | 8 | 3 |

## Reproduction

```bash
# Install dependencies
pip install modelaudit modelscan

# Generate test files
python comparisons/generate_test_models.py

# Run comparison
python comparisons/run_comparison_fixed.py

# View results
cat comparisons/results/summary_fixed.json
```

## Version Information

- ModelAudit: 0.1.0
- ModelScan: 0.8.5
- Test Date: July 6

## Notes

- All raw outputs preserved for independent verification
- Test files contain simulated vulnerabilities for security testing purposes
