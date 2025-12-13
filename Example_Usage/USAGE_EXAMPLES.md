# SymExE Usage Examples

Comprehensive guide for using SymExE to analyze evasive malware.

---

## Table of Contents

1. [Basic Usage](#basic-usage)
2. [Configuration Options](#configuration-options)
3. [Batch Processing](#batch-processing)
4. [Output Analysis](#output-analysis)
5. [Advanced Usage](#advanced-usage)
6. [Troubleshooting](#troubleshooting)

---

## Basic Usage

### Analyze Single Binary

```bash
# Uses defaults: max_states=2500, timeout=600s
python3 symexe.py malware.exe --output results.json

---

## Configuration Options

### Max States

Control the maximum number of symbolic states to explore:

```bash
# Light analysis (faster, less thorough)
python3 symexe.py malware.exe --max-states 1000 --output results.json

# Default (paper configuration)
python3 symexe.py malware.exe --max-states 2500 --output results.json

# Deep analysis (slower, more thorough)
python3 symexe.py malware.exe --max-states 5000 --output results.json
```

### Timeout

Set analysis timeout per binary:

```bash
# Paper configuration (10 minutes)
python3 symexe.py malware.exe --timeout 600 --output results.json

# Extended analysis (75 minutes)
python3 symexe.py malware.exe --timeout 4500 --output results.json

# Quick scan (5 minutes)
python3 symexe.py malware.exe --timeout 300 --output results.json
```

### Combined Configuration

```bash
python3 symexe.py malware.exe \
    --max-states 2500 \
    --timeout 4500 \
    --output results.json \
    --verbose
```

---

## Batch Processing

### Analyze Directory

```bash
# Analyze all binaries in directory
python3 symexe.py samples/ \
    --max-states 2500 \
    --timeout 600 \
    --output results_dir/

# Creates:
#   results_dir/binary1.exe.json
#   results_dir/binary2.exe.json
#   results_dir/aggregate.csv
```

### Using Batch Script

```bash
# Process representative subset
chmod +x run_subset_analysis.sh

./run_subset_analysis.sh subset_150_list.txt results_150/

# Shows progress:
# [42/150] Processing binary42.exe
# Progress: 28% | ETA: 2h 15m
```

### Parallel Processing

```bash
# Split dataset for parallel processing
split -n l/4 binary_list.txt subset_

# Run on multiple machines/terminals
python3 symexe.py subset_aa --output results_1/ &
python3 symexe.py subset_ab --output results_2/ &
python3 symexe.py subset_ac --output results_3/ &
python3 symexe.py subset_ad --output results_4/ &

# Merge results
cat results_*/aggregate.csv > combined_results.csv
```

---

## Output Analysis

### Reading JSON Results

```python
import json

# Load single result
with open('results/malware.exe.json') as f:
    result = json.load(f)

print(f"Binary: {result['binary_name']}")
print(f"Classification: {result['classification']}")
print(f"Score: {result['evasiveness_score']}/100")
print(f"States: {result['symbolic_execution_stats']['states_analyzed']}")
print(f"Paths: {result['symbolic_execution_stats']['paths_explored']}")
```

### Analyzing CSV Aggregate

```python
import pandas as pd
import matplotlib.pyplot as plt

# Load aggregate results
df = pd.read_csv('results/aggregate.csv')

# Basic statistics
print(f"Total samples: {len(df)}")
print(f"Evasive: {(df['evasiveness_score'] >= 40).sum()}")
print(f"Average score: {df['evasiveness_score'].mean():.1f}")

# Plot distribution
df['classification'].value_counts().plot(kind='bar')
plt.title('Evasiveness Distribution')
plt.show()

# Correlation analysis
print(df[['states_analyzed', 'paths_explored', 'evasiveness_score']].corr())
```

### Generate Summary Report

```bash
# Using Python
python3 -c "
import json, glob
from pathlib import Path

results = []
for f in glob.glob('results/*.json'):
    with open(f) as fp:
        results.append(json.load(fp))

evasive = sum(1 for r in results if r['is_evasive'])
avg_score = sum(r['evasiveness_score'] for r in results) / len(results)

print(f'Analyzed: {len(results)} samples')
print(f'Evasive: {evasive} ({evasive/len(results)*100:.1f}%)')
print(f'Average Score: {avg_score:.1f}/100')
"
```

---

## Advanced Usage

#### Initial Study (100 Samples)

```bash
# Paper-exact configuration
python3 symexe.py paper_samples_100/ \
    --max-states 2500 \
    --timeout 600 \
    --output paper_results/

# Runtime: ~60 minutes
# Avg per binary: ~36 seconds
```

#### Large-Scale Validation (638 Samples)

```bash
# Extended configuration
python3 symexe.py validation_samples_638/ \
    --max-states 2500 \
    --timeout 4500 \
    --output validation_results/

# Runtime: ~45-60 hours
# Avg per binary: ~75 minutes
```

### Representative Subset Analysis

```bash
# Select 150 representative samples
python3 select_representative_subset.py \
    samples_638/ \
    subset_150.json

# This creates:
#   subset_150.json (metadata)
#   subset_150_list.txt (file paths)

# Analyze subset
./run_subset_analysis.sh subset_150_list.txt subset_results/

# Runtime: ~75 hours
```

### Using Screen/Tmux for Long Runs

```bash
# Start screen session
screen -S symexe_analysis

# Activate environment and run
conda activate symexe
./run_subset_analysis.sh subset_150_list.txt results_150/

# Detach: Ctrl+A, then D
# Reattach later: screen -r symexe_analysis
```

### Memory-Constrained Systems

```bash
# Reduce max states for lower memory usage
python3 symexe.py malware.exe \
    --max-states 1500 \
    --timeout 600 \
    --output results.json

# Process samples one at a time
for sample in samples/*.exe; do
    python3 symexe.py "$sample" \
        --max-states 1500 \
        --timeout 600 \
        --output "results/$(basename $sample).json"
    
    # Optional: Add delay to prevent overheating
    sleep 10
done
```

---

## Troubleshooting

### Binary Not Loading

```bash
# Check if binary is valid PE
file malware.exe

# Expected: "PE32 executable"
# If not PE32, tool may not support it
```

### Timeout Issues

```bash
# If many binaries timeout, reduce timeout:
python3 symexe.py samples/ --timeout 300 --output results/

# Or increase for thorough analysis:
python3 symexe.py samples/ --timeout 7200 --output results/
```

### Memory Errors

```bash
# Reduce max states
python3 symexe.py malware.exe --max-states 1000 --output results.json

# Check available memory
free -h

# Close other applications
```

### Angr Import Errors

```bash
# Reinstall angr
pip uninstall angr claripy -y
pip install angr==9.2.181 --break-system-packages

# Verify installation
python3 -c "import angr; print(angr.__version__)"
# Should print: 9.2.181
```

### Permission Errors

```bash
# Make scripts executable
chmod +x run_subset_analysis.sh
chmod +x symexe.py

# Ensure output directory exists
mkdir -p results/
```

### Slow Performance

Common causes:
1. Packed binaries - Take full timeout (expected)
2. Large binaries - More code to analyze
3. Complex evasion - Path explosion (expected)

Solutions:
- Use representative subset instead of full dataset
- Reduce timeout for preliminary analysis
- Use parallel processing on multiple machines

---

## Best Practices

### For Quick Analysis

```bash
# Fast scan (300s timeout)
python3 symexe.py samples/ --timeout 300 --max-states 1000 --output quick_results/
```

### Full analysis

```bash
python3 symexe.py samples/ --timeout 600 --max-states 2500 --output paper_results/
```

### For Deep Dive

```bash
# Extended analysis (4500s timeout)
python3 symexe.py target.exe --timeout 4500 --max-states 2500 --output deep_analysis.json
```

---

## Example Workflow

### Complete Research Workflow

```bash
# 1. Setup environment
python3 -m venv symexe_env
source symexe_env/bin/activate
pip install -r requirements.txt

# 2. Verify installation
python3 symexe.py --help

# 3. Test on single sample
python3 symexe.py test_sample.exe --output test.json

# 4. Select representative subset
python3 select_representative_subset.py samples/ subset_150.json

# 5. Run batch analysis in screen
screen -S analysis
./run_subset_analysis.sh subset_150_list.txt results/
# Ctrl+A, D to detach

# 6. Monitor progress
screen -r analysis

# 7. Generate report
python3 analyze_results.py results/ > report.txt

# 8. Create visualizations
python3 visualize_results.py results/ figures/
