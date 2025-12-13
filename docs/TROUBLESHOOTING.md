# Troubleshooting Guide

Common issues and solutions for SymExE.

---

## Installation Issues

### Python Version Not Found

Problem.
```
python3.13 command not found
```

Solutions.

1. Check installed Python versions.
```bash
python3 --version
```

2. Use available Python 3.x.
```bash
python3 -m venv symexe_env
```

3. Install Python 3.13.
```bash
# Ubuntu/Debian
sudo apt-get install python3.13

# macOS
brew install python@3.13
```

---

### angr Installation Fails

Problem.
```
ERROR Could not install packages due to an OSError
```

Solutions.

1. Upgrade pip first.
```bash
pip install --upgrade pip
pip install angr==9.2.181
```

2. Use --break-system-packages (Linux).
```bash
pip install --break-system-packages angr==9.2.181
```

3. Install without cache.
```bash
pip install --no-cache-dir angr==9.2.181
```

---

### Memory Errors During Installation

Problem.
```
MemoryError: Unable to allocate...
```

Solutions.

1. Install without cache:
```bash
pip install --no-cache-dir -r requirements.txt
```

2. Install packages one at a time.
```bash
pip install angr==9.2.181
pip install claripy==9.2.181
pip install z3-solver
```

3. Increase swap space (Linux).
```bash
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

---

### z3-solver Conflicts

Problem.
```
ERROR Cannot uninstall 'z3-solver'
```

Solutions.

1. Force uninstall.
```bash
pip uninstall -y z3-solver
pip install z3-solver>=4.12.0.0
```

2. Use virtual environment (recommended).
```bash
python3 -m venv fresh_env
source fresh_env/bin/activate
pip install -r requirements.txt
```

---

## Runtime Issues

### Binary Not Loading

Problem.
```
ERROR Failed to load binary
```

Solutions.

1. Check file exists:
```bash
ls -lh malware.exe
file malware.exe
```

2. Verify it's a PE32 executable:
```bash
file malware.exe
# Should show: PE32 executable
```

3. Check permissions.
```bash
chmod +r malware.exe
```

---

### Timeout on Every Binary

Problem.
All binaries hit the 600-second timeout.

Solutions.

1. Reduce max states.
```bash
python3 symexe.py malware.exe --max-states 1000 --timeout 600
```

2. Reduce timeout for testing.
```bash
python3 symexe.py malware.exe --timeout 300
```

3. Check system resources.
```bash
free -h  # Check available memory
top      # Check CPU usage
```

---

### Memory Errors During Analysis

Problem.
```
MemoryError: Cannot allocate memory
```

Solutions.

1. Reduce max states:
```bash
python3 symexe.py malware.exe --max-states 1500
```

2. Close other applications

3. Analyze binaries one at a time instead of batch

4. Use a system with more RAM (16GB+ recommended)

---

### No Evasion Indicators Found

Problem.
All binaries show 0 evasion indicators.

Solutions.

1. Check if binary is actually evasive malware (not benign software)

2. Verify angr loaded correctly.
```bash
python3 -c "import angr; print('OK')"
```

3. Check verbose output.
```bash
python3 symexe.py malware.exe --verbose
```

4. Inspect binary manually.
```bash
strings malware.exe | grep -i "debug\|vmware\|vbox"
```

---

### JSON Output Empty

Problem.
Output JSON file is empty or missing fields.

Solutions.

1. Check if analysis completed:
```bash
# Look for success message
python3 symexe.py malware.exe -o test.json
```

2. Check for errors in output.
```bash
python3 symexe.py malware.exe -o test.json 2>&1 | tee error.log
```

3. Verify output directory exists.
```bash
mkdir -p results/
python3 symexe.py malware.exe -o results/test.json
```

---

## Performance Issues

### Analysis Very Slow

Problem.
Analysis takes much longer than expected.

Solutions.

1. Check system specs meet minimum requirements:
   - 8GB+ RAM
   - Multi-core CPU
   - SSD storage

2. Reduce timeout.
```bash
python3 symexe.py malware.exe --timeout 300
```

3. Use representative subset instead of full dataset:
```bash
python3 select_representative_subset.py samples/ subset.json
```

---

### Disk Space Full

Problem.
```
No space left on device
```

Solutions.

1. Check disk space.
```bash
df -h
```

2. Clean temporary files.
```bash
rm -rf /tmp/angr_*
```

3. Remove old results.
```bash
rm -rf results_old/
```

---

## Platform-Specific Issues

### Windows: pip not recognized

Solution.
```cmd
python -m pip install -r requirements.txt
```

### Windows: Permission Denied

Solution.
Run Command Prompt as Administrator

### macOS: SSL Certificate Error

Solution.
```bash
/Applications/Python\ 3.13/Install\ Certificates.command
```

### Linux: externally-managed-environment

Solution.
```bash
# Use virtual environment (recommended)
python3 -m venv symexe_env
source symexe_env/bin/activate

# OR use --break-system-packages
pip install --break-system-packages -r requirements.txt
```

---

## Import Errors

### No module named 'angr'

Solution.
```bash
# Verify virtual environment is activated
which python3
# Should show path to venv

# Reinstall angr
pip install angr==9.2.181
```

### No module named 'claripy'

Solution.
```bash
pip install claripy==9.2.181
```

### No module named 'z3'

Solution.
```bash
pip install z3-solver>=4.12.0.0
```

---

## Output Issues

### CSV File Not Generated

Problem.
JSON files created but no CSV aggregate.

Solution.
CSV is only generated for batch analysis.
```bash
# Single binary - no CSV
python3 symexe.py binary.exe -o result.json

# Batch analysis - creates CSV
python3 symexe.py samples/ -o results/
```

---

### Cannot Read JSON Output

Problem.
```
JSONDecodeError: Expecting value
```

Solution.
```bash
# Check if file is valid JSON
python3 -m json.tool result.json

# If corrupted, re-run analysis
python3 symexe.py malware.exe -o result_new.json
```

---

## Advanced Debugging

### Enable Verbose Mode

```bash
python3 symexe.py malware.exe --verbose -o test.json
```

### Check angr Version

```bash
python3 -c "import angr; print(angr.__version__)"
# Should print: 9.2.181
```

### Test on Simple Binary

```bash
# Test with /bin/ls (if analyzing Linux in future)
# Or test with known benign Windows PE32
```

### Enable angr Logging

```python
import angr
import logging
logging.getLogger('angr').setLevel(logging.DEBUG)
```

---

## Getting Help

If your issue isn't listed here.

1. Check GitHub Issues: Search existing issues
2. Open New Issue: Provide:
   - Error message (full output)
   - OS and Python version
   - angr version
   - Steps to reproduce

---

## Common Error Messages

| Error | Meaning | Solution |
|-------|---------|----------|
| `ImportError: No module named 'angr'` | angr not installed | `pip install angr==9.2.181` |
| `FileNotFoundError` | Binary not found | Check file path |
| `MemoryError` | Out of RAM | Reduce max_states or add RAM |
| `TimeoutError` | Analysis exceeded limit | This is normal for evasive binaries |
| `PermissionError` | Cannot read/write file | Check file permissions |

---

Last updated: December 12, 2025
