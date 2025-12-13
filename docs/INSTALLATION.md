# Installation Guide

Complete installation instructions for SymExE on Linux, macOS, and Windows.

---

### Required
- Python 3.13.7
- pip (Python package manager)
- git
- 8GB RAM minimum (16GB+ recommended)
- 5GB free disk space

### Operating System
- Recommended: Linux (Ubuntu 20.04+, Kali Linux 2025.3)
- Supported: macOS 10.15+, Windows 10/11

---

## Installation Steps

### 1. Clone Repository

```bash
https://github.com/cs2researchlab/SymExE.git
cd SymExE
```

### 2. Create Virtual Environment

```bash
# Create virtual environment
python3 -m venv symexe_env

# Activate environment
# On Linux/macOS:
source symexe_env/bin/activate

# On Windows:
symexe_env\Scripts\activate
```

### 3. Install Dependencies

```bash
# Install all dependencies
pip install -r requirements.txt

# This will install:
# - angr==9.2.181
# - claripy==9.2.181
# - z3-solver
# - and all other dependencies
```

### 4. Verify Installation

```bash
# Check angr version
python3 -c "import angr; print(f'angr {angr.__version__}')"

# Expected output: angr 9.2.181

# Test SymExE
python3 symexe.py --help
```

---

## Platform-Specific Notes

### Linux (Ubuntu/Debian)

Install system dependencies:

```bash
sudo apt-get update
sudo apt-get install python3.13 python3.13-venv python3-pip build-essential
```

### macOS

Install Python 3.13:

```bash
brew install python@3.13
```

### Windows

1. Download Python 3.13.7 from [python.org](https://www.python.org/downloads/)
2. During installation, check "Add Python to PATH"
3. Open Command Prompt as Administrator
4. Follow installation steps above

---

## Troubleshooting

### Issue: "python3.13: command not found"

Solution.
```bash
# Use python3 instead
python3 -m venv symexe_env

# Or install Python 3.13
```

### Issue: pip install angr fails

Solution.
```bash
# On some systems, use --break-system-packages
pip install --break-system-packages angr==9.2.181

# Or upgrade pip first
pip install --upgrade pip
pip install angr==9.2.181
```

### Issue: Memory errors during installation

Solution.
```bash
# Install without cache
pip install --no-cache-dir angr==9.2.181
```

### Issue: z3-solver conflicts

Solution.
```bash
# Uninstall and reinstall
pip uninstall z3-solver
pip install z3-solver>=4.12.0.0
```

---

## Verification

After installation, run these tests.

```bash
# Test 1: Check Python version
python3 --version
# Should show: Python 3.13.7

# Test 2: Check angr
python3 -c "import angr; print('angr OK')"

# Test 3: Check SymExE
python3 symexe.py --help
# Should display help message

# Test 4: Check all imports
python3 -c "import angr, claripy, z3; print('All imports OK')"
```

---

## Docker Installation (Alternative)

For a containerized installation:

```bash
# Pull Docker image (if available)
docker pull [username]/symexe:latest

# Run container
docker run -it [username]/symexe:latest

# Or build from Dockerfile
docker build -t symexe .
```

Note: Dockerfile not yet available, but may be added in future releases.

---

## System Requirements

### Minimum
- CPU: 2 cores
- RAM: 8GB
- Storage: 5GB
- OS: Linux/macOS/Windows

### Recommended (from paper)
- CPU: 8+ cores (Intel i9 or equivalent)
- RAM: 16-48GB
- Storage: 20GB
- OS: Linux (Ubuntu 20.04+ or Kali Linux 2025.3)
