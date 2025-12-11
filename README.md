# SymExE - Symbolic Execution for Evasive Malware

 Characterizing Symbolic Execution Behavior on Evasive Malware: A Large-Scale Analysis

Authors:
- Rachel Soubier (rcs2002@uncw.edu)
- Shahid Ali (sal9310@uncw.edu)
- Dr. Ajay Kumara Makanahalli Annaiah (makanahalliannaiaha@uncw.edu)

Institution: Department of Computer Science, University of North Carolina Wilmington

---

## Overview

SymExE is a symbolic execution framework built on angr designed to analyze how evasive malware impacts symbolic execution engines. Unlike traditional malware analysis tools, SymExE characterizes execution behavior to understand how anti-analysis techniques stress symbolic execution systems.

### Key Research Contributions

1. First empirical study of symbolic execution on solely real evasive malware  
2. Novel characterization of how evasion affects SE performance
3. Comprehensive metrics (states, paths, constraints, coverage, time)
4. Key finding: Size does not equal complexity (no correlation between binary size and SE difficulty)
5. Open-source framework for reproducibility

---

## Research Findings

Analysis of 100 evasive malware samples revealed:
----------------------------------------------------------------------------|
| Metric           | Finding                                                |
|------------------|--------------------------------------------------------|
| Dataset          | 100 PE32 Windows executables (0-500KB)                 |
| Malware Families | 10 families (Emotet, TrickBot, Zeus, etc.)             |
| Key Discovery    | No correlation between binary size and SE difficulty   |
| Primary Factor   | Structural complexity and evasive logic drive SE strain|
| Average Runtime  | ~36 seconds per binary (600s timeout)                  |
| Total Runtime    | ~60 minutes for 100 samples                            |
----------------------------------------------------------------------------|
Key Insight: Evasive tactics (obfuscation, environmental checks, complex branching) are the primary drivers of the difficulty of symbolic execution, not binary size.


### Evasion Detection

- Anti-Debug (23 indicators): IsDebuggerPresent, RDTSC, INT3
- Anti-VM (27 indicators): CPUID, registry checks, system metrics
- Sandbox Evasion (24 indicators): Sleep delays, user interaction checks
- Process Injection (15 patterns): CreateRemoteThread, process hollowing
- SE-Specific: Path explosion, constraint complexity

### Performance Metrics

- States analyzed, paths explored, constraints solved
- Code coverage, execution time, memory usage
- States-to-paths ratio (evasion effectiveness)

### Classification

- Highly Evasive (70-100)
- Moderately Evasive (40-69)
- Minimally Evasive (10-39)
- Non-Evasive (0-9)

## Quick Start

### Installation

```bash
git clone https://github.com/[username]/SymExE.git
cd SymExE

conda create -n symexe python=3.13
conda activate symexe
pip install -r requirements.txt
```

### Usage

```bash
# Single binary (paper configuration)
python3 symexe.py malware.exe --output results.json

# Paper-exact configuration (explicit)
python3 symexe.py malware.exe \
    --max-states 2500 \
    --timeout 600 \
    --output results.json

# Batch analysis (100 samples)
python3 symexe.py samples/ --output results/
```

## Dataset

100 evasive malware samples from VXUnderground:

10 Malware Families Analyzed:
- Emotet, TrickBot, Zeus, AgentTesla, Qakbot
- Dridex, LokiBot, AZORult, ZLoader, IcedID

Size Groups (for visualization):
- 0-100 KB, 100-200 KB, 200-300 KB, 300-400 KB, 400-500 KB

Total: 100 PE32 Windows executables

---

## Configuration

Paper Configuration:
- Dataset: 100 samples
- Max States: 2500
- Timeout: 600s (10 minutes)
- Runtime: ~60 minutes total
- Average: ~36 seconds per binary

For Extended Analysis:
- Increase timeout: --timeout 4500 (75 minutes)
- For larger datasets or deeper exploration

---


---

## Contact

- Rachel Soubier: rcs2002@uncw.edu
- Dr. Ajay Kumara: makanahalliannaiaha@uncw.edu

University of North Carolina Wilmington  
Department of Computer Science

---

## Acknowledgments

Built on angr • Dataset from VXUnderground

---

Last Updated: December 11, 2025 • Version: 1.0.0
