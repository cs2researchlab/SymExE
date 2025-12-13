# Frequently Asked Questions (FAQ)

Common questions about SymExE and the research.

---

## General Questions

### What is SymExE?

SymExE is a symbolic execution framework for analyzing how evasive malware affects symbolic execution systems. It's built on angr and designed for research purposes.

### Who created SymExE?

SymExE was developed by Rachel Soubier, Shahid Ali, and Dr. Ajay Kumara Makanahalli Annaiah at the University of North Carolina Wilmington.

### Is SymExE open source?

Yes! SymExE is released under the MIT License and available on GitHub for academic and research use.

---

## Research Questions

### How many samples were analyzed?

The paper analyzed 100 evasive malware samples from 10 different malware families.

### What was the main finding?

The key finding is that binary size does NOT correlate with symbolic execution difficulty. Structural complexity and evasive logic are the primary drivers, not file size.

### What malware families were studied?

Emotet, TrickBot, Zeus, AgentTesla, Qakbot, Dridex, LokiBot, AZORult, ZLoader, and IcedID.

---

## Technical Questions

### What version of Python is required?

Python 3.13.7 (as specified in the paper)

### What version of angr is used?

angr 9.2.181 with the Z3 SMT solver

### How long does analysis take?

- Average: ~36 seconds per binary
- Total for 100 samples: ~60 minutes
- Timeout: 600 seconds (10 minutes) per binary

### What configuration is used?

- Max states: 2500
- Timeout: 600 seconds
- Engine: angr 9.2.181
- Solver: Z3 (BackendZ3)

---

## Usage Questions

### Can I analyze my own binaries?

Yes! SymExE can analyze any PE32 Windows executable. However, it's designed for evasive malware analysis.

### Does it work on Linux binaries?

Currently no. SymExE is designed for Windows PE32 executables only.

### Can I change the timeout?

Yes! Use `--timeout` flag.
```bash
python3 symexe.py malware.exe --timeout 4500
```

### How do I analyze multiple binaries?

```bash
python3 symexe.py samples_directory/ --output results/
```

---

## Output Questions

### What format are the results?

Results are provided in two formats.
- JSON. Individual results per binary
- CSV. Aggregate results for all binaries

### What metrics are collected?

- States analyzed
- Paths explored
- Constraints solved
- Execution time
- Code coverage
- Evasion indicator counts
- States-to-paths ratio

### What does evasiveness score mean?

A 0-100 score measuring how evasive the binary is
- 70-100: Highly Evasive
- 40-69: Moderately Evasive
- 10-39: Minimally Evasive
- 0-9: Non-Evasive

---

## Troubleshooting Questions

### Why does installation fail?

See [INSTALLATION.md](INSTALLATION.md) and [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for platform-specific solutions.

### Why does my binary timeout?

Highly evasive binaries may use the full 600-second timeout. This is expected behavior for binaries with complex evasion techniques.

### Why are some metrics zero?

Some binaries may not trigger certain metrics (e.g., if symbolic execution can't proceed far, paths explored may be low).

---

## Academic Questions


### Can I use this for my research?

Yes! SymExE is open source (MIT License) and designed for academic research.

### Where can I get the malware samples?

The samples were obtained from VXUnderground. We cannot distribute malware samples directly for safety and legal reasons.

### Can I reproduce the results?

Yes! All code is available on GitHub with exact versions specified in requirements.txt.

---

## Safety Questions

### Is it safe to run SymExE?

SymExE performs STATIC and SYMBOLIC analysis - it does not actually EXECUTE the malware. However, always analyze malware in isolated environments (VMs).

### Should I use a virtual machine?

Yes! Always analyze malware in isolated virtual machines, not on your host system.

### Does it detect all malware?

No. SymExE is designed to CHARACTERIZE evasive behavior, not detect all malware. It's a research tool, not an antivirus.

---

## Feature Questions

### Does it support ARM binaries?

Not currently. Only x86 PE32 Windows executables are supported.

### Can it analyze packed binaries?

Yes, but packing may limit static analysis results. Symbolic execution still proceeds.

### Does it detect new/unknown evasion?

It detects known evasion patterns (APIs, instructions) and also measures SE impact (path explosion, constraint complexity), which can indicate unknown evasion.

---

## Future Work

### Will there be updates?

This is a research tool released alongside the IEEE CCWC 2026 paper. Updates depend on research needs and community interest.

### Can I contribute?

Contributions are welcome! See the GitHub repository for contribution guidelines.

### What features are planned?

Potential future features:
- Support for Linux ELF binaries
- Automated unpacking
- Machine learning integration
- Extended malware family coverage

---

## Contact

For questions not answered here:
- Check [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
- Open a GitHub issue
- Email: rcs2002@uncw.edu
- Email: sal9310@uncw.edu

---

Last updated: December 12, 2025
