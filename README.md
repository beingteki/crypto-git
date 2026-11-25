# CryptoBench - revised benchmark analysis package

This package contains the corrected benchmark source, the corrected Mac and Kali benchmark captures, host and guest environment records, the analysis scripts, result tables, figures and report. The attached Kali CSV and environment record and the Mac outputs are preserved byte for byte in their corresponding run directories. The `environment.txt` files describe these runs. The other hardware and backend files are supporting environment captures.

## Verified environments

### Environment 1 - MacBook Pro M3 Pro

- macOS 27.2.1, ARM64
- Apple M3 Pro
- **11 physical CPU cores and 11 logical CPUs**, separately confirmed with `sysctl -n hw.physicalcpu` and `sysctl -n hw.logicalcpu`
- 18.00 GiB visible to the environment collector
- Python 3.14.7; pyca/cryptography 50.0.2
- cryptography backend OpenSSL 4.0.3 (29 Sep 2026)
- Python's separate standard-library `ssl` module OpenSSL 3.6.1 (27 Jan 2026)

### Environment 2 - Kali Linux VM on Windows host

**Physical Windows host:**

- ASUS VivoBook X415EA
- Windows 11 Home Single Language, build 10.0.26300, 64-bit
- Intel Core i3-1115G4 @ 3.00 GHz, 2 physical cores / 4 logical processors
- 19.7 GiB RAM as reported by the supplied PowerShell capture
- Oracle VirtualBox host application 7.2.20r175154

**Kali Linux guest:**

- Kali Linux kernel 6.19.14+kali-amd64, x86_64
- Guest-visible Intel Core i3-1115G4; 2 vCPUs / 2 logical CPUs
- 4096 MB configured memory, confirmed by VirtualBox Manager and VBoxManage. Kali reports 3.83 GiB visible RAM.
- Python 3.14.7; pyca/cryptography 50.0.2
- cryptography backend OpenSSL 4.0.3 (29 Sep 2026)
- Python's separate standard-library `ssl` module OpenSSL 3.6.2 (7 Apr 2026)

The Kali guest's DMI and `systemd-detect-virt` identify Oracle VirtualBox. `lscpu` additionally prints `KVM` in its guest-visible hypervisor-vendor field. The package preserves both observations and identifies the host-side platform from the Windows capture. See `results/run-2/guest_hardware.txt` and `windows_host_hardware.txt`.

**OpenSSL distinction:** report `cryptography backend OpenSSL` as 4.0.3 in both environments. The Python `ssl` module values (3.6.1 and 3.6.2) are separate and must not be substituted for the cryptography backend version.

## Python setup for analysis/report generation

The benchmark was captured using Python 3.14.7 and `cryptography==50.0.2`. To recreate the analysis/report tooling environment:

```bash
python3.14 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

On Windows PowerShell, activate with `.venv\Scripts\Activate.ps1`.

## Reproduce the report from both recorded runs

From the project directory, run:

```bash
python build_report.py
```

This command reads both captured datasets, validates the exact 83 operation groups and run numbering per environment, recomputes six result tables, six plots, the 83 cross-environment ratios and the validation summary, and builds `reports/CryptoBench_Report.docx`. It retains run 0 in the source files and excludes it from statistics. The CSV contains a blank Message bytes field for cross-environment comparisons where message size does not apply.

The accompanying PDF is an export of that Word document. To rebuild with the verified student identity and repository URL:

```bash
python build_report.py --student-name "Full Name" --student-id "Student ID" --repository-url "Repository URL"
```

## Capture fresh measurements

Run the same benchmark command once per environment with a fresh directory. One invocation records all 83 groups on the machine where it runs.

```bash
python my_project.py results/repeat-run-1
python my_project.py results/repeat-run-2
```

Write new measurements to fresh directories. The supplied Word discussion describes the two packaged captures. Use `python analyse_results.py` to calculate results for replacement captures and update the discussion before rebuilding the report. The report builder checks the packaged raw-file hashes to prevent the discussion from being paired with different measurements.
