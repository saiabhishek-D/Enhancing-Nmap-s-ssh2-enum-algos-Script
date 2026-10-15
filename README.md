# Enhancing Nmap's `ssh2-enum-algos` Script

**Author:** Sai Abhishek  
**Institution:** Vellore Institute of Technology, Chennai  
**Course:** Cyber Security — Fall Semester 2026–2027

## Overview

This project enhances Nmap's existing `ssh2-enum-algos.nse` script to provide additional information about SSH server cryptographic configurations.

The original script enumerates the algorithms advertised by an SSH server, including key-exchange, host-key, encryption, message authentication code (MAC), and compression algorithms.

This project introduces two enhancements to extend its functionality.

## Project Enhancements

### 1. Terrapin Attack Assessment

**Script:** `ssh2-enum-algos-enhanced1.nse`

This enhancement adds a configuration-based assessment related to the Terrapin attack (CVE-2023-48795).

It examines advertised SSH algorithms and strict key exchange support to identify configurations that may indicate potential exposure. The output includes a result and a reason explaining the assessment.

**Features:**
- Retains the original algorithm enumeration functionality.
- Examines relevant encryption and MAC algorithm combinations.
- Checks for the strict key exchange marker.
- Displays an additional Terrapin assessment in the output.

**Note:** This is a preliminary configuration-based assessment, not definitive proof of vulnerability or safety.

### 2. Per-Algorithm Strength Grading

**Script:** `ssh2-enum-algos-enhanced2.nse`

This enhancement classifies individual algorithms according to predefined strength-grading rules.

The script evaluates the following categories:
- Key-exchange algorithms
- Host-key algorithms
- Encryption algorithms
- Message authentication code (MAC) algorithms

Each evaluated algorithm receives one of three labels:

| Classification | Meaning |
|---|---|
| `STRONG` | Classified as strong by the script's rules |
| `ACCEPTABLE` | Classified as acceptable by the script's rules |
| `WEAK` | Classified as weak by the script's rules |

The script also reports a final `least strength` value representing the lowest grade assigned among the evaluated algorithms. Compression algorithms are displayed but are not graded.

These classifications are based on the implemented rules and should be treated as an assessment aid rather than a complete security audit.

## Repository Contents

| File | Description |
|---|---|
| `ssh2-enum-algos.nse` | Original Nmap reference script |
| `ssh2-enum-algos-enhanced1.nse` | Terrapin assessment enhancement |
| `ssh2-enum-algos-enhanced2.nse` | Per-algorithm strength-grading enhancement |

## Requirements

- Nmap with Nmap Scripting Engine (NSE) support
- A system with the required Nmap SSH scripting libraries
- Access to an SSH service for testing
- Appropriate permissions to run the Nmap commands

## Installation and Usage

Clone the repository:

```bash
git clone https://github.com/saiabhishek-D/Enhancing-Nmap-s-ssh2-enum-algos-Script.git
cd Enhancing-Nmap-s-ssh2-enum-algos-Script
```

### Run Enhancement 1 — Terrapin Assessment

Against the local SSH service:

```bash
sudo nmap -p 22 -sV --script ./ssh2-enum-algos-enhanced1.nse -v 127.0.0.1
```

Against `scanme.nmap.org`:

```bash
sudo nmap -p 22 -sV --script ./ssh2-enum-algos-enhanced1.nse -v scanme.nmap.org
```

### Run Enhancement 2 — Strength Grading

Against the local SSH service:

```bash
sudo nmap -p 22 -sV --script ./ssh2-enum-algos-enhanced2.nse -v 127.0.0.1
```

Against `scanme.nmap.org`:

```bash
sudo nmap -p 22 -sV --script ./ssh2-enum-algos-enhanced2.nse -v scanme.nmap.org
```

The commands assume that the scripts are in the current directory and that SSH is accessible on port 22. Only test `scanme.nmap.org` within the scope of its published testing permissions.

## Testing

The enhanced scripts were tested against:

1. **Local SSH server (`127.0.0.1`)**
2. **Nmap's public test server (`scanme.nmap.org`)**

The first enhancement adds a Terrapin-related assessment to the algorithm enumeration results. The second enhancement adds strength labels and a summary of the lowest assigned grade.

The observed results depend on the algorithms advertised by each server at the time of testing.

## Limitations

- The Terrapin assessment uses advertised configuration indicators and does not establish vulnerability conclusively.
- Algorithm strength labels depend on the script's predefined classification rules.
- The `least strength` result summarizes the lowest assigned grade; it is not a complete measure of the server's overall security.
- The scripts focus on SSH algorithm analysis rather than a comprehensive security audit.

## Acknowledgements

I acknowledge the Nmap project and its contributors for the original `ssh2-enum-algos.nse` script and official documentation, which provided the foundation for this work.

I also thank my faculty for the opportunity to explore practical network security assessment through this project.

## References

- [Nmap Official Website](https://nmap.org/)
- [Nmap Scripting Engine Documentation](https://nmap.org/book/nse.html)
- [Official `ssh2-enum-algos.nse` Documentation](https://nmap.org/nsedoc/scripts/ssh2-enum-algos.html)
- [Terrapin Attack — CVE-2023-48795](https://nvd.nist.gov/vuln/detail/CVE-2023-48795)

---

*Academic cybersecurity project — Fall Semester 2026–2027.*
