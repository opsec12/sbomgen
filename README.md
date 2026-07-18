# sbomgen

A zero-dependency CLI tool written in Go that generates a **Software Bill of Materials (SBOM)** for any project. Automatically detects dependency files across ecosystems and outputs industry-standard SPDX 2.3 or CycloneDX 1.4 JSON — or a clean text summary.

Optionally queries the [OSV vulnerability database](https://osv.dev) to flag known CVEs in your dependencies.

## Features

- **Multi-ecosystem** — Go, Python, Node.js (npm), Ruby
- **Industry-standard output** — SPDX 2.3 JSON, CycloneDX 1.4 JSON, or text table
- **Vulnerability scanning** — live OSV.dev batch query, no API key required
- **Auto-discovery** — finds all dependency files recursively in a project
- **CI/CD ready** — exits `1` when vulnerabilities are found
- **Zero dependencies** — standard library only, single binary

## Supported Ecosystems

| File | Ecosystem |
|------|-----------|
| `go.mod` | Go |
| `requirements.txt` | Python / PyPI |
| `Gemfile.lock` | Ruby / RubyGems |
| `package-lock.json` | Node.js / npm |
| `package.json` | Node.js / npm (fallback) |

## Installation

```bash
git clone https://github.com/opsec12/sbomgen
cd sbomgen
go build -o sbomgen .
```

Or install directly:

```bash
go install github.com/opsec12/sbomgen@latest
```

## Usage

```bash
# Scan current directory, text output
./sbomgen

# Scan a specific project
./sbomgen -path /path/to/project

# Include vulnerability check against osv.dev
./sbomgen -path . -vulns

# SPDX 2.3 JSON output
./sbomgen -path . -format spdx

# CycloneDX 1.4 JSON output
./sbomgen -path . -format cyclonedx

# Save SPDX to file
./sbomgen -path . -format spdx > sbom.spdx.json

# Named project
./sbomgen -path . -name "my-api-service" -format cyclonedx
```

## Example Output

```
Scanning: /home/user/myproject

sbomgen — SBOM Generator
──────────────────────────────────────────────────────────────────────

Detected dependency files:
  • go.mod
  • requirements.txt

// Go (12 packages)
PACKAGE                                       VERSION              VULNS
──────────────────────────────────────────────────────────────────────
github.com/gin-gonic/gin                      v1.9.1               ✓
golang.org/x/crypto                           v0.14.0              1 VULN(S)
  └─ GO-2023-2402 Timing sidechannel for P-256 on amd64
     https://osv.dev/vulnerability/GO-2023-2402

// PyPI (8 packages)
PACKAGE                                       VERSION              VULNS
──────────────────────────────────────────────────────────────────────
requests                                      2.28.0               ✓
flask                                         2.2.0                ✓

──────────────────────────────────────────────────────────────────────
Total packages: 20   Vulnerabilities: 1
Generated in 342ms
```

## CI/CD Integration

### GitHub Actions

```yaml
name: SBOM + Vulnerability Check
on: [push, pull_request]

jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.21'
      - name: Install sbomgen
        run: go install github.com/opsec12/sbomgen@latest
      - name: Generate SBOM
        run: sbomgen -path . -format spdx > sbom.spdx.json
      - name: Upload SBOM artifact
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: sbom.spdx.json
      - name: Check for vulnerabilities
        run: sbomgen -path . -vulns
```

### Pre-release Check

```bash
#!/bin/bash
echo "Running pre-release SBOM check..."
sbomgen -path . -vulns -format cyclonedx > sbom.cdx.json
if [ $? -ne 0 ]; then
  echo "Vulnerable dependencies detected. Release blocked."
  exit 1
fi
echo "SBOM clean. Proceeding with release."
```

## Output Formats

### SPDX 2.3 JSON
Industry-standard format used by GitHub, NTIA, and US government supply chain requirements.

### CycloneDX 1.4 JSON
OWASP standard used by many enterprise security tools and Dependency-Track.

### Text
Human-readable table for local development and quick audits.

## License

MIT — Eric Fong (github.com/opsec12)
