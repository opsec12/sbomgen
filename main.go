// sbomgen — Software Bill of Materials Generator
// Scans a project directory, detects dependency files across ecosystems,
// and generates an SBOM in SPDX 2.3, CycloneDX 1.4, or text format.
// Optionally queries osv.dev to flag known vulnerabilities.
//
// Author: Eric Fong (github.com/opsec12)

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ─── ANSI colors ─────────────────────────────────────────────────────────────

const (
	colorReset  = "\033[0m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorRed    = "\033[31m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"
	colorBold   = "\033[1m"
)

// ─── Data model ──────────────────────────────────────────────────────────────

type Package struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
	Source    string `json:"source_file"`
	Vulns     []Vuln `json:"vulnerabilities,omitempty"`
}

type Vuln struct {
	ID       string `json:"id"`
	Summary  string `json:"summary"`
	Severity string `json:"severity"`
	URL      string `json:"url"`
}

// ─── Parsers ─────────────────────────────────────────────────────────────────

// go.mod
func parseGoMod(path string) ([]Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pkgs []Package
	inRequire := false
	scanner := bufio.NewScanner(f)
	re := regexp.MustCompile(`^\s+([^\s]+)\s+([^\s]+)`)

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "require (") {
			inRequire = true
			continue
		}
		if inRequire && trimmed == ")" {
			inRequire = false
			continue
		}
		if strings.HasPrefix(trimmed, "require ") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 3 {
				pkgs = append(pkgs, Package{
					Name: parts[1], Version: strings.TrimSuffix(parts[2], " // indirect"),
					Ecosystem: "Go", Source: filepath.Base(path),
				})
			}
			continue
		}
		if inRequire {
			m := re.FindStringSubmatch(line)
			if len(m) >= 3 {
				pkgs = append(pkgs, Package{
					Name: m[1], Version: strings.TrimSuffix(m[2], " // indirect"),
					Ecosystem: "Go", Source: filepath.Base(path),
				})
			}
		}
	}
	return pkgs, scanner.Err()
}

// requirements.txt (Python)
func parseRequirementsTxt(path string) ([]Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pkgs []Package
	re := regexp.MustCompile(`^([A-Za-z0-9_\-\.]+)\s*([=~!<>]+)\s*([^\s#;]+)`)
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		m := re.FindStringSubmatch(line)
		if len(m) >= 4 {
			pkgs = append(pkgs, Package{
				Name: m[1], Version: m[3],
				Ecosystem: "PyPI", Source: filepath.Base(path),
			})
		} else {
			// Package with no version pin
			name := strings.Fields(line)[0]
			pkgs = append(pkgs, Package{
				Name: name, Version: "UNPINNED",
				Ecosystem: "PyPI", Source: filepath.Base(path),
			})
		}
	}
	return pkgs, scanner.Err()
}

// Gemfile.lock (Ruby)
func parseGemfileLock(path string) ([]Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pkgs []Package
	re := regexp.MustCompile(`^\s{4}([a-zA-Z0-9_\-]+)\s+\(([^)]+)\)`)
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		m := re.FindStringSubmatch(scanner.Text())
		if len(m) >= 3 {
			pkgs = append(pkgs, Package{
				Name: m[1], Version: m[2],
				Ecosystem: "RubyGems", Source: filepath.Base(path),
			})
		}
	}
	return pkgs, scanner.Err()
}

// package-lock.json (Node.js) — reads "packages" block from v2/v3 lockfile
func parsePackageLockJSON(path string) ([]Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var raw struct {
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}

	if err := json.NewDecoder(f).Decode(&raw); err != nil {
		return nil, err
	}

	var pkgs []Package

	// v2/v3 format
	for name, info := range raw.Packages {
		if name == "" || strings.HasPrefix(name, "node_modules/") {
			clean := strings.TrimPrefix(name, "node_modules/")
			if clean == "" {
				continue
			}
			pkgs = append(pkgs, Package{
				Name: clean, Version: info.Version,
				Ecosystem: "npm", Source: filepath.Base(path),
			})
		}
	}

	// v1 fallback
	if len(pkgs) == 0 {
		for name, info := range raw.Dependencies {
			pkgs = append(pkgs, Package{
				Name: name, Version: info.Version,
				Ecosystem: "npm", Source: filepath.Base(path),
			})
		}
	}

	return pkgs, nil
}

// package.json — only direct dependencies (no lock file present)
func parsePackageJSON(path string) ([]Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var raw struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}

	if err := json.NewDecoder(f).Decode(&raw); err != nil {
		return nil, err
	}

	var pkgs []Package
	for name, ver := range raw.Dependencies {
		pkgs = append(pkgs, Package{Name: name, Version: ver, Ecosystem: "npm", Source: "package.json"})
	}
	for name, ver := range raw.DevDependencies {
		pkgs = append(pkgs, Package{Name: name, Version: ver + " (dev)", Ecosystem: "npm", Source: "package.json"})
	}
	return pkgs, nil
}

// ─── Discovery ───────────────────────────────────────────────────────────────

type depFile struct {
	filename string
	parser   func(string) ([]Package, error)
}

var depFiles = []depFile{
	{"go.mod", parseGoMod},
	{"requirements.txt", parseRequirementsTxt},
	{"Gemfile.lock", parseGemfileLock},
	{"package-lock.json", parsePackageLockJSON},
	{"package.json", parsePackageJSON},
}

func discover(root string) ([]Package, []string, error) {
	var all []Package
	var found []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			if info != nil && info.IsDir() {
				skip := map[string]bool{
					"node_modules": true, "vendor": true, ".git": true,
					"dist": true, "build": true, ".terraform": true,
				}
				if skip[info.Name()] {
					return filepath.SkipDir
				}
			}
			return nil
		}

		for _, df := range depFiles {
			if info.Name() == df.filename {
				// Skip package.json if package-lock.json exists alongside
				if df.filename == "package.json" {
					lockPath := filepath.Join(filepath.Dir(path), "package-lock.json")
					if _, err := os.Stat(lockPath); err == nil {
						return nil
					}
				}
				pkgs, err := df.parser(path)
				if err == nil && len(pkgs) > 0 {
					rel, _ := filepath.Rel(root, path)
					found = append(found, rel)
					all = append(all, pkgs...)
				}
			}
		}
		return nil
	})

	return all, found, err
}

// ─── OSV vulnerability check ─────────────────────────────────────────────────

type osvQuery struct {
	Queries []osvPackage `json:"queries"`
}

type osvPackage struct {
	Version string      `json:"version"`
	Package osvPkgInner `json:"package"`
}

type osvPkgInner struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvResponse struct {
	Results []struct {
		Vulns []struct {
			ID       string `json:"id"`
			Summary  string `json:"summary"`
			Aliases  []string `json:"aliases"`
			Severity []struct {
				Type  string `json:"type"`
				Score string `json:"score"`
			} `json:"severity"`
		} `json:"vulns"`
	} `json:"results"`
}

func checkOSV(pkgs []Package) ([]Package, error) {
	// Build batch query (OSV supports up to 1000 per request)
	batchSize := 100
	updated := make([]Package, len(pkgs))
	copy(updated, pkgs)

	for i := 0; i < len(pkgs); i += batchSize {
		end := i + batchSize
		if end > len(pkgs) {
			end = len(pkgs)
		}
		batch := pkgs[i:end]

		query := osvQuery{}
		for _, p := range batch {
			if p.Version == "UNPINNED" || p.Version == "" {
				continue
			}
			eco := p.Ecosystem
			// OSV ecosystem names
			switch eco {
			case "PyPI":
				eco = "PyPI"
			case "RubyGems":
				eco = "RubyGems"
			case "npm":
				eco = "npm"
			case "Go":
				eco = "Go"
			}
			query.Queries = append(query.Queries, osvPackage{
				Version: p.Version,
				Package: osvPkgInner{Name: p.Name, Ecosystem: eco},
			})
		}

		if len(query.Queries) == 0 {
			continue
		}

		body, err := json.Marshal(query)
		if err != nil {
			continue
		}

		client := &http.Client{Timeout: 15 * time.Second}
		resp, err := client.Post("https://api.osv.dev/v1/querybatch", "application/json", bytes.NewReader(body))
		if err != nil {
			return updated, fmt.Errorf("OSV API error: %w", err)
		}
		defer resp.Body.Close()

		respBody, _ := io.ReadAll(resp.Body)
		var osvResp osvResponse
		if err := json.Unmarshal(respBody, &osvResp); err != nil {
			continue
		}

		qi := 0
		for pi := i; pi < end; pi++ {
			if updated[pi].Version == "UNPINNED" || updated[pi].Version == "" {
				continue
			}
			if qi >= len(osvResp.Results) {
				break
			}
			for _, v := range osvResp.Results[qi].Vulns {
				sev := "UNKNOWN"
				if len(v.Severity) > 0 {
					sev = v.Severity[0].Score
				}
				updated[pi].Vulns = append(updated[pi].Vulns, Vuln{
					ID:       v.ID,
					Summary:  v.Summary,
					Severity: sev,
					URL:      "https://osv.dev/vulnerability/" + v.ID,
				})
			}
			qi++
		}
	}

	return updated, nil
}

// ─── Output formats ──────────────────────────────────────────────────────────

// SPDX 2.3 JSON
func outputSPDX(pkgs []Package, projectName string) {
	type spdxPkg struct {
		SPDXID           string `json:"SPDXID"`
		Name             string `json:"name"`
		VersionInfo      string `json:"versionInfo"`
		DownloadLocation string `json:"downloadLocation"`
		FilesAnalyzed    bool   `json:"filesAnalyzed"`
		Supplier         string `json:"supplier,omitempty"`
	}
	type spdxDoc struct {
		SPDXVersion      string    `json:"spdxVersion"`
		DataLicense      string    `json:"dataLicense"`
		SPDXID           string    `json:"SPDXID"`
		Name             string    `json:"name"`
		DocumentNamespace string   `json:"documentNamespace"`
		Created          string    `json:"created"`
		CreatorTool      string    `json:"creatorTool"`
		Packages         []spdxPkg `json:"packages"`
	}

	doc := spdxDoc{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              projectName,
		DocumentNamespace: fmt.Sprintf("https://github.com/opsec12/sbomgen/%s-%d", projectName, time.Now().Unix()),
		Created:           time.Now().UTC().Format(time.RFC3339),
		CreatorTool:       "sbomgen (github.com/opsec12/sbomgen)",
	}

	for i, p := range pkgs {
		doc.Packages = append(doc.Packages, spdxPkg{
			SPDXID:           fmt.Sprintf("SPDXRef-Package-%d", i+1),
			Name:             p.Name,
			VersionInfo:      p.Version,
			DownloadLocation: "NOASSERTION",
			FilesAnalyzed:    false,
		})
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(doc)
}

// CycloneDX 1.4 JSON
func outputCycloneDX(pkgs []Package, projectName string) {
	type cdxComponent struct {
		Type    string `json:"type"`
		Name    string `json:"name"`
		Version string `json:"version"`
		PURL    string `json:"purl,omitempty"`
	}
	type cdxDoc struct {
		BOMFormat   string         `json:"bomFormat"`
		SpecVersion string         `json:"specVersion"`
		Version     int            `json:"version"`
		Metadata    map[string]any `json:"metadata"`
		Components  []cdxComponent `json:"components"`
	}

	doc := cdxDoc{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.4",
		Version:     1,
		Metadata: map[string]any{
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"tools":     []map[string]string{{"name": "sbomgen", "version": "1.0.0"}},
		},
	}

	ecoToPURL := map[string]string{
		"Go": "golang", "PyPI": "pypi", "npm": "npm", "RubyGems": "gem",
	}

	for _, p := range pkgs {
		purl := ""
		if prefix, ok := ecoToPURL[p.Ecosystem]; ok {
			purl = fmt.Sprintf("pkg:%s/%s@%s", prefix, p.Name, p.Version)
		}
		doc.Components = append(doc.Components, cdxComponent{
			Type: "library", Name: p.Name, Version: p.Version, PURL: purl,
		})
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(doc)
}

// Text table
func outputText(pkgs []Package, sources []string, elapsed time.Duration) {
	fmt.Printf("\n%s%s sbomgen — SBOM Generator%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%s%s%s\n\n", colorGray, strings.Repeat("─", 70), colorReset)

	fmt.Printf("%sDetected dependency files:%s\n", colorGray, colorReset)
	for _, s := range sources {
		fmt.Printf("  %s•%s %s\n", colorGreen, colorReset, s)
	}
	fmt.Println()

	// Group by ecosystem
	byEco := map[string][]Package{}
	for _, p := range pkgs {
		byEco[p.Ecosystem] = append(byEco[p.Ecosystem], p)
	}

	totalVulns := 0
	for eco, epkgs := range byEco {
		fmt.Printf("%s%s // %s (%d packages)%s\n", colorBold, colorCyan, eco, len(epkgs), colorReset)
		fmt.Printf("%s%-45s %-20s %s%s\n", colorGray, "PACKAGE", "VERSION", "VULNS", colorReset)
		fmt.Printf("%s%s%s\n", colorGray, strings.Repeat("─", 70), colorReset)

		for _, p := range epkgs {
			vulnStr := ""
			if len(p.Vulns) > 0 {
				vulnStr = fmt.Sprintf("%s%d VULN(S)%s", colorRed, len(p.Vulns), colorReset)
				totalVulns += len(p.Vulns)
			} else {
				vulnStr = fmt.Sprintf("%s✓%s", colorGreen, colorReset)
			}
			name := p.Name
			if len(name) > 43 {
				name = name[:40] + "..."
			}
			fmt.Printf("%-45s %-20s %s\n", name, p.Version, vulnStr)

			for _, v := range p.Vulns {
				fmt.Printf("  %s└─ %s%s %s\n", colorRed, v.ID, colorReset, v.Summary)
				fmt.Printf("     %s%s%s\n", colorGray, v.URL, colorReset)
			}
		}
		fmt.Println()
	}

	fmt.Printf("%s%s%s\n", colorGray, strings.Repeat("─", 70), colorReset)
	fmt.Printf("Total packages: %s%d%s   Vulnerabilities: ", colorBold, len(pkgs), colorReset)
	if totalVulns > 0 {
		fmt.Printf("%s%d%s\n", colorRed, totalVulns, colorReset)
	} else {
		fmt.Printf("%s0%s\n", colorGreen, colorReset)
	}
	fmt.Printf("Generated in %s\n\n", elapsed.Round(time.Millisecond))
}

// ─── Main ────────────────────────────────────────────────────────────────────

func main() {
	path := flag.String("path", ".", "Project directory to scan")
	format := flag.String("format", "text", "Output format: text | spdx | cyclonedx")
	checkVulns := flag.Bool("vulns", false, "Query osv.dev for known vulnerabilities")
	projectName := flag.String("name", "", "Project name (default: directory name)")
	flag.Parse()

	absPath, err := filepath.Abs(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if *projectName == "" {
		*projectName = filepath.Base(absPath)
	}

	if *format == "text" {
		fmt.Printf("%sScanning:%s %s\n", colorGray, colorReset, absPath)
	}

	start := time.Now()
	pkgs, sources, err := discover(absPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Scan error: %v\n", err)
		os.Exit(1)
	}

	if len(pkgs) == 0 {
		fmt.Println("No dependency files found.")
		os.Exit(0)
	}

	if *checkVulns {
		if *format == "text" {
			fmt.Printf("%sQuerying osv.dev for %d packages...%s\n", colorGray, len(pkgs), colorReset)
		}
		pkgs, err = checkOSV(pkgs)
		if err != nil && *format == "text" {
			fmt.Fprintf(os.Stderr, "%sWarning: %v%s\n", colorYellow, err, colorReset)
		}
	}

	elapsed := time.Since(start)

	switch *format {
	case "spdx":
		outputSPDX(pkgs, *projectName)
	case "cyclonedx":
		outputCycloneDX(pkgs, *projectName)
	default:
		outputText(pkgs, sources, elapsed)
	}

	// Non-zero exit if vulnerabilities found (CI/CD integration)
	if *checkVulns {
		for _, p := range pkgs {
			if len(p.Vulns) > 0 {
				os.Exit(1)
			}
		}
	}
}
