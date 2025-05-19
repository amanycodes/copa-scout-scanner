package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	sarif "github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
	v1alpha1 "github.com/project-copacetic/copacetic/pkg/types/v1alpha1"
)

// ScoutSarifParser encapsulates the logic for parsing Docker Scout SARIF reports.
type ScoutSarifParser struct{}

// PURLInfo holds extracted data from a Package URL.
type PURLInfo struct {
	Type      string
	Namespace string
	Name      string
	Version   string
	OSDistro  string
	OSName    string
	OSVersion string
	Arch      string
}

func newScoutSarifParser() *ScoutSarifParser {
	return &ScoutSarifParser{}
}

// parsePURL parses a PURL string into a PURLInfo struct.
func parsePURL(purlStr string) (*PURLInfo, error) {
	if !strings.HasPrefix(purlStr, "pkg:") {
		return nil, fmt.Errorf("not a valid PURL: %s", purlStr)
	}
	info := PURLInfo{}
	mainAndQualifiers := strings.SplitN(purlStr, "?", 2)
	parts := strings.TrimPrefix(mainAndQualifiers[0], "pkg:")
	nameAndVersion := strings.SplitN(parts, "@", 2)
	typeAndRemaining := strings.SplitN(nameAndVersion[0], "/", 2)
	info.Type = typeAndRemaining[0]
	if len(typeAndRemaining) > 1 {
		slashIndex := strings.Index(typeAndRemaining[1], "/")
		if slashIndex != -1 && slashIndex != 0 && slashIndex != len(typeAndRemaining[1])-1 {
			info.Namespace = typeAndRemaining[1][:slashIndex]
			info.Name = typeAndRemaining[1][slashIndex+1:]
		} else {
			info.Name = typeAndRemaining[1]
		}
	}
	if len(nameAndVersion) > 1 {
		info.Version = nameAndVersion[1]
	}
	if len(mainAndQualifiers) > 1 {
		qualifiers, err := url.ParseQuery(mainAndQualifiers[1])
		if err == nil {
			info.OSDistro = qualifiers.Get("os_distro")
			info.OSName = qualifiers.Get("os_name")
			info.OSVersion = qualifiers.Get("os_version")
			info.Arch = qualifiers.Get("arch")
		}
	}
	if info.Name == "" {
		return nil, fmt.Errorf("could not parse package name from PURL: %s", purlStr)
	}
	return &info, nil
}

// normalizeOSType normalizes OS identifiers to a canonical form.
func normalizeOSType(sarifOSIdentifier string) string {
	if sarifOSIdentifier == "" {
		return ""
	}
	lowerID := strings.ToLower(sarifOSIdentifier)
	switch {
	case strings.Contains(lowerID, "debian"):
		return "debian"
	case strings.Contains(lowerID, "ubuntu"):
		return "ubuntu"
	case strings.Contains(lowerID, "alpine"):
		return "alpine"
	case strings.Contains(lowerID, "centos"):
		return "centos"
	case strings.Contains(lowerID, "rhel"), strings.Contains(lowerID, "red hat"):
		return "rhel"
	case strings.Contains(lowerID, "fedora"):
		return "fedora"
	case strings.Contains(lowerID, "amazon"), strings.Contains(lowerID, "amzn"):
		return "amazon"
	case strings.Contains(lowerID, "mariner"):
		return "mariner"
	case strings.Contains(lowerID, "azurelinux"):
		return "azurelinux"
	default:
		fmt.Fprintf(os.Stderr, "copa-scout-plugin: Warning - Unrecognized OS identifier from SARIF: '%s'. Using as is: '%s'.\n", sarifOSIdentifier, lowerID)
		return lowerID
	}
}

// parse parses the SARIF report file and transforms it into v1alpha1.UpdateManifest.
func (p *ScoutSarifParser) parse(sarifFilePath string) (*v1alpha1.UpdateManifest, error) {
	sarifReport, err := sarif.Open(sarifFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open or parse SARIF file '%s': %w", sarifFilePath, err)
	}

	if len(sarifReport.Runs) == 0 {
		return nil, fmt.Errorf("no runs found in SARIF report from '%s'", sarifFilePath)
	}
	run := sarifReport.Runs[0]

	outputManifest := &v1alpha1.UpdateManifest{
		APIVersion: v1alpha1.APIVersion,
		Metadata:   v1alpha1.Metadata{OS: v1alpha1.OS{}, Config: v1alpha1.Config{}},
		Updates:    []v1alpha1.UpdatePackage{},
	}

	// OS Metadata Extraction
	osMetaInitialized := false
	var determinedOSType, determinedOSVersion, determinedArch string

	// Try artifact properties first for OS metadata
	if len(run.Artifacts) > 0 && run.Artifacts[0] != nil && run.Artifacts[0].Properties != nil {
		if props, ok := run.Artifacts[0].Properties.Properties["osDetails"].(map[string]interface{}); ok {
			if osName, okName := props["name"].(string); okName {
				determinedOSType = normalizeOSType(osName)
			}
			if osVer, okVer := props["version"].(string); okVer {
				determinedOSVersion = osVer
			}
		}
		if archVal, okArch := run.Artifacts[0].Properties.Properties["architecture"].(string); okArch {
			determinedArch = archVal
		}
	}

	rulesMap := make(map[string]*sarif.ReportingDescriptor)
	if run.Tool.Driver != nil {
		for _, rule := range run.Tool.Driver.Rules {
			ruleCopy := rule
			if ruleCopy.ID != nil {
				rulesMap[*ruleCopy.ID] = ruleCopy
			}
		}
	}

	for _, result := range run.Results {
		if &result.Kind == nil || result.Kind != "fail" || result.RuleID == nil || *result.RuleID == "" {
			continue
		}
		rule, ok := rulesMap[*result.RuleID]
		if !ok {
			continue
		}

		var cveID, fixedVersion, pkgName, installedVersion string
		if rule.ID != nil {
			cveID = *rule.ID
		}

		// Extract FixedVersion
		if rule.Properties != nil && rule.Properties.Properties != nil {
			if fv, okFv := rule.Properties.Properties["fixed_version"].(string); okFv {
				fixedVersion = fv
			}
		}
		if fixedVersion == "" && rule.Help != nil && rule.Help.Markdown != nil {
			// Optionally parse markdown for fixed version
		}
		if fixedVersion == "" || strings.ToLower(fixedVersion) == "not fixed" || fixedVersion == "-" {
			continue
		}

		// Extract PURLs and parse the first one
		if rule.Properties != nil && rule.Properties.Properties != nil {
			if psInterface, okPurls := rule.Properties.Properties["purls"].([]interface{}); okPurls && len(psInterface) > 0 {
				if pStr, okPStr := psInterface[0].(string); okPStr {
					purlInfo, errPURL := parsePURL(pStr)
					if errPURL == nil {
						pkgName = purlInfo.Name
						installedVersion = purlInfo.Version
						// Initialize OS info from first PURL if not already found
						if !osMetaInitialized {
							if determinedOSType == "" && purlInfo.OSName != "" {
								determinedOSType = normalizeOSType(purlInfo.OSName)
							}
							if determinedOSVersion == "" && purlInfo.OSVersion != "" {
								determinedOSVersion = purlInfo.OSVersion
							}
							if determinedArch == "" && purlInfo.Arch != "" {
								determinedArch = purlInfo.Arch
							}
							if determinedOSType != "" {
								osMetaInitialized = true
							}
						}
					}
				}
			}
		}
		if pkgName == "" || installedVersion == "" {
			continue
		}

		outputManifest.Updates = append(outputManifest.Updates, v1alpha1.UpdatePackage{
			Name:             pkgName,
			InstalledVersion: installedVersion,
			FixedVersion:     fixedVersion,
			VulnerabilityID:  cveID,
		})
	}

	outputManifest.Metadata.OS.Type = determinedOSType
	outputManifest.Metadata.OS.Version = determinedOSVersion
	outputManifest.Metadata.Config.Arch = determinedArch

	if outputManifest.Metadata.OS.Type == "" {
		return nil, fmt.Errorf("critical: OS Type not found in SARIF")
	}
	if outputManifest.Metadata.OS.Version == "" {
		return nil, fmt.Errorf("critical: OS Version not found in SARIF")
	}
	if outputManifest.Metadata.Config.Arch == "" {
		outputManifest.Metadata.Config.Arch = "amd64"
	}
	return outputManifest, nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "copa-scout-plugin: ERROR - Usage: %s <sarif_report_file>\n", os.Args[0])
		os.Exit(1)
	}
	sarifFilePath := os.Args[1]

	parser := newScoutSarifParser()
	report, err := parser.parse(sarifFilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "copa-scout-plugin: ERROR - Failed to parse report using parser.parse(): %v\n", err)
		os.Exit(1)
	}

	reportBytes, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "copa-scout-plugin: ERROR - Failed to serialize standardized report to JSON: %v\n", err)
		os.Exit(1)
	}

	os.Stdout.Write(reportBytes)
}
