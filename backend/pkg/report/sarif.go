package report

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ============================================================================
// SARIF Report Generator
//
// Generates reports in SARIF v2.1.0 (Static Analysis Results Interchange
// Format) — the industry standard for security tooling output. This enables
// PentAGI to integrate directly with:
//   - GitHub Advanced Security (code scanning alerts)
//   - GitLab SAST/DAST
//   - Azure DevOps Security
//   - SonarQube
//   - Any CI/CD pipeline that consumes SARIF
//
// Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
// ============================================================================

const (
	sarifVersion = "2.1.0"
	sarifSchema  = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
	toolName     = "PentAGI"
	toolOrg      = "vxcontrol"
)

// SARIFReport is the top-level SARIF document.
type SARIFReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single analysis run.
type SARIFRun struct {
	Tool        SARIFTool         `json:"tool"`
	Results     []SARIFResult     `json:"results"`
	Invocations []SARIFInvocation `json:"invocations,omitempty"`
	Taxonomies  []SARIFTaxonomy   `json:"taxonomies,omitempty"`
}

// SARIFTool describes the tool that produced the results.
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver is the primary tool component.
type SARIFDriver struct {
	Name            string               `json:"name"`
	Organization    string               `json:"organization,omitempty"`
	Version         string               `json:"version,omitempty"`
	InformationURI  string               `json:"informationUri,omitempty"`
	Rules           []SARIFReportingDesc `json:"rules,omitempty"`
	SupportedTaxonomies []SARIFTaxonomyRef `json:"supportedTaxonomies,omitempty"`
}

// SARIFReportingDesc describes a rule (vulnerability type).
type SARIFReportingDesc struct {
	ID               string               `json:"id"`
	Name             string               `json:"name,omitempty"`
	ShortDescription SARIFMessage         `json:"shortDescription,omitempty"`
	FullDescription  SARIFMessage         `json:"fullDescription,omitempty"`
	HelpURI          string               `json:"helpUri,omitempty"`
	Help             *SARIFMessage        `json:"help,omitempty"`
	DefaultConfig    *SARIFReportingConfig `json:"defaultConfiguration,omitempty"`
	Properties       map[string]any       `json:"properties,omitempty"`
	Relationships    []SARIFRelationship  `json:"relationships,omitempty"`
}

// SARIFReportingConfig sets the default severity level for a rule.
type SARIFReportingConfig struct {
	Level string `json:"level"` // error, warning, note, none
}

// SARIFResult is a single finding.
type SARIFResult struct {
	RuleID    string            `json:"ruleId"`
	RuleIndex int               `json:"ruleIndex,omitempty"`
	Level     string            `json:"level"`   // error, warning, note, none
	Message   SARIFMessage      `json:"message"`
	Locations []SARIFLocation   `json:"locations,omitempty"`
	Fixes     []SARIFFix        `json:"fixes,omitempty"`
	Properties map[string]any   `json:"properties,omitempty"`
}

// SARIFMessage is a human-readable message.
type SARIFMessage struct {
	Text     string `json:"text,omitempty"`
	Markdown string `json:"markdown,omitempty"`
}

// SARIFLocation points to where a finding was discovered.
type SARIFLocation struct {
	PhysicalLocation *SARIFPhysicalLocation `json:"physicalLocation,omitempty"`
	LogicalLocations []SARIFLogicalLocation `json:"logicalLocations,omitempty"`
	Properties       map[string]any         `json:"properties,omitempty"`
}

// SARIFPhysicalLocation identifies a file/URI location.
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           *SARIFRegion          `json:"region,omitempty"`
}

// SARIFArtifactLocation is a URI reference.
type SARIFArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

// SARIFLogicalLocation describes a conceptual location (e.g., a service or endpoint).
type SARIFLogicalLocation struct {
	Name               string `json:"name,omitempty"`
	FullyQualifiedName string `json:"fullyQualifiedName,omitempty"`
	Kind               string `json:"kind,omitempty"` // "endpoint", "service", "host", etc.
}

// SARIFRegion identifies a region within an artifact.
type SARIFRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}

// SARIFFix describes a potential fix for a finding.
type SARIFFix struct {
	Description SARIFMessage `json:"description"`
}

// SARIFInvocation records metadata about the analysis run.
type SARIFInvocation struct {
	ExecutionSuccessful bool       `json:"executionSuccessful"`
	StartTimeUTC        string     `json:"startTimeUtc,omitempty"`
	EndTimeUTC          string     `json:"endTimeUtc,omitempty"`
	Properties          map[string]any `json:"properties,omitempty"`
}

// SARIFTaxonomy represents an external classification system (e.g., MITRE ATT&CK).
type SARIFTaxonomy struct {
	Name         string               `json:"name"`
	Version      string               `json:"version,omitempty"`
	Organization string               `json:"organization,omitempty"`
	ShortDescription SARIFMessage     `json:"shortDescription,omitempty"`
	Taxa         []SARIFReportingDesc `json:"taxa,omitempty"`
	GUID         string               `json:"guid,omitempty"`
}

// SARIFTaxonomyRef references a taxonomy.
type SARIFTaxonomyRef struct {
	Name string `json:"name"`
	GUID string `json:"guid,omitempty"`
}

// SARIFRelationship links a rule to a taxonomy category.
type SARIFRelationship struct {
	Target SARIFRelTarget `json:"target"`
	Kinds  []string       `json:"kinds,omitempty"` // "relevant", "superset", "equal"
}

// SARIFRelTarget identifies the target of a relationship.
type SARIFRelTarget struct {
	ID            string `json:"id"`
	ToolComponent SARIFToolComponentRef `json:"toolComponent"`
}

// SARIFToolComponentRef references a tool component by index.
type SARIFToolComponentRef struct {
	Name  string `json:"name"`
	Index int    `json:"index"`
}

// ============================================================================
// Finding — the internal representation of a discovered vulnerability.
// ============================================================================

// Finding represents a vulnerability or issue discovered during a pentest.
type Finding struct {
	// Identity
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`

	// Classification
	Severity    string   `json:"severity"`     // critical, high, medium, low, info
	CVE         string   `json:"cve,omitempty"`
	CVSS        float64  `json:"cvss,omitempty"`
	CWE         string   `json:"cwe,omitempty"` // e.g., "CWE-89"

	// Location
	Target      string   `json:"target"`       // URL, IP, hostname
	Endpoint    string   `json:"endpoint,omitempty"` // specific path/port
	Service     string   `json:"service,omitempty"`  // e.g., "http", "ssh"

	// Evidence
	Evidence    string   `json:"evidence,omitempty"`
	Steps       []string `json:"steps,omitempty"`      // Reproduction steps
	Remediation string   `json:"remediation,omitempty"` // Fix recommendation

	// MITRE ATT&CK
	ATTACKTechniques []string `json:"attack_techniques,omitempty"`

	// Metadata
	FlowID    int64     `json:"flow_id"`
	TaskID    *int64    `json:"task_id,omitempty"`
	FoundAt   time.Time `json:"found_at"`
}

// ============================================================================
// Generator — builds SARIF reports from findings
// ============================================================================

// Generator creates SARIF reports from pentest findings.
type Generator struct {
	version string
}

// NewGenerator creates a SARIF report generator.
func NewGenerator(version string) *Generator {
	return &Generator{version: version}
}

// GenerateSARIF creates a SARIF report from the given findings.
func (g *Generator) GenerateSARIF(findings []Finding, startTime, endTime time.Time) ([]byte, error) {
	// Build unique rules from findings
	ruleMap := make(map[string]int) // rule ID → index
	var rules []SARIFReportingDesc
	var results []SARIFResult

	for _, f := range findings {
		ruleID := g.buildRuleID(f)

		ruleIdx, exists := ruleMap[ruleID]
		if !exists {
			ruleIdx = len(rules)
			ruleMap[ruleID] = ruleIdx

			rule := SARIFReportingDesc{
				ID:   ruleID,
				Name: f.Title,
				ShortDescription: SARIFMessage{
					Text: f.Title,
				},
				FullDescription: SARIFMessage{
					Text: f.Description,
				},
				DefaultConfig: &SARIFReportingConfig{
					Level: severityToSARIFLevel(f.Severity),
				},
				Properties: map[string]any{
					"severity": f.Severity,
				},
			}

			if f.CWE != "" {
				rule.HelpURI = fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html",
					strings.TrimPrefix(f.CWE, "CWE-"))
			}

			if f.CVE != "" {
				rule.Properties["cve"] = f.CVE
				rule.Properties["cvss"] = f.CVSS
			}

			// Link to MITRE ATT&CK taxonomy
			for _, techID := range f.ATTACKTechniques {
				rule.Relationships = append(rule.Relationships, SARIFRelationship{
					Target: SARIFRelTarget{
						ID: techID,
						ToolComponent: SARIFToolComponentRef{
							Name:  "MITRE ATT&CK",
							Index: 0,
						},
					},
					Kinds: []string{"relevant"},
				})
			}

			if f.Remediation != "" {
				rule.Help = &SARIFMessage{
					Text:     f.Remediation,
					Markdown: fmt.Sprintf("**Remediation:** %s", f.Remediation),
				}
			}

			rules = append(rules, rule)
		}

		// Build the result
		result := SARIFResult{
			RuleID:    ruleID,
			RuleIndex: ruleIdx,
			Level:     severityToSARIFLevel(f.Severity),
			Message: SARIFMessage{
				Text: f.Description,
				Markdown: g.buildResultMarkdown(f),
			},
			Properties: map[string]any{
				"flow_id":    f.FlowID,
				"found_at":   f.FoundAt.Format(time.RFC3339),
				"severity":   f.Severity,
			},
		}

		if f.CVE != "" {
			result.Properties["cve"] = f.CVE
			result.Properties["cvss"] = f.CVSS
		}

		// Add location
		location := SARIFLocation{
			LogicalLocations: []SARIFLogicalLocation{
				{
					Name:               f.Target,
					FullyQualifiedName: f.Target,
					Kind:               "host",
				},
			},
		}

		if f.Endpoint != "" {
			location.PhysicalLocation = &SARIFPhysicalLocation{
				ArtifactLocation: SARIFArtifactLocation{
					URI: f.Endpoint,
				},
			}
			location.LogicalLocations = append(location.LogicalLocations, SARIFLogicalLocation{
				Name: f.Endpoint,
				Kind: "endpoint",
			})
		}

		result.Locations = []SARIFLocation{location}

		// Add fix suggestion if available
		if f.Remediation != "" {
			result.Fixes = []SARIFFix{
				{Description: SARIFMessage{Text: f.Remediation}},
			}
		}

		results = append(results, result)
	}

	report := SARIFReport{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           toolName,
						Organization:   toolOrg,
						Version:        g.version,
						InformationURI: "https://github.com/vxcontrol/pentagi",
						Rules:          rules,
						SupportedTaxonomies: []SARIFTaxonomyRef{
							{Name: "MITRE ATT&CK", GUID: "1A2B3C4D-1234-5678-9ABC-DEF012345678"},
						},
					},
				},
				Results: results,
				Invocations: []SARIFInvocation{
					{
						ExecutionSuccessful: true,
						StartTimeUTC:        startTime.UTC().Format(time.RFC3339),
						EndTimeUTC:          endTime.UTC().Format(time.RFC3339),
						Properties: map[string]any{
							"findings_count": len(findings),
							"duration_seconds": endTime.Sub(startTime).Seconds(),
						},
					},
				},
			},
		},
	}

	return json.MarshalIndent(report, "", "  ")
}

// ============================================================================
// Helpers
// ============================================================================

func (g *Generator) buildRuleID(f Finding) string {
	if f.CVE != "" {
		return f.CVE
	}
	if f.CWE != "" {
		return f.CWE
	}
	return fmt.Sprintf("PENTAGI-%s", f.ID)
}

func (g *Generator) buildResultMarkdown(f Finding) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("## %s\n\n", f.Title))
	sb.WriteString(fmt.Sprintf("**Severity:** %s", strings.ToUpper(f.Severity)))
	if f.CVSS > 0 {
		sb.WriteString(fmt.Sprintf(" (CVSS: %.1f)", f.CVSS))
	}
	sb.WriteString("\n\n")

	if f.Target != "" {
		sb.WriteString(fmt.Sprintf("**Target:** `%s`\n\n", f.Target))
	}

	if f.CVE != "" {
		sb.WriteString(fmt.Sprintf("**CVE:** [%s](https://nvd.nist.gov/vuln/detail/%s)\n\n", f.CVE, f.CVE))
	}

	sb.WriteString(f.Description)
	sb.WriteString("\n\n")

	if f.Evidence != "" {
		sb.WriteString("### Evidence\n\n")
		sb.WriteString("```\n")
		sb.WriteString(f.Evidence)
		sb.WriteString("\n```\n\n")
	}

	if len(f.Steps) > 0 {
		sb.WriteString("### Reproduction Steps\n\n")
		for i, step := range f.Steps {
			sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, step))
		}
		sb.WriteString("\n")
	}

	if f.Remediation != "" {
		sb.WriteString("### Remediation\n\n")
		sb.WriteString(f.Remediation)
		sb.WriteString("\n")
	}

	return sb.String()
}

func severityToSARIFLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low", "info", "informational":
		return "note"
	default:
		return "warning"
	}
}
