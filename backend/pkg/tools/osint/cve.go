package osint

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vxcontrol/langchaingo/llms"
)

// ============================================================================
// CVE/NVD Lookup Tool
//
// Queries the NIST National Vulnerability Database (NVD) for known CVEs.
// No API key required for basic queries (rate-limited to 5 requests/30s).
// With API key: 50 requests/30s.
//
// The agent uses this tool to:
//   - Look up details of a specific CVE ID
//   - Search for vulnerabilities affecting a specific product/vendor
//   - Get CVSS scores and severity ratings
//   - Find known exploits and references
//
// API: https://services.nvd.nist.gov/rest/json/cves/2.0
// ============================================================================

const (
	nvdBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	nvdTimeout = 30 * time.Second
)

// CVETool implements vulnerability lookup via the NVD API.
type CVETool struct {
	apiKey string // Optional: NVD API key for higher rate limits
	client *http.Client
	logger *logrus.Entry
}

// NewCVETool creates a CVE lookup tool.
func NewCVETool(apiKey string) *CVETool {
	return &CVETool{
		apiKey: apiKey,
		client: &http.Client{Timeout: nvdTimeout},
		logger: logrus.WithField("tool", "cve_search"),
	}
}

func (c *CVETool) IsAvailable() bool {
	return true // NVD API works without key (rate-limited)
}

// Tools returns the LLM tool definitions for CVE lookup.
func (c *CVETool) Tools() []llms.Tool {
	return []llms.Tool{
		{
			Type: "function",
			Function: &llms.FunctionDefinition{
				Name:        "cve_search",
				Description: "Search the NIST National Vulnerability Database (NVD) for known CVEs. Look up specific CVE IDs, search by product/vendor keyword, or find vulnerabilities by severity. Returns CVSS scores, descriptions, references, and affected configurations.",
				Parameters: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"action": map[string]any{
							"type":        "string",
							"enum":        []string{"lookup", "search"},
							"description": "'lookup' for specific CVE ID (e.g., CVE-2021-44228), 'search' for keyword search",
						},
						"query": map[string]any{
							"type":        "string",
							"description": "For 'lookup': CVE ID. For 'search': keyword (product name, vendor, etc.)",
						},
						"severity": map[string]any{
							"type":        "string",
							"enum":        []string{"", "LOW", "MEDIUM", "HIGH", "CRITICAL"},
							"description": "Optional: filter by CVSS v3 severity for search queries",
						},
						"max_results": map[string]any{
							"type":        "integer",
							"description": "Maximum results (default: 10, max: 50)",
						},
					},
					"required": []string{"action", "query"},
				},
			},
		},
	}
}

// Handle processes a CVE tool call.
func (c *CVETool) Handle(ctx context.Context, name string, args json.RawMessage) (string, error) {
	var action struct {
		Action     string `json:"action"`
		Query      string `json:"query"`
		Severity   string `json:"severity"`
		MaxResults int    `json:"max_results"`
	}
	if err := json.Unmarshal(args, &action); err != nil {
		return "", fmt.Errorf("failed to parse cve_search args: %w", err)
	}

	if action.MaxResults <= 0 || action.MaxResults > 50 {
		action.MaxResults = 10
	}

	switch action.Action {
	case "lookup":
		return c.lookupCVE(ctx, action.Query)
	case "search":
		return c.searchCVEs(ctx, action.Query, action.Severity, action.MaxResults)
	default:
		return "", fmt.Errorf("unknown cve_search action: %s", action.Action)
	}
}

// lookupCVE retrieves details for a specific CVE ID.
func (c *CVETool) lookupCVE(ctx context.Context, cveID string) (string, error) {
	cveID = strings.ToUpper(strings.TrimSpace(cveID))
	if !strings.HasPrefix(cveID, "CVE-") {
		cveID = "CVE-" + cveID
	}

	endpoint := fmt.Sprintf("%s?cveId=%s", nvdBaseURL, url.QueryEscape(cveID))

	body, err := c.doRequest(ctx, endpoint)
	if err != nil {
		return "", err
	}

	var response NVDResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return "", fmt.Errorf("failed to parse NVD response: %w", err)
	}

	if len(response.Vulnerabilities) == 0 {
		return fmt.Sprintf("CVE %s not found in NVD database.", cveID), nil
	}

	return c.formatCVEDetail(response.Vulnerabilities[0].CVE), nil
}

// searchCVEs searches for CVEs by keyword.
func (c *CVETool) searchCVEs(ctx context.Context, keyword, severity string, maxResults int) (string, error) {
	params := url.Values{}
	params.Set("keywordSearch", keyword)
	params.Set("resultsPerPage", fmt.Sprintf("%d", maxResults))

	if severity != "" {
		params.Set("cvssV3Severity", strings.ToUpper(severity))
	}

	endpoint := fmt.Sprintf("%s?%s", nvdBaseURL, params.Encode())

	body, err := c.doRequest(ctx, endpoint)
	if err != nil {
		return "", err
	}

	var response NVDResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return "", fmt.Errorf("failed to parse NVD response: %w", err)
	}

	return c.formatSearchResults(response, keyword), nil
}

// ============================================================================
// NVD API Response Types
// ============================================================================

// NVDResponse is the top-level NVD API response.
type NVDResponse struct {
	ResultsPerPage  int             `json:"resultsPerPage"`
	StartIndex      int             `json:"startIndex"`
	TotalResults    int             `json:"totalResults"`
	Vulnerabilities []NVDVulnWrapper `json:"vulnerabilities"`
}

// NVDVulnWrapper wraps a CVE entry.
type NVDVulnWrapper struct {
	CVE NVDCve `json:"cve"`
}

// NVDCve represents a CVE entry from NVD.
type NVDCve struct {
	ID               string           `json:"id"`
	Published        string           `json:"published"`
	LastModified     string           `json:"lastModified"`
	VulnStatus       string           `json:"vulnStatus"`
	Descriptions     []NVDDescription `json:"descriptions"`
	Metrics          NVDMetrics       `json:"metrics"`
	References       []NVDReference   `json:"references"`
	Weaknesses       []NVDWeakness    `json:"weaknesses"`
	Configurations   []NVDConfig      `json:"configurations"`
}

// NVDDescription is a multilingual description.
type NVDDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// NVDMetrics contains CVSS scoring.
type NVDMetrics struct {
	CvssMetricV31 []NVDCvssV31 `json:"cvssMetricV31"`
	CvssMetricV2  []NVDCvssV2  `json:"cvssMetricV2"`
}

// NVDCvssV31 is a CVSS v3.1 score entry.
type NVDCvssV31 struct {
	Source   string      `json:"source"`
	Type     string      `json:"type"`
	CvssData NVDCvssData `json:"cvssData"`
}

// NVDCvssData contains the CVSS scoring details.
type NVDCvssData struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

// NVDCvssV2 is a CVSS v2.0 score entry.
type NVDCvssV2 struct {
	Source   string      `json:"source"`
	CvssData NVDCvssData `json:"cvssData"`
}

// NVDReference is a URL reference for a CVE.
type NVDReference struct {
	URL    string   `json:"url"`
	Source string   `json:"source"`
	Tags   []string `json:"tags"`
}

// NVDWeakness identifies a CWE.
type NVDWeakness struct {
	Source      string           `json:"source"`
	Type        string           `json:"type"`
	Description []NVDDescription `json:"description"`
}

// NVDConfig describes affected products.
type NVDConfig struct {
	Nodes []NVDConfigNode `json:"nodes"`
}

// NVDConfigNode is a CPE match node.
type NVDConfigNode struct {
	Operator string        `json:"operator"`
	CpeMatch []NVDCpeMatch `json:"cpeMatch"`
}

// NVDCpeMatch identifies an affected product/version.
type NVDCpeMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
	VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
}

// ============================================================================
// HTTP & Formatting
// ============================================================================

func (c *CVETool) doRequest(ctx context.Context, endpoint string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	if c.apiKey != "" {
		req.Header.Set("apiKey", c.apiKey)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("NVD API request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == 429 {
		return nil, fmt.Errorf("NVD API rate limit exceeded (status %d), try again shortly", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NVD API returned %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

func (c *CVETool) formatCVEDetail(cve NVDCve) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("=== %s ===\n", cve.ID))
	sb.WriteString(fmt.Sprintf("Status: %s\n", cve.VulnStatus))
	sb.WriteString(fmt.Sprintf("Published: %s\n", cve.Published))

	// Description
	for _, desc := range cve.Descriptions {
		if desc.Lang == "en" {
			sb.WriteString(fmt.Sprintf("\nDescription:\n%s\n", desc.Value))
			break
		}
	}

	// CVSS Scores
	if len(cve.Metrics.CvssMetricV31) > 0 {
		m := cve.Metrics.CvssMetricV31[0]
		sb.WriteString(fmt.Sprintf("\nCVSS v3.1: %.1f (%s)\n", m.CvssData.BaseScore, m.CvssData.BaseSeverity))
		sb.WriteString(fmt.Sprintf("Vector: %s\n", m.CvssData.VectorString))
	} else if len(cve.Metrics.CvssMetricV2) > 0 {
		m := cve.Metrics.CvssMetricV2[0]
		sb.WriteString(fmt.Sprintf("\nCVSS v2.0: %.1f\n", m.CvssData.BaseScore))
	}

	// CWE
	for _, w := range cve.Weaknesses {
		for _, d := range w.Description {
			if d.Lang == "en" {
				sb.WriteString(fmt.Sprintf("CWE: %s\n", d.Value))
			}
		}
	}

	// Affected products
	for _, config := range cve.Configurations {
		for _, node := range config.Nodes {
			for _, match := range node.CpeMatch {
				if match.Vulnerable {
					sb.WriteString(fmt.Sprintf("Affected: %s\n", match.Criteria))
				}
			}
		}
	}

	// References (top 5)
	if len(cve.References) > 0 {
		sb.WriteString("\nReferences:\n")
		for i, ref := range cve.References {
			if i >= 5 {
				sb.WriteString(fmt.Sprintf("  ... and %d more\n", len(cve.References)-5))
				break
			}
			tags := ""
			if len(ref.Tags) > 0 {
				tags = fmt.Sprintf(" [%s]", strings.Join(ref.Tags, ", "))
			}
			sb.WriteString(fmt.Sprintf("  - %s%s\n", ref.URL, tags))
		}
	}

	return sb.String()
}

func (c *CVETool) formatSearchResults(response NVDResponse, keyword string) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("CVE Search Results for '%s' (showing %d of %d):\n\n",
		keyword, len(response.Vulnerabilities), response.TotalResults))

	for i, vuln := range response.Vulnerabilities {
		cve := vuln.CVE

		// Get severity
		severity := "N/A"
		score := 0.0
		if len(cve.Metrics.CvssMetricV31) > 0 {
			m := cve.Metrics.CvssMetricV31[0]
			severity = m.CvssData.BaseSeverity
			score = m.CvssData.BaseScore
		}

		// Get description
		desc := ""
		for _, d := range cve.Descriptions {
			if d.Lang == "en" {
				desc = d.Value
				if len(desc) > 150 {
					desc = desc[:150] + "..."
				}
				break
			}
		}

		sb.WriteString(fmt.Sprintf("[%d] %s — CVSS: %.1f (%s)\n", i+1, cve.ID, score, severity))
		sb.WriteString(fmt.Sprintf("    %s\n\n", desc))
	}

	return sb.String()
}
