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
// Shodan OSINT Plugin
//
// Integrates Shodan (https://www.shodan.io) into PentAGI as a native tool.
// Shodan crawls the entire internet and indexes exposed services, open ports,
// banners, SSL certificates, and known vulnerabilities.
//
// The agent can use this tool for:
//   - Discovering exposed services on a target IP/domain
//   - Finding all hosts running a specific service/software
//   - Identifying known vulnerabilities on exposed services
//   - Mapping the attack surface before active scanning
//
// Required env: SHODAN_API_KEY
// ============================================================================

const (
	shodanBaseURL = "https://api.shodan.io"
	shodanTimeout = 30 * time.Second
)

// ShodanTool implements the tools.Tool interface for Shodan queries.
type ShodanTool struct {
	apiKey string
	client *http.Client
	logger *logrus.Entry
}

// NewShodanTool creates a Shodan search tool.
func NewShodanTool(apiKey string) *ShodanTool {
	return &ShodanTool{
		apiKey: apiKey,
		client: &http.Client{Timeout: shodanTimeout},
		logger: logrus.WithField("tool", "shodan"),
	}
}

func (s *ShodanTool) IsAvailable() bool {
	return s.apiKey != ""
}

// Tools returns the LLM tool definitions for Shodan.
func (s *ShodanTool) Tools() []llms.Tool {
	return []llms.Tool{
		{
			Type: "function",
			Function: &llms.FunctionDefinition{
				Name:        "shodan_search",
				Description: "Search Shodan for internet-connected devices and services. Use to discover exposed services, open ports, vulnerabilities, and banners on target hosts. Supports IP lookup, search queries, and DNS resolution.",
				Parameters: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"action": map[string]any{
							"type":        "string",
							"enum":        []string{"host", "search", "dns", "exploits"},
							"description": "Action type: 'host' for IP lookup, 'search' for Shodan query, 'dns' for DNS resolution, 'exploits' for known exploit search",
						},
						"query": map[string]any{
							"type":        "string",
							"description": "For 'host': IP address. For 'search': Shodan search query (e.g., 'apache port:8080 country:US'). For 'dns': hostname to resolve. For 'exploits': search term (e.g., 'apache 2.4')",
						},
						"max_results": map[string]any{
							"type":        "integer",
							"description": "Maximum results to return (default: 10, max: 100)",
						},
					},
					"required": []string{"action", "query"},
				},
			},
		},
	}
}

// Handle processes a Shodan tool call.
func (s *ShodanTool) Handle(ctx context.Context, name string, args json.RawMessage) (string, error) {
	var action struct {
		Action     string `json:"action"`
		Query      string `json:"query"`
		MaxResults int    `json:"max_results"`
	}
	if err := json.Unmarshal(args, &action); err != nil {
		return "", fmt.Errorf("failed to parse shodan args: %w", err)
	}

	if action.MaxResults <= 0 || action.MaxResults > 100 {
		action.MaxResults = 10
	}

	switch action.Action {
	case "host":
		return s.hostLookup(ctx, action.Query)
	case "search":
		return s.search(ctx, action.Query, action.MaxResults)
	case "dns":
		return s.dnsResolve(ctx, action.Query)
	case "exploits":
		return s.searchExploits(ctx, action.Query, action.MaxResults)
	default:
		return "", fmt.Errorf("unknown shodan action: %s", action.Action)
	}
}

// hostLookup returns all known services and vulnerabilities for an IP.
func (s *ShodanTool) hostLookup(ctx context.Context, ip string) (string, error) {
	endpoint := fmt.Sprintf("%s/shodan/host/%s?key=%s", shodanBaseURL, url.PathEscape(ip), s.apiKey)

	body, err := s.doRequest(ctx, endpoint)
	if err != nil {
		return "", fmt.Errorf("shodan host lookup failed: %w", err)
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("failed to parse shodan response: %w", err)
	}

	return s.formatHostResult(result), nil
}

// search performs a Shodan search query.
func (s *ShodanTool) search(ctx context.Context, query string, maxResults int) (string, error) {
	endpoint := fmt.Sprintf("%s/shodan/host/search?key=%s&query=%s&page=1",
		shodanBaseURL, s.apiKey, url.QueryEscape(query))

	body, err := s.doRequest(ctx, endpoint)
	if err != nil {
		return "", fmt.Errorf("shodan search failed: %w", err)
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("failed to parse shodan response: %w", err)
	}

	return s.formatSearchResult(result, maxResults), nil
}

// dnsResolve resolves a hostname to IP addresses via Shodan.
func (s *ShodanTool) dnsResolve(ctx context.Context, hostname string) (string, error) {
	endpoint := fmt.Sprintf("%s/dns/resolve?hostnames=%s&key=%s",
		shodanBaseURL, url.QueryEscape(hostname), s.apiKey)

	body, err := s.doRequest(ctx, endpoint)
	if err != nil {
		return "", fmt.Errorf("shodan DNS resolve failed: %w", err)
	}

	var result map[string]string
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("failed to parse DNS response: %w", err)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("DNS Resolution for %s:\n", hostname))
	for host, ip := range result {
		sb.WriteString(fmt.Sprintf("  %s → %s\n", host, ip))
	}
	return sb.String(), nil
}

// searchExploits searches for known exploits.
func (s *ShodanTool) searchExploits(ctx context.Context, query string, maxResults int) (string, error) {
	endpoint := fmt.Sprintf("https://exploits.shodan.io/api/search?query=%s&key=%s",
		url.QueryEscape(query), s.apiKey)

	body, err := s.doRequest(ctx, endpoint)
	if err != nil {
		return "", fmt.Errorf("shodan exploit search failed: %w", err)
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("failed to parse exploit response: %w", err)
	}

	return s.formatExploitResult(result, maxResults), nil
}

// ============================================================================
// HTTP & Formatting helpers
// ============================================================================

func (s *ShodanTool) doRequest(ctx context.Context, endpoint string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("shodan API returned %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

func (s *ShodanTool) formatHostResult(data map[string]any) string {
	var sb strings.Builder

	ip, _ := data["ip_str"].(string)
	org, _ := data["org"].(string)
	os, _ := data["os"].(string)
	country, _ := data["country_code"].(string)

	sb.WriteString(fmt.Sprintf("=== Shodan Host Report: %s ===\n", ip))
	sb.WriteString(fmt.Sprintf("Organization: %s\n", org))
	if os != "" {
		sb.WriteString(fmt.Sprintf("OS: %s\n", os))
	}
	sb.WriteString(fmt.Sprintf("Country: %s\n", country))

	// Open ports
	if ports, ok := data["ports"].([]any); ok {
		portStrs := make([]string, 0, len(ports))
		for _, p := range ports {
			portStrs = append(portStrs, fmt.Sprintf("%v", p))
		}
		sb.WriteString(fmt.Sprintf("Open Ports: %s\n", strings.Join(portStrs, ", ")))
	}

	// Vulnerabilities
	if vulns, ok := data["vulns"].([]any); ok && len(vulns) > 0 {
		sb.WriteString(fmt.Sprintf("\nKnown Vulnerabilities (%d):\n", len(vulns)))
		for _, v := range vulns {
			sb.WriteString(fmt.Sprintf("  - %v\n", v))
		}
	}

	// Services/banners
	if matches, ok := data["data"].([]any); ok {
		sb.WriteString(fmt.Sprintf("\nServices (%d):\n", len(matches)))
		for i, m := range matches {
			if i >= 20 {
				sb.WriteString(fmt.Sprintf("  ... and %d more\n", len(matches)-20))
				break
			}
			if match, ok := m.(map[string]any); ok {
				port, _ := match["port"].(float64)
				transport, _ := match["transport"].(string)
				product, _ := match["product"].(string)
				version, _ := match["version"].(string)

				sb.WriteString(fmt.Sprintf("  Port %d/%s", int(port), transport))
				if product != "" {
					sb.WriteString(fmt.Sprintf(" — %s", product))
					if version != "" {
						sb.WriteString(fmt.Sprintf(" %s", version))
					}
				}
				sb.WriteString("\n")
			}
		}
	}

	return sb.String()
}

func (s *ShodanTool) formatSearchResult(data map[string]any, max int) string {
	var sb strings.Builder

	total, _ := data["total"].(float64)
	sb.WriteString(fmt.Sprintf("Shodan Search Results (total: %d)\n\n", int(total)))

	matches, _ := data["matches"].([]any)
	for i, m := range matches {
		if i >= max {
			break
		}
		if match, ok := m.(map[string]any); ok {
			ip, _ := match["ip_str"].(string)
			port, _ := match["port"].(float64)
			org, _ := match["org"].(string)
			product, _ := match["product"].(string)

			sb.WriteString(fmt.Sprintf("[%d] %s:%d", i+1, ip, int(port)))
			if org != "" {
				sb.WriteString(fmt.Sprintf(" (%s)", org))
			}
			if product != "" {
				sb.WriteString(fmt.Sprintf(" — %s", product))
			}
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

func (s *ShodanTool) formatExploitResult(data map[string]any, max int) string {
	var sb strings.Builder

	total, _ := data["total"].(float64)
	sb.WriteString(fmt.Sprintf("Exploit Search Results (total: %d)\n\n", int(total)))

	matches, _ := data["matches"].([]any)
	for i, m := range matches {
		if i >= max {
			break
		}
		if match, ok := m.(map[string]any); ok {
			desc, _ := match["description"].(string)
			source, _ := match["source"].(string)
			id, _ := match["_id"].(string)

			// Truncate long descriptions
			if len(desc) > 200 {
				desc = desc[:200] + "..."
			}

			sb.WriteString(fmt.Sprintf("[%d] %s (source: %s, id: %s)\n", i+1, desc, source, id))

			if cves, ok := match["cve"].([]any); ok && len(cves) > 0 {
				cveStrs := make([]string, 0, len(cves))
				for _, c := range cves {
					cveStrs = append(cveStrs, fmt.Sprintf("%v", c))
				}
				sb.WriteString(fmt.Sprintf("    CVEs: %s\n", strings.Join(cveStrs, ", ")))
			}
		}
	}

	return sb.String()
}
