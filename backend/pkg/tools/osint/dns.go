package osint

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vxcontrol/langchaingo/llms"
)

// ============================================================================
// DNS Enumeration Tool
//
// Performs DNS reconnaissance without requiring external API keys.
// Uses Go's native DNS resolver + public DNS-over-HTTPS endpoints + crt.sh
// for certificate transparency log mining.
//
// Capabilities:
//   - Standard DNS record lookups (A, AAAA, MX, NS, TXT, CNAME, SOA)
//   - Subdomain discovery via Certificate Transparency (crt.sh)
//   - WHOIS-like information via RDAP
//   - Reverse DNS lookups
// ============================================================================

const (
	crtshURL     = "https://crt.sh"
	rdapURL      = "https://rdap.org"
	dnsTimeout   = 15 * time.Second
)

// DNSTool provides DNS enumeration capabilities.
type DNSTool struct {
	resolver *net.Resolver
	client   *http.Client
	logger   *logrus.Entry
}

// NewDNSTool creates a DNS enumeration tool.
func NewDNSTool() *DNSTool {
	return &DNSTool{
		resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: dnsTimeout}
				return d.DialContext(ctx, "udp", "8.8.8.8:53")
			},
		},
		client: &http.Client{Timeout: dnsTimeout},
		logger: logrus.WithField("tool", "dns_enum"),
	}
}

func (d *DNSTool) IsAvailable() bool {
	return true // No API key needed
}

// Tools returns the LLM tool definitions for DNS enumeration.
func (d *DNSTool) Tools() []llms.Tool {
	return []llms.Tool{
		{
			Type: "function",
			Function: &llms.FunctionDefinition{
				Name:        "dns_enum",
				Description: "DNS enumeration and reconnaissance tool. Look up DNS records (A, AAAA, MX, NS, TXT, CNAME), discover subdomains via Certificate Transparency logs, perform reverse DNS lookups, and query RDAP for domain registration information. No API key required.",
				Parameters: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"action": map[string]any{
							"type":        "string",
							"enum":        []string{"records", "subdomains", "reverse", "rdap"},
							"description": "'records' for DNS record lookup, 'subdomains' for subdomain discovery via crt.sh, 'reverse' for reverse DNS, 'rdap' for domain registration info",
						},
						"target": map[string]any{
							"type":        "string",
							"description": "Domain name for records/subdomains/rdap, or IP address for reverse lookup",
						},
						"record_types": map[string]any{
							"type":        "string",
							"description": "Comma-separated DNS record types for 'records' action (default: 'A,AAAA,MX,NS,TXT,CNAME')",
						},
					},
					"required": []string{"action", "target"},
				},
			},
		},
	}
}

// Handle processes a DNS tool call.
func (d *DNSTool) Handle(ctx context.Context, name string, args json.RawMessage) (string, error) {
	var action struct {
		Action      string `json:"action"`
		Target      string `json:"target"`
		RecordTypes string `json:"record_types"`
	}
	if err := json.Unmarshal(args, &action); err != nil {
		return "", fmt.Errorf("failed to parse dns_enum args: %w", err)
	}

	action.Target = strings.TrimSpace(action.Target)

	switch action.Action {
	case "records":
		return d.lookupRecords(ctx, action.Target, action.RecordTypes)
	case "subdomains":
		return d.discoverSubdomains(ctx, action.Target)
	case "reverse":
		return d.reverseLookup(ctx, action.Target)
	case "rdap":
		return d.rdapLookup(ctx, action.Target)
	default:
		return "", fmt.Errorf("unknown dns_enum action: %s", action.Action)
	}
}

// lookupRecords performs standard DNS record lookups.
func (d *DNSTool) lookupRecords(ctx context.Context, domain, recordTypes string) (string, error) {
	if recordTypes == "" {
		recordTypes = "A,AAAA,MX,NS,TXT,CNAME"
	}

	types := strings.Split(strings.ToUpper(recordTypes), ",")
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== DNS Records for %s ===\n\n", domain))

	for _, rt := range types {
		rt = strings.TrimSpace(rt)
		switch rt {
		case "A":
			ips, err := d.resolver.LookupHost(ctx, domain)
			if err == nil && len(ips) > 0 {
				sb.WriteString("A Records:\n")
				for _, ip := range ips {
					if net.ParseIP(ip).To4() != nil { // IPv4 only for A records
						sb.WriteString(fmt.Sprintf("  %s\n", ip))
					}
				}
			}

		case "AAAA":
			ips, err := d.resolver.LookupHost(ctx, domain)
			if err == nil {
				var ipv6 []string
				for _, ip := range ips {
					if net.ParseIP(ip).To4() == nil { // IPv6 only
						ipv6 = append(ipv6, ip)
					}
				}
				if len(ipv6) > 0 {
					sb.WriteString("AAAA Records:\n")
					for _, ip := range ipv6 {
						sb.WriteString(fmt.Sprintf("  %s\n", ip))
					}
				}
			}

		case "MX":
			mxs, err := d.resolver.LookupMX(ctx, domain)
			if err == nil && len(mxs) > 0 {
				sb.WriteString("MX Records:\n")
				for _, mx := range mxs {
					sb.WriteString(fmt.Sprintf("  %d %s\n", mx.Pref, mx.Host))
				}
			}

		case "NS":
			nss, err := d.resolver.LookupNS(ctx, domain)
			if err == nil && len(nss) > 0 {
				sb.WriteString("NS Records:\n")
				for _, ns := range nss {
					sb.WriteString(fmt.Sprintf("  %s\n", ns.Host))
				}
			}

		case "TXT":
			txts, err := d.resolver.LookupTXT(ctx, domain)
			if err == nil && len(txts) > 0 {
				sb.WriteString("TXT Records:\n")
				for _, txt := range txts {
					if len(txt) > 200 {
						txt = txt[:200] + "..."
					}
					sb.WriteString(fmt.Sprintf("  \"%s\"\n", txt))
				}
			}

		case "CNAME":
			cname, err := d.resolver.LookupCNAME(ctx, domain)
			if err == nil && cname != "" && cname != domain+"." {
				sb.WriteString(fmt.Sprintf("CNAME: %s\n", cname))
			}
		}
	}

	result := sb.String()
	if strings.Count(result, "\n") <= 2 {
		return fmt.Sprintf("No DNS records found for %s", domain), nil
	}
	return result, nil
}

// discoverSubdomains finds subdomains using Certificate Transparency logs.
func (d *DNSTool) discoverSubdomains(ctx context.Context, domain string) (string, error) {
	endpoint := fmt.Sprintf("%s/?q=%%25.%s&output=json", crtshURL, url.QueryEscape(domain))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("crt.sh request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("crt.sh returned %d", resp.StatusCode)
	}

	var entries []struct {
		NameValue string `json:"name_value"`
		IssuerName string `json:"issuer_name"`
		NotBefore  string `json:"not_before"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return fmt.Sprintf("No certificate transparency data found for %s", domain), nil
	}

	// Deduplicate subdomains
	seen := make(map[string]bool)
	var subdomains []string
	for _, entry := range entries {
		names := strings.Split(entry.NameValue, "\n")
		for _, name := range names {
			name = strings.TrimSpace(strings.ToLower(name))
			if name != "" && !seen[name] && strings.HasSuffix(name, domain) {
				seen[name] = true
				subdomains = append(subdomains, name)
			}
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== Subdomains for %s (via Certificate Transparency) ===\n", domain))
	sb.WriteString(fmt.Sprintf("Found %d unique subdomains:\n\n", len(subdomains)))

	for i, sub := range subdomains {
		if i >= 100 {
			sb.WriteString(fmt.Sprintf("\n... and %d more (truncated)\n", len(subdomains)-100))
			break
		}
		sb.WriteString(fmt.Sprintf("  %s\n", sub))
	}

	return sb.String(), nil
}

// reverseLookup performs reverse DNS on an IP address.
func (d *DNSTool) reverseLookup(ctx context.Context, ip string) (string, error) {
	names, err := d.resolver.LookupAddr(ctx, ip)
	if err != nil {
		return fmt.Sprintf("No reverse DNS found for %s: %v", ip, err), nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Reverse DNS for %s:\n", ip))
	for _, name := range names {
		sb.WriteString(fmt.Sprintf("  %s\n", name))
	}
	return sb.String(), nil
}

// rdapLookup queries RDAP for domain registration information.
func (d *DNSTool) rdapLookup(ctx context.Context, domain string) (string, error) {
	endpoint := fmt.Sprintf("%s/domain/%s", rdapURL, url.PathEscape(domain))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/rdap+json")

	resp, err := d.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("RDAP request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Sprintf("RDAP lookup failed for %s (status %d)", domain, resp.StatusCode), nil
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}

	return d.formatRDAP(domain, result), nil
}

func (d *DNSTool) formatRDAP(domain string, data map[string]any) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== RDAP Info for %s ===\n\n", domain))

	if name, ok := data["name"].(string); ok {
		sb.WriteString(fmt.Sprintf("Domain: %s\n", name))
	}

	if status, ok := data["status"].([]any); ok {
		strs := make([]string, 0, len(status))
		for _, s := range status {
			strs = append(strs, fmt.Sprintf("%v", s))
		}
		sb.WriteString(fmt.Sprintf("Status: %s\n", strings.Join(strs, ", ")))
	}

	// Nameservers
	if nameservers, ok := data["nameservers"].([]any); ok {
		sb.WriteString("Nameservers:\n")
		for _, ns := range nameservers {
			if nsMap, ok := ns.(map[string]any); ok {
				if host, ok := nsMap["ldhName"].(string); ok {
					sb.WriteString(fmt.Sprintf("  %s\n", host))
				}
			}
		}
	}

	// Events (registration, expiration, etc.)
	if events, ok := data["events"].([]any); ok {
		sb.WriteString("Events:\n")
		for _, e := range events {
			if ev, ok := e.(map[string]any); ok {
				action, _ := ev["eventAction"].(string)
				date, _ := ev["eventDate"].(string)
				sb.WriteString(fmt.Sprintf("  %s: %s\n", action, date))
			}
		}
	}

	// Entities (registrant, registrar, etc.)
	if entities, ok := data["entities"].([]any); ok {
		for _, e := range entities {
			if entity, ok := e.(map[string]any); ok {
				if roles, ok := entity["roles"].([]any); ok {
					roleStrs := make([]string, 0, len(roles))
					for _, r := range roles {
						roleStrs = append(roleStrs, fmt.Sprintf("%v", r))
					}

					sb.WriteString(fmt.Sprintf("\n%s:\n", strings.Join(roleStrs, ", ")))

					if vcard, ok := entity["vcardArray"].([]any); ok && len(vcard) > 1 {
						if entries, ok := vcard[1].([]any); ok {
							for _, entry := range entries {
								if arr, ok := entry.([]any); ok && len(arr) >= 4 {
									prop, _ := arr[0].(string)
									val := fmt.Sprintf("%v", arr[3])
									if prop == "fn" || prop == "org" || prop == "email" {
										sb.WriteString(fmt.Sprintf("  %s: %s\n", prop, val))
									}
								}
							}
						}
					}
				}
			}
		}
	}

	return sb.String()
}
