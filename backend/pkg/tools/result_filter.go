package tools

import (
	"fmt"
	"regexp"
	"strings"
)

// preFilterTerminalResult reduces large terminal output to only the
// security-relevant essentials BEFORE the LLM summarizer sees it.
// This eliminates ~90% of summarizer calls by bringing most results
// under the DefaultResultSizeLimit (16KB) without losing any
// actionable intelligence.
//
// Only known, high-noise commands are filtered. Unknown commands pass
// through untouched so no offensive output is ever silently discarded.
func preFilterTerminalResult(command, result string) string {
	if len(result) <= DefaultResultSizeLimit {
		return result // Already small enough, no filtering needed
	}

	cmdLower := strings.ToLower(command)

	switch {
	case isNmapCommand(cmdLower):
		return filterNmapOutput(result)
	case isCurlCommand(cmdLower):
		return filterCurlOutput(result)
	case isSubfinderCommand(cmdLower):
		return filterSubfinderOutput(result)
	case isDNSEnumCommand(cmdLower):
		return filterDNSEnumOutput(result)
	case isNucleiCommand(cmdLower):
		return filterNucleiOutput(result)
	case isDirBruteCommand(cmdLower):
		return filterDirBruteOutput(result)
	case isSQLMapCommand(cmdLower):
		return filterSQLMapOutput(result)
	case isHydraCommand(cmdLower):
		return filterHydraOutput(result)
	case isNiktoCommand(cmdLower):
		return filterNiktoOutput(result)
	case isWPScanCommand(cmdLower):
		return filterWPScanOutput(result)
	default:
		return result // Unknown commands: never touch, preserve full output
	}
}

// --- Command detection helpers ---

func isNmapCommand(cmd string) bool {
	return strings.Contains(cmd, "nmap")
}

func isCurlCommand(cmd string) bool {
	return strings.HasPrefix(strings.TrimSpace(cmd), "curl") ||
		strings.Contains(cmd, "| curl") ||
		strings.Contains(cmd, "&& curl")
}

func isSubfinderCommand(cmd string) bool {
	return strings.Contains(cmd, "subfinder") ||
		strings.Contains(cmd, "amass") ||
		strings.Contains(cmd, "assetfinder")
}

func isDNSEnumCommand(cmd string) bool {
	return strings.Contains(cmd, "dnsrecon") ||
		strings.Contains(cmd, "dnsenum") ||
		strings.Contains(cmd, "fierce")
}

func isNucleiCommand(cmd string) bool {
	return strings.Contains(cmd, "nuclei")
}

func isDirBruteCommand(cmd string) bool {
	return strings.Contains(cmd, "gobuster") ||
		strings.Contains(cmd, "ffuf") ||
		strings.Contains(cmd, "feroxbuster") ||
		strings.Contains(cmd, "dirsearch")
}

func isSQLMapCommand(cmd string) bool {
	return strings.Contains(cmd, "sqlmap")
}

func isHydraCommand(cmd string) bool {
	return strings.Contains(cmd, "hydra") ||
		strings.Contains(cmd, "medusa") ||
		strings.Contains(cmd, "ncrack")
}

func isNiktoCommand(cmd string) bool {
	return strings.Contains(cmd, "nikto")
}

func isWPScanCommand(cmd string) bool {
	return strings.Contains(cmd, "wpscan")
}

// --- Filters ---

// nmapOpenPortRegex matches lines like "80/tcp   open  http    Apache httpd 2.4.41"
var nmapOpenPortRegex = regexp.MustCompile(`(?m)^\s*(\d+/(tcp|udp)\s+open\s+.*)$`)

// nmapHostUpRegex matches the "Host is up" line
var nmapHostUpRegex = regexp.MustCompile(`(?m)^.*Host is up.*$`)

// nmapScriptRegex matches NSE script output lines (e.g., "|  http-title: ...")
var nmapScriptRegex = regexp.MustCompile(`(?m)^[|_].*$`)

// nmapOSRegex matches OS detection lines
var nmapOSRegex = regexp.MustCompile(`(?m)^.*(?:OS details|Running|Aggressive OS guesses):.*$`)

// nmapSummaryRegex matches the Nmap scan summary line
var nmapSummaryRegex = regexp.MustCompile(`(?m)^Nmap done:.*$`)

func filterNmapOutput(result string) string {
	var sb strings.Builder
	sb.WriteString("[pre-filtered: nmap — only open ports, scripts, OS, and summary retained]\n\n")

	// Extract host-up lines
	for _, match := range nmapHostUpRegex.FindAllString(result, -1) {
		sb.WriteString(match)
		sb.WriteByte('\n')
	}

	// Extract all open port lines (the critical intelligence)
	openPorts := nmapOpenPortRegex.FindAllString(result, -1)
	if len(openPorts) > 0 {
		sb.WriteString("\nOpen ports:\n")
		for _, port := range openPorts {
			sb.WriteString(strings.TrimSpace(port))
			sb.WriteByte('\n')
		}
	}

	// Extract NSE script output (vulns, titles, SSL info)
	scripts := nmapScriptRegex.FindAllString(result, -1)
	if len(scripts) > 0 {
		sb.WriteString("\nScript output:\n")
		for _, script := range scripts {
			sb.WriteString(script)
			sb.WriteByte('\n')
		}
	}

	// Extract OS detection
	for _, match := range nmapOSRegex.FindAllString(result, -1) {
		sb.WriteString(match)
		sb.WriteByte('\n')
	}

	// Extract summary
	for _, match := range nmapSummaryRegex.FindAllString(result, -1) {
		sb.WriteByte('\n')
		sb.WriteString(match)
		sb.WriteByte('\n')
	}

	filtered := sb.String()
	if len(filtered) < 100 {
		// Filter extracted almost nothing — return original to avoid data loss
		return result
	}

	return filtered
}

// curlHeaderEndRegex matches the blank line separating HTTP headers from body
var curlHeaderEndRegex = regexp.MustCompile(`\r?\n\r?\n`)

const curlBodyPreviewBytes = 1024 // Keep first 1KB of response body

func filterCurlOutput(result string) string {
	var sb strings.Builder
	sb.WriteString("[pre-filtered: curl — headers + first 1KB body retained]\n\n")

	// Find header/body boundary
	loc := curlHeaderEndRegex.FindStringIndex(result)
	if loc == nil {
		// No clear header/body split — keep first 4KB
		limit := min(len(result), 4*1024)
		sb.WriteString(result[:limit])
		if len(result) > limit {
			fmt.Fprintf(&sb, "\n... [body truncated, full size: %d bytes]\n", len(result))
		}
		return sb.String()
	}

	// Keep all headers
	headerEnd := loc[1]
	sb.WriteString(result[:headerEnd])

	// Keep first curlBodyPreviewBytes of body
	body := result[headerEnd:]
	bodyLimit := min(len(body), curlBodyPreviewBytes)
	sb.WriteString(body[:bodyLimit])

	if len(body) > bodyLimit {
		fmt.Fprintf(&sb, "\n... [body truncated, full size: %d bytes]\n", len(body))
	}

	return sb.String()
}

func filterSubfinderOutput(result string) string {
	lines := strings.Split(strings.TrimSpace(result), "\n")

	var domains []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		domains = append(domains, trimmed)
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "[pre-filtered: subdomain enumeration — %d total domains found]\n\n", len(domains))

	// Keep first 30 domains (enough for intelligence), save rest as count
	showCount := min(len(domains), 30)
	for i := 0; i < showCount; i++ {
		sb.WriteString(domains[i])
		sb.WriteByte('\n')
	}

	if len(domains) > showCount {
		fmt.Fprintf(&sb, "\n... and %d more domains (full list in terminal output)\n", len(domains)-showCount)
	}

	return sb.String()
}

func filterDNSEnumOutput(result string) string {
	// DNS enum tools produce verbose output; keep lines with actual records
	var sb strings.Builder
	sb.WriteString("[pre-filtered: DNS enumeration — record lines retained]\n\n")

	recordIndicators := []string{" A ", " AAAA ", " MX ", " NS ", " TXT ", " CNAME ", " SOA ", " PTR ", " SRV "}

	count := 0
	for _, line := range strings.Split(result, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		isRecord := false
		for _, indicator := range recordIndicators {
			if strings.Contains(line, indicator) {
				isRecord = true
				break
			}
		}

		if isRecord || strings.HasPrefix(trimmed, "[+]") || strings.HasPrefix(trimmed, "[*]") {
			sb.WriteString(trimmed)
			sb.WriteByte('\n')
			count++
		}
	}

	if count == 0 {
		return result // No records extracted, return original
	}

	fmt.Fprintf(&sb, "\n[%d record lines extracted from %d bytes of output]\n", count, len(result))
	return sb.String()
}

func filterNucleiOutput(result string) string {
	// Nuclei outputs findings with severity tags; keep ONLY finding lines
	var sb strings.Builder
	sb.WriteString("[pre-filtered: nuclei — finding lines retained]\n\n")

	severityIndicators := []string{"[info]", "[low]", "[medium]", "[high]", "[critical]", "[unknown]"}
	count := 0

	for _, line := range strings.Split(result, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		isFinding := false
		for _, indicator := range severityIndicators {
			if strings.Contains(strings.ToLower(trimmed), indicator) {
				isFinding = true
				break
			}
		}

		// Also keep lines starting with [ which are typically nuclei results
		if isFinding || (len(trimmed) > 0 && trimmed[0] == '[') {
			sb.WriteString(trimmed)
			sb.WriteByte('\n')
			count++
		}
	}

	if count == 0 {
		return result // No findings extracted, return original
	}

	fmt.Fprintf(&sb, "\n[%d findings extracted from %d bytes of output]\n", count, len(result))
	return sb.String()
}

func filterDirBruteOutput(result string) string {
	var sb strings.Builder
	sb.WriteString("[pre-filtered: web path enumeration — discovered paths retained]\n\n")

	statusIndicators := []string{
		"Status: 200", "Status: 204", "Status: 301", "Status: 302", "Status: 307", "Status: 401", "Status: 403",
		"200 OK", "301 Moved", "302 Found", "401 Unauthorized", "403 Forbidden",
		" 200 ", " 301 ", " 302 ", " 401 ", " 403 ",
	}

	count := 0
	lines := strings.Split(result, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if strings.HasPrefix(trimmed, "Progress:") ||
			strings.HasPrefix(trimmed, "::") ||
			strings.Contains(trimmed, "Starting gobuster") ||
			strings.Contains(trimmed, "Starting feroxbuster") {
			continue
		}

		matched := false
		if strings.HasPrefix(trimmed, "Found:") || strings.HasPrefix(trimmed, "-->") || strings.HasPrefix(trimmed, "[+]") {
			matched = true
		} else {
			for _, indicator := range statusIndicators {
				if strings.Contains(trimmed, indicator) {
					matched = true
					break
				}
			}
		}

		if matched {
			sb.WriteString(trimmed)
			sb.WriteByte('\n')
			count++
			if count >= 60 {
				fmt.Fprintf(&sb, "\n... [truncated at 60 paths to preserve context window, %d total lines]\n", len(lines))
				break
			}
		}
	}

	if count == 0 {
		return result
	}

	fmt.Fprintf(&sb, "\n[%d paths extracted from %d bytes of output]\n", count, len(result))
	return sb.String()
}

func filterSQLMapOutput(result string) string {
	var sb strings.Builder
	sb.WriteString("[pre-filtered: sqlmap — vulnerability and parameter findings retained]\n\n")

	keyIndicators := []string{
		"is vulnerable",
		"might be injectable",
		"back-end DBMS",
		"web server operating system",
		"web application technology",
		"available databases",
		"Database:",
		"Table:",
		"fetched data:",
		"[CRITICAL]",
		"[WARNING]",
		"[+]",
		"[*]",
		"[!]",
	}

	count := 0
	lines := strings.Split(result, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if strings.Contains(trimmed, "[INFO] testing ") ||
			strings.Contains(trimmed, "[INFO] resumed: ") ||
			strings.Contains(trimmed, "[PAYLOAD] ") {
			continue
		}

		matched := false
		lower := strings.ToLower(trimmed)
		for _, indicator := range keyIndicators {
			if strings.Contains(lower, strings.ToLower(indicator)) {
				matched = true
				break
			}
		}

		if matched {
			sb.WriteString(trimmed)
			sb.WriteByte('\n')
			count++
		}
	}

	if count == 0 {
		return result
	}

	fmt.Fprintf(&sb, "\n[%d key lines extracted from %d bytes of output]\n", count, len(result))
	return sb.String()
}

func filterHydraOutput(result string) string {
	var sb strings.Builder
	sb.WriteString("[pre-filtered: credential check — valid logins and summary retained]\n\n")

	count := 0
	lines := strings.Split(result, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if strings.HasPrefix(trimmed, "[ATTEMPT]") {
			continue
		}

		isKeyLine := strings.Contains(trimmed, "login:") ||
			strings.Contains(trimmed, "password:") ||
			strings.Contains(trimmed, "host:") ||
			strings.Contains(trimmed, "valid password found") ||
			strings.HasPrefix(trimmed, "[DATA]") ||
			strings.HasPrefix(trimmed, "[STATUS]") ||
			strings.HasPrefix(trimmed, "[ERROR]") ||
			strings.HasPrefix(trimmed, "[+]")

		if isKeyLine {
			sb.WriteString(trimmed)
			sb.WriteByte('\n')
			count++
		}
	}

	if count == 0 {
		return result
	}

	fmt.Fprintf(&sb, "\n[%d result lines extracted from %d bytes of output]\n", count, len(result))
	return sb.String()
}

func filterNiktoOutput(result string) string {
	var sb strings.Builder
	sb.WriteString("[pre-filtered: nikto — findings retained]\n\n")

	count := 0
	lines := strings.Split(result, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if strings.HasPrefix(trimmed, "+") {
			sb.WriteString(trimmed)
			sb.WriteByte('\n')
			count++
		}
	}

	if count == 0 {
		return result
	}

	fmt.Fprintf(&sb, "\n[%d finding lines extracted from %d bytes of output]\n", count, len(result))
	return sb.String()
}

func filterWPScanOutput(result string) string {
	var sb strings.Builder
	sb.WriteString("[pre-filtered: wpscan — security findings retained]\n\n")

	count := 0
	lines := strings.Split(result, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if strings.HasPrefix(trimmed, "[+]") ||
			strings.HasPrefix(trimmed, "[!]") ||
			strings.HasPrefix(trimmed, "[i]") {
			sb.WriteString(trimmed)
			sb.WriteByte('\n')
			count++
		}
	}

	if count == 0 {
		return result
	}

	fmt.Fprintf(&sb, "\n[%d finding lines extracted from %d bytes of output]\n", count, len(result))
	return sb.String()
}

