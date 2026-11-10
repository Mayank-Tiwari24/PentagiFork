package tools

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPreFilterTerminalResult_UnknownCommand(t *testing.T) {
	// Generate large output > DefaultResultSizeLimit
	largeOutput := strings.Repeat("arbitrary text line\n", 1000)
	filtered := preFilterTerminalResult("cat something.txt", largeOutput)
	assert.Equal(t, largeOutput, filtered, "unknown command output must not be modified")
}

func TestPreFilterTerminalResult_SmallOutput(t *testing.T) {
	smallOutput := "small output"
	filtered := preFilterTerminalResult("nmap 127.0.0.1", smallOutput)
	assert.Equal(t, smallOutput, filtered, "output <= 16KB should not be filtered")
}

func TestPreFilterTerminalResult_DirBrute(t *testing.T) {
	var input strings.Builder
	input.WriteString("Starting gobuster dir on http://target.com\n")
	input.WriteString("Progress: 100/100000\n")
	for i := 0; i < 500; i++ {
		input.WriteString("Progress: checking paths...\n")
	}
	input.WriteString("Found: /admin (Status: 200) [Size: 1234]\n")
	input.WriteString("Found: /login (Status: 301) [Size: 567]\n")
	input.WriteString("Found: /secret (Status: 403) [Size: 890]\n")
	input.WriteString(strings.Repeat("some noise line\n", 1000))

	raw := input.String()
	assert.Greater(t, len(raw), DefaultResultSizeLimit)

	filtered := preFilterTerminalResult("gobuster dir -u http://target.com -w list.txt", raw)
	assert.Contains(t, filtered, "[pre-filtered: web path enumeration")
	assert.Contains(t, filtered, "Found: /admin")
	assert.Contains(t, filtered, "Found: /login")
	assert.Contains(t, filtered, "Found: /secret")
	assert.NotContains(t, filtered, "Progress: checking paths")
}

func TestPreFilterTerminalResult_SQLMap(t *testing.T) {
	var input strings.Builder
	input.WriteString("sqlmap/1.5#stable\n")
	for i := 0; i < 500; i++ {
		input.WriteString("[12:00:00] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'\n")
		input.WriteString("[12:00:01] [PAYLOAD] id=1 AND 1=1\n")
	}
	input.WriteString("[12:05:00] [INFO] GET parameter 'id' is vulnerable.\n")
	input.WriteString("[12:05:01] [INFO] the back-end DBMS is MySQL\n")
	input.WriteString("[12:05:02] [INFO] available databases [2]:\n")
	input.WriteString("[*] information_schema\n")
	input.WriteString("[*] app_db\n")
	input.WriteString(strings.Repeat("trailing log info\n", 800))

	raw := input.String()
	assert.Greater(t, len(raw), DefaultResultSizeLimit)

	filtered := preFilterTerminalResult("sqlmap -u 'http://target.com?id=1' --batch", raw)
	assert.Contains(t, filtered, "[pre-filtered: sqlmap")
	assert.Contains(t, filtered, "parameter 'id' is vulnerable")
	assert.Contains(t, filtered, "the back-end DBMS is MySQL")
	assert.Contains(t, filtered, "[*] app_db")
	assert.NotContains(t, filtered, "[PAYLOAD]")
}

func TestPreFilterTerminalResult_Hydra(t *testing.T) {
	var input strings.Builder
	input.WriteString("Hydra v9.2\n")
	for i := 0; i < 600; i++ {
		input.WriteString("[ATTEMPT] target 10.0.0.1 - login 'user' - pass 'pass' - 1 of 5000\n")
	}
	input.WriteString("[80][http-get] host: 10.0.0.1   login: admin   password: secretPassword\n")
	input.WriteString("[STATUS] 1 valid password found\n")
	input.WriteString(strings.Repeat("footer noise\n", 600))

	raw := input.String()
	assert.Greater(t, len(raw), DefaultResultSizeLimit)

	filtered := preFilterTerminalResult("hydra -l admin -P passlist.txt 10.0.0.1 http-get", raw)
	assert.Contains(t, filtered, "[pre-filtered: credential check")
	assert.Contains(t, filtered, "password: secretPassword")
	assert.Contains(t, filtered, "1 valid password found")
	assert.NotContains(t, filtered, "[ATTEMPT]")
}

func TestPreFilterTerminalResult_Nikto(t *testing.T) {
	var input strings.Builder
	input.WriteString("- Nikto v2.1.6\n")
	for i := 0; i < 800; i++ {
		input.WriteString("Testing server port 80...\n")
	}
	input.WriteString("+ Target IP: 10.0.0.1\n")
	input.WriteString("+ Server: Apache/2.4.41\n")
	input.WriteString("+ OSVDB-3092: /admin/: This might be interesting...\n")
	input.WriteString(strings.Repeat("noise info\n", 600))

	raw := input.String()
	assert.Greater(t, len(raw), DefaultResultSizeLimit)

	filtered := preFilterTerminalResult("nikto -h 10.0.0.1", raw)
	assert.Contains(t, filtered, "[pre-filtered: nikto")
	assert.Contains(t, filtered, "+ Target IP: 10.0.0.1")
	assert.Contains(t, filtered, "+ Server: Apache/2.4.41")
	assert.NotContains(t, filtered, "Testing server port 80...")
}

func TestPreFilterTerminalResult_WPScan(t *testing.T) {
	var input strings.Builder
	input.WriteString("WPScan v3.8.22\n")
	for i := 0; i < 800; i++ {
		input.WriteString("Progress: [========================================] 100%\n")
	}
	input.WriteString("[+] WordPress version 6.0 identified\n")
	input.WriteString("[!] 2 vulnerabilities identified in plugin contact-form-7\n")
	input.WriteString("[i] XML-RPC seems to be enabled: http://target.com/xmlrpc.php\n")
	input.WriteString(strings.Repeat("progress bar noise\n", 600))

	raw := input.String()
	assert.Greater(t, len(raw), DefaultResultSizeLimit)

	filtered := preFilterTerminalResult("wpscan --url http://target.com", raw)
	assert.Contains(t, filtered, "[pre-filtered: wpscan")
	assert.Contains(t, filtered, "[+] WordPress version 6.0 identified")
	assert.Contains(t, filtered, "[!] 2 vulnerabilities identified")
	assert.NotContains(t, filtered, "Progress: [========================================]")
}

func TestEnrichWAFAndRateLimitAdvice(t *testing.T) {
	// Normal response without WAF or rate limit
	normal := "HTTP/1.1 200 OK\nContent-Type: text/html\n\nHello World\n[exit code: 0]"
	assert.Equal(t, normal, enrichWAFAndRateLimitAdvice(normal))

	// HTTP 429 Rate limit
	rateLimited := "HTTP/1.1 429 Too Many Requests\nRetry-After: 60\n[exit code: 0]"
	res429 := enrichWAFAndRateLimitAdvice(rateLimited)
	assert.Contains(t, res429, "[PENTAGI DEFENSE ADVISORY: Target defense triggered]")
	assert.Contains(t, res429, "Rate limit (HTTP 429) detected")

	// Cloudflare challenge
	cfBlocked := "HTTP/1.1 403 Forbidden\ncf-ray: 12345678-SIN\nServer: cloudflare\nAttention Required! | Cloudflare\n[exit code: 0]"
	resCF := enrichWAFAndRateLimitAdvice(cfBlocked)
	assert.Contains(t, resCF, "[PENTAGI DEFENSE ADVISORY: Target defense triggered]")
	assert.Contains(t, resCF, "Cloudflare WAF / challenge page detected")

	// ModSecurity block
	modSec := "HTTP/1.1 406 Not Acceptable\nServer: Apache\nMod_Security error: access denied\n[exit code: 0]"
	resModSec := enrichWAFAndRateLimitAdvice(modSec)
	assert.Contains(t, resModSec, "[PENTAGI DEFENSE ADVISORY: Target defense triggered]")
	assert.Contains(t, resModSec, "ModSecurity WAF detected")
}

