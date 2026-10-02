package attack

// ============================================================================
// MITRE ATT&CK Mapping Engine
//
// Automatically maps agent actions (tool calls, subtask descriptions) to
// MITRE ATT&CK techniques. This enables:
//   - Real-time ATT&CK coverage tracking during a pentest
//   - Attack graph visualization in the frontend
//   - Compliance-ready reporting (maps to specific techniques/tactics)
//   - Cross-flow learning enrichment (patterns tagged with ATT&CK IDs)
// ============================================================================

// Tactic represents a MITRE ATT&CK tactic (the "why" of an attack).
type Tactic struct {
	ID          string `json:"id"`           // e.g., "TA0043"
	Name        string `json:"name"`         // e.g., "Reconnaissance"
	ShortName   string `json:"short_name"`   // e.g., "reconnaissance"
	Description string `json:"description"`
	Order       int    `json:"order"`        // Display order in ATT&CK matrix
}

// Technique represents a MITRE ATT&CK technique (the "how" of an attack).
type Technique struct {
	ID          string   `json:"id"`           // e.g., "T1595" or "T1595.002"
	Name        string   `json:"name"`         // e.g., "Active Scanning"
	TacticIDs   []string `json:"tactic_ids"`   // Which tactics this technique belongs to
	Description string   `json:"description"`
	IsSubtech   bool     `json:"is_subtech"`   // True for sub-techniques (T1595.002)
	ParentID    string   `json:"parent_id"`    // Parent technique ID if sub-technique
	Platforms   []string `json:"platforms"`    // linux, windows, macos, cloud, etc.
}

// ATTCKMapping records that a specific action maps to a technique.
type ATTCKMapping struct {
	TechniqueID string  `json:"technique_id"`
	Confidence  float64 `json:"confidence"`    // 0.0-1.0 — how confident is the mapping
	Source      string  `json:"source"`        // What triggered this mapping (tool name, keyword, etc.)
	FlowID      int64   `json:"flow_id"`
	TaskID      *int64  `json:"task_id,omitempty"`
	SubtaskID   *int64  `json:"subtask_id,omitempty"`
	ToolCallID  *int64  `json:"toolcall_id,omitempty"`
}

// CoverageMatrix shows which techniques were exercised during a pentest.
type CoverageMatrix struct {
	FlowID     int64                     `json:"flow_id"`
	Tactics    []Tactic                  `json:"tactics"`
	Techniques map[string]TechniqueCoverage `json:"techniques"` // keyed by technique ID
	Coverage   CoverageStats              `json:"coverage"`
}

// TechniqueCoverage records how a technique was covered during the pentest.
type TechniqueCoverage struct {
	Technique  Technique     `json:"technique"`
	Mappings   []ATTCKMapping `json:"mappings"`
	Covered    bool          `json:"covered"`
	Confidence float64       `json:"max_confidence"`
}

// CoverageStats summarizes overall ATT&CK coverage.
type CoverageStats struct {
	TotalTechniques   int     `json:"total_techniques"`
	CoveredTechniques int     `json:"covered_techniques"`
	CoveragePercent   float64 `json:"coverage_percent"`
	TacticCoverage    map[string]float64 `json:"tactic_coverage"` // per-tactic coverage %
}

// ============================================================================
// Tool → ATT&CK Technique Mapping
//
// Maps PentAGI tool names and keywords to ATT&CK technique IDs.
// This is the primary auto-mapping mechanism — when a tool is called,
// we look up which ATT&CK techniques it corresponds to.
// ============================================================================

// ToolTechniqueMap maps tool names to their most likely ATT&CK techniques.
// Updated as new tools are added to PentAGI.
var ToolTechniqueMap = map[string][]MappingRule{
	// === Reconnaissance Tools ===
	"web_search": {
		{TechniqueID: "T1593", Confidence: 0.7, Tactic: "reconnaissance"},     // Search Open Websites/Domains
		{TechniqueID: "T1596", Confidence: 0.6, Tactic: "reconnaissance"},     // Search Open Technical Databases
	},
	"browser": {
		{TechniqueID: "T1593", Confidence: 0.8, Tactic: "reconnaissance"},     // Search Open Websites/Domains
		{TechniqueID: "T1593.001", Confidence: 0.7, Tactic: "reconnaissance"}, // Social Media
		{TechniqueID: "T1592", Confidence: 0.5, Tactic: "reconnaissance"},     // Gather Victim Host Information
	},
	"duckduckgo": {
		{TechniqueID: "T1593", Confidence: 0.7, Tactic: "reconnaissance"},
	},
	"google": {
		{TechniqueID: "T1593", Confidence: 0.8, Tactic: "reconnaissance"},
		{TechniqueID: "T1593.003", Confidence: 0.6, Tactic: "reconnaissance"}, // Code Repositories
	},
	"sploitus": {
		{TechniqueID: "T1588.005", Confidence: 0.9, Tactic: "resource-development"}, // Obtain Capabilities: Exploits
		{TechniqueID: "T1588.006", Confidence: 0.7, Tactic: "resource-development"}, // Obtain Capabilities: Vulnerabilities
	},

	// === OSINT Tools ===
	"shodan_search": {
		{TechniqueID: "T1596", Confidence: 0.9, Tactic: "reconnaissance"},     // Search Open Technical Databases
		{TechniqueID: "T1592", Confidence: 0.8, Tactic: "reconnaissance"},     // Gather Victim Host Information
		{TechniqueID: "T1592.002", Confidence: 0.7, Tactic: "reconnaissance"}, // Gather Victim Host Info: Software
		{TechniqueID: "T1590", Confidence: 0.7, Tactic: "reconnaissance"},     // Gather Victim Network Information
	},
	"cve_search": {
		{TechniqueID: "T1588.006", Confidence: 0.9, Tactic: "resource-development"}, // Obtain Capabilities: Vulnerabilities
		{TechniqueID: "T1596", Confidence: 0.7, Tactic: "reconnaissance"},            // Search Open Technical Databases
	},
	"dns_enum": {
		{TechniqueID: "T1596.001", Confidence: 0.9, Tactic: "reconnaissance"},  // Search Open Technical Databases: DNS/Passive DNS
		{TechniqueID: "T1590.002", Confidence: 0.85, Tactic: "reconnaissance"}, // Gather Victim Network Info: DNS
		{TechniqueID: "T1590", Confidence: 0.7, Tactic: "reconnaissance"},      // Gather Victim Network Information
	},

	// === Terminal / Execution Tools ===
	"terminal": {
		{TechniqueID: "T1059.004", Confidence: 0.8, Tactic: "execution"},      // Unix Shell
		{TechniqueID: "T1059", Confidence: 0.7, Tactic: "execution"},          // Command and Scripting Interpreter
	},
	"coder": {
		{TechniqueID: "T1059", Confidence: 0.7, Tactic: "execution"},          // Command and Scripting Interpreter
		{TechniqueID: "T1587.001", Confidence: 0.6, Tactic: "resource-development"}, // Develop Capabilities: Malware
	},

	// === Pentester Agent ===
	"pentester": {
		{TechniqueID: "T1595", Confidence: 0.8, Tactic: "reconnaissance"},     // Active Scanning
		{TechniqueID: "T1595.001", Confidence: 0.7, Tactic: "reconnaissance"}, // Scanning IP Blocks
		{TechniqueID: "T1595.002", Confidence: 0.8, Tactic: "reconnaissance"}, // Vulnerability Scanning
	},

	// === Memory / Knowledge Tools ===
	"search_in_memory": {
		{TechniqueID: "T1213", Confidence: 0.5, Tactic: "collection"},         // Data from Information Repositories
	},
	"search_guide": {
		{TechniqueID: "T1213", Confidence: 0.4, Tactic: "collection"},
	},
	"graphiti_search": {
		{TechniqueID: "T1213", Confidence: 0.4, Tactic: "collection"},
	},

	// === File Operations ===
	"file": {
		{TechniqueID: "T1005", Confidence: 0.6, Tactic: "collection"},         // Data from Local System
		{TechniqueID: "T1083", Confidence: 0.5, Tactic: "discovery"},          // File and Directory Discovery
	},
}

// KeywordTechniqueMap maps keywords found in subtask descriptions or
// tool arguments to ATT&CK techniques. This catches techniques that
// aren't directly tied to a specific tool name.
var KeywordTechniqueMap = map[string][]MappingRule{
	// Network scanning
	"nmap":        {{TechniqueID: "T1046", Confidence: 0.95, Tactic: "discovery"}},          // Network Service Discovery
	"port scan":   {{TechniqueID: "T1046", Confidence: 0.9, Tactic: "discovery"}},
	"masscan":     {{TechniqueID: "T1046", Confidence: 0.95, Tactic: "discovery"}},

	// DNS
	"dns":         {{TechniqueID: "T1596.001", Confidence: 0.8, Tactic: "reconnaissance"}},  // DNS/Passive DNS
	"subdomain":   {{TechniqueID: "T1596.001", Confidence: 0.85, Tactic: "reconnaissance"}},
	"dig":         {{TechniqueID: "T1596.001", Confidence: 0.8, Tactic: "reconnaissance"}},
	"nslookup":    {{TechniqueID: "T1596.001", Confidence: 0.8, Tactic: "reconnaissance"}},

	// Web attacks
	"sql injection":  {{TechniqueID: "T1190", Confidence: 0.95, Tactic: "initial-access"}},  // Exploit Public-Facing Application
	"sqli":           {{TechniqueID: "T1190", Confidence: 0.95, Tactic: "initial-access"}},
	"sqlmap":         {{TechniqueID: "T1190", Confidence: 0.95, Tactic: "initial-access"}},
	"xss":            {{TechniqueID: "T1189", Confidence: 0.8, Tactic: "initial-access"}},    // Drive-by Compromise
	"rce":            {{TechniqueID: "T1190", Confidence: 0.9, Tactic: "initial-access"}},
	"nikto":          {{TechniqueID: "T1595.002", Confidence: 0.9, Tactic: "reconnaissance"}},
	"nuclei":         {{TechniqueID: "T1595.002", Confidence: 0.95, Tactic: "reconnaissance"}},
	"dirb":           {{TechniqueID: "T1083", Confidence: 0.8, Tactic: "discovery"}},          // File and Directory Discovery
	"gobuster":       {{TechniqueID: "T1083", Confidence: 0.85, Tactic: "discovery"}},
	"ffuf":           {{TechniqueID: "T1083", Confidence: 0.85, Tactic: "discovery"}},

	// Credentials
	"brute force":    {{TechniqueID: "T1110", Confidence: 0.95, Tactic: "credential-access"}}, // Brute Force
	"hydra":          {{TechniqueID: "T1110", Confidence: 0.95, Tactic: "credential-access"}},
	"john":           {{TechniqueID: "T1110.002", Confidence: 0.9, Tactic: "credential-access"}}, // Password Cracking
	"hashcat":        {{TechniqueID: "T1110.002", Confidence: 0.95, Tactic: "credential-access"}},
	"credential":     {{TechniqueID: "T1110", Confidence: 0.7, Tactic: "credential-access"}},
	"password":       {{TechniqueID: "T1110", Confidence: 0.6, Tactic: "credential-access"}},

	// Privilege escalation
	"privilege escalation": {{TechniqueID: "T1068", Confidence: 0.9, Tactic: "privilege-escalation"}}, // Exploitation for Privilege Escalation
	"linpeas":       {{TechniqueID: "T1068", Confidence: 0.85, Tactic: "privilege-escalation"}},
	"winpeas":       {{TechniqueID: "T1068", Confidence: 0.85, Tactic: "privilege-escalation"}},
	"sudo":          {{TechniqueID: "T1548.003", Confidence: 0.8, Tactic: "privilege-escalation"}},    // Sudo and Sudo Caching
	"suid":          {{TechniqueID: "T1548.001", Confidence: 0.85, Tactic: "privilege-escalation"}},   // Setuid and Setgid

	// Lateral movement
	"ssh":            {{TechniqueID: "T1021.004", Confidence: 0.8, Tactic: "lateral-movement"}},  // Remote Services: SSH
	"rdp":            {{TechniqueID: "T1021.001", Confidence: 0.8, Tactic: "lateral-movement"}},  // Remote Desktop Protocol
	"smb":            {{TechniqueID: "T1021.002", Confidence: 0.8, Tactic: "lateral-movement"}},  // SMB/Windows Admin Shares
	"lateral":        {{TechniqueID: "T1021", Confidence: 0.7, Tactic: "lateral-movement"}},

	// Exploitation frameworks
	"metasploit":     {{TechniqueID: "T1203", Confidence: 0.9, Tactic: "execution"}},             // Exploitation for Client Execution
	"msfconsole":     {{TechniqueID: "T1203", Confidence: 0.9, Tactic: "execution"}},
	"exploit":        {{TechniqueID: "T1190", Confidence: 0.7, Tactic: "initial-access"}},
	"payload":        {{TechniqueID: "T1587.001", Confidence: 0.7, Tactic: "resource-development"}},

	// Network sniffing
	"wireshark":      {{TechniqueID: "T1040", Confidence: 0.9, Tactic: "credential-access"}},     // Network Sniffing
	"tcpdump":        {{TechniqueID: "T1040", Confidence: 0.9, Tactic: "credential-access"}},

	// Discovery
	"whoami":         {{TechniqueID: "T1033", Confidence: 0.9, Tactic: "discovery"}},              // System Owner/User Discovery
	"ifconfig":       {{TechniqueID: "T1016", Confidence: 0.9, Tactic: "discovery"}},              // System Network Configuration Discovery
	"ip addr":        {{TechniqueID: "T1016", Confidence: 0.9, Tactic: "discovery"}},
	"netstat":        {{TechniqueID: "T1049", Confidence: 0.9, Tactic: "discovery"}},              // System Network Connections Discovery
	"uname":          {{TechniqueID: "T1082", Confidence: 0.9, Tactic: "discovery"}},              // System Information Discovery
	"cat /etc/passwd":{{TechniqueID: "T1087.001", Confidence: 0.9, Tactic: "discovery"}},          // Account Discovery: Local Account

	// Persistence
	"cron":           {{TechniqueID: "T1053.003", Confidence: 0.8, Tactic: "persistence"}},        // Scheduled Task/Job: Cron
	"backdoor":       {{TechniqueID: "T1505.003", Confidence: 0.8, Tactic: "persistence"}},        // Web Shell
	"webshell":       {{TechniqueID: "T1505.003", Confidence: 0.95, Tactic: "persistence"}},
	"reverse shell":  {{TechniqueID: "T1059.004", Confidence: 0.9, Tactic: "execution"}},

	// Data exfiltration
	"exfiltrat":      {{TechniqueID: "T1041", Confidence: 0.8, Tactic: "exfiltration"}},           // Exfiltration Over C2 Channel
	"download":       {{TechniqueID: "T1005", Confidence: 0.6, Tactic: "collection"}},
}

// MappingRule defines a single tool/keyword → technique mapping with confidence.
type MappingRule struct {
	TechniqueID string  `json:"technique_id"`
	Confidence  float64 `json:"confidence"`
	Tactic      string  `json:"tactic"`
}

// ============================================================================
// MITRE ATT&CK Tactics Reference (Enterprise, v14)
// ============================================================================

// AllTactics returns the complete ordered list of ATT&CK Enterprise tactics.
var AllTactics = []Tactic{
	{ID: "TA0043", Name: "Reconnaissance", ShortName: "reconnaissance", Order: 1,
		Description: "Gathering information to plan future adversary operations"},
	{ID: "TA0042", Name: "Resource Development", ShortName: "resource-development", Order: 2,
		Description: "Establishing resources to support operations"},
	{ID: "TA0001", Name: "Initial Access", ShortName: "initial-access", Order: 3,
		Description: "Trying to get into your network"},
	{ID: "TA0002", Name: "Execution", ShortName: "execution", Order: 4,
		Description: "Trying to run malicious code"},
	{ID: "TA0003", Name: "Persistence", ShortName: "persistence", Order: 5,
		Description: "Trying to maintain their foothold"},
	{ID: "TA0004", Name: "Privilege Escalation", ShortName: "privilege-escalation", Order: 6,
		Description: "Trying to gain higher-level permissions"},
	{ID: "TA0005", Name: "Defense Evasion", ShortName: "defense-evasion", Order: 7,
		Description: "Trying to avoid being detected"},
	{ID: "TA0006", Name: "Credential Access", ShortName: "credential-access", Order: 8,
		Description: "Trying to steal account names and passwords"},
	{ID: "TA0007", Name: "Discovery", ShortName: "discovery", Order: 9,
		Description: "Trying to figure out your environment"},
	{ID: "TA0008", Name: "Lateral Movement", ShortName: "lateral-movement", Order: 10,
		Description: "Trying to move through your environment"},
	{ID: "TA0009", Name: "Collection", ShortName: "collection", Order: 11,
		Description: "Trying to gather data of interest"},
	{ID: "TA0011", Name: "Command and Control", ShortName: "command-and-control", Order: 12,
		Description: "Trying to communicate with compromised systems"},
	{ID: "TA0010", Name: "Exfiltration", ShortName: "exfiltration", Order: 13,
		Description: "Trying to steal data"},
	{ID: "TA0040", Name: "Impact", ShortName: "impact", Order: 14,
		Description: "Trying to manipulate, interrupt, or destroy systems and data"},
}

// TacticByShortName returns the tactic matching the given short name, or nil.
func TacticByShortName(shortName string) *Tactic {
	for _, t := range AllTactics {
		if t.ShortName == shortName {
			return &t
		}
	}
	return nil
}
