package knowledge

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"pentagi/pkg/database"
	"pentagi/pkg/providers/embeddings"

	"github.com/sirupsen/logrus"
	"github.com/vxcontrol/langchaingo/schema"
	"github.com/vxcontrol/langchaingo/vectorstores"
	"github.com/vxcontrol/langchaingo/vectorstores/pgvector"
)

// ============================================================================
// Cross-Flow Learning Engine
//
// This module enables PentAGI to learn from ALL previous pentests, not just the
// current flow. When a new flow starts, the agent can query: "Have I seen a
// similar target before? What attack strategies worked?"
//
// Architecture:
//   - AttackPattern: a structured record of what worked (or didn't) during a pentest
//   - GlobalKnowledge: cross-flow search/store layer on top of pgvector
//   - PatternMatcher: ranks and merges global + flow-local knowledge
// ============================================================================

// AttackPatternType classifies what kind of knowledge is being stored.
type AttackPatternType string

const (
	// PatternSuccessfulAttack records an attack vector that achieved its goal.
	PatternSuccessfulAttack AttackPatternType = "successful_attack"

	// PatternFailedAttack records an attack that was attempted but didn't work,
	// along with why it failed — so the agent doesn't repeat the same mistake.
	PatternFailedAttack AttackPatternType = "failed_attack"

	// PatternToolSequence records a sequence of tools that effectively
	// accomplished a subtask type (e.g., "to enumerate subdomains, use:
	// dns_enum → web_search → nmap").
	PatternToolSequence AttackPatternType = "tool_sequence"

	// PatternTargetProfile records a discovered target profile (OS, services,
	// frameworks) that can inform initial reconnaissance on similar targets.
	PatternTargetProfile AttackPatternType = "target_profile"

	// PatternVulnerability records a discovered vulnerability with exploitation
	// details — the crown jewel of cross-flow learning.
	PatternVulnerability AttackPatternType = "vulnerability"

	// PatternRemediation records a remediation/mitigation that was observed
	// during testing — useful context for report generation.
	PatternRemediation AttackPatternType = "remediation"
)

// AttackPattern represents a reusable piece of pentest knowledge.
type AttackPattern struct {
	// Identity
	ID        string            `json:"id"`
	Type      AttackPatternType `json:"type"`
	CreatedAt time.Time         `json:"created_at"`

	// Source — which flow/task produced this knowledge
	SourceFlowID    *int64 `json:"source_flow_id,omitempty"`
	SourceTaskID    *int64 `json:"source_task_id,omitempty"`
	SourceSubtaskID *int64 `json:"source_subtask_id,omitempty"`
	UserID          int64  `json:"user_id"`

	// Content — the actual knowledge
	Title       string `json:"title"`       // Short description (used for embedding)
	Description string `json:"description"` // Detailed explanation
	Content     string `json:"content"`     // Full technical details

	// Context — what was the target/environment
	TargetType    string   `json:"target_type,omitempty"`    // e.g., "web_app", "network", "api", "cloud"
	TargetTech    []string `json:"target_tech,omitempty"`    // e.g., ["nginx", "php", "mysql"]
	TargetOS      string   `json:"target_os,omitempty"`      // e.g., "linux", "windows"
	AttackSurface string   `json:"attack_surface,omitempty"` // e.g., "external", "internal", "wireless"

	// Effectiveness — how well did this work?
	Success    bool    `json:"success"`              // Did it achieve its goal?
	Confidence float64 `json:"confidence"`           // 0.0-1.0, how confident are we this is reusable
	UseCount   int     `json:"use_count"`            // How many times has this been successfully reused
	LastUsed   *time.Time `json:"last_used,omitempty"` // When was this last applied

	// MITRE ATT&CK mapping
	ATTACKTechniques []string `json:"attack_techniques,omitempty"` // e.g., ["T1059.004", "T1046"]
	ATTACKTactics    []string `json:"attack_tactics,omitempty"`    // e.g., ["execution", "discovery"]

	// Tool sequence — for PatternToolSequence type
	ToolChain []ToolChainStep `json:"tool_chain,omitempty"`

	// Vulnerability details — for PatternVulnerability type
	CVE      string  `json:"cve,omitempty"`
	CVSS     float64 `json:"cvss,omitempty"`
	Severity string  `json:"severity,omitempty"` // critical, high, medium, low, info
}

// ToolChainStep records one step in a successful tool sequence.
type ToolChainStep struct {
	ToolName    string `json:"tool_name"`
	Description string `json:"description"`
	Order       int    `json:"order"`
	Duration    float64 `json:"duration_seconds,omitempty"`
}

// GlobalKnowledge provides cross-flow knowledge search and storage.
// It sits on top of the existing pgvector store but uses a separate
// collection and metadata schema for attack patterns.
type GlobalKnowledge struct {
	store             *pgvector.Store
	embedder          embeddings.Embedder
	db                database.Querier
	maxEmbeddingBytes int
	logger            *logrus.Entry
}

// NewGlobalKnowledge creates a new cross-flow knowledge engine.
func NewGlobalKnowledge(
	store *pgvector.Store,
	embedder embeddings.Embedder,
	db database.Querier,
	maxEmbeddingBytes int,
) *GlobalKnowledge {
	return &GlobalKnowledge{
		store:             store,
		embedder:          embedder,
		db:                db,
		maxEmbeddingBytes: maxEmbeddingBytes,
		logger:            logrus.WithField("component", "global-knowledge"),
	}
}

const (
	globalKnowledgeCollection = "attack_patterns"
	globalSearchThreshold     = 0.25
	globalSearchMaxResults    = 10
)

// StorePattern persists an attack pattern to the global knowledge base.
// The pattern's Title + Description are embedded for semantic search.
func (gk *GlobalKnowledge) StorePattern(ctx context.Context, pattern AttackPattern) error {
	if gk.store == nil || !gk.embedder.IsAvailable() {
		return fmt.Errorf("embedding provider not available")
	}

	// Build the text to embed — combine title, description, and key context
	embeddingText := buildEmbeddingText(pattern)

	// Truncate to max embedding bytes
	if len(embeddingText) > gk.maxEmbeddingBytes {
		embeddingText = embeddingText[:gk.maxEmbeddingBytes]
	}

	// Serialize the full pattern as metadata
	patternJSON, err := json.Marshal(pattern)
	if err != nil {
		return fmt.Errorf("failed to serialize attack pattern: %w", err)
	}

	metadata := map[string]any{
		"pattern_type":    string(pattern.Type),
		"success":         pattern.Success,
		"confidence":      pattern.Confidence,
		"target_type":     pattern.TargetType,
		"target_os":       pattern.TargetOS,
		"attack_surface":  pattern.AttackSurface,
		"user_id":         pattern.UserID,
		"full_pattern":    string(patternJSON),
		"doc_type":        "attack_pattern",
		"collection_name": globalKnowledgeCollection,
	}

	// Add source flow info if available
	if pattern.SourceFlowID != nil {
		metadata["source_flow_id"] = *pattern.SourceFlowID
	}

	// Add MITRE ATT&CK info
	if len(pattern.ATTACKTechniques) > 0 {
		metadata["attack_techniques"] = strings.Join(pattern.ATTACKTechniques, ",")
	}

	// Add vulnerability info
	if pattern.CVE != "" {
		metadata["cve"] = pattern.CVE
		metadata["cvss"] = pattern.CVSS
		metadata["severity"] = pattern.Severity
	}

	doc := schema.Document{
		PageContent: embeddingText,
		Metadata:    metadata,
	}

	_, err = gk.store.AddDocuments(ctx, []schema.Document{doc})
	if err != nil {
		return fmt.Errorf("failed to store attack pattern: %w", err)
	}

	gk.logger.WithFields(logrus.Fields{
		"pattern_type": pattern.Type,
		"title":        pattern.Title,
		"success":      pattern.Success,
	}).Info("attack pattern stored in global knowledge base")

	return nil
}

// SearchPatterns finds attack patterns similar to the given query.
// Returns patterns ranked by semantic similarity, optionally filtered.
func (gk *GlobalKnowledge) SearchPatterns(
	ctx context.Context,
	query string,
	filter *PatternSearchFilter,
) ([]ScoredPattern, error) {
	if gk.store == nil || !gk.embedder.IsAvailable() {
		return nil, fmt.Errorf("embedding provider not available")
	}

	// Build metadata filters
	metadataFilter := map[string]any{
		"collection_name": globalKnowledgeCollection,
		"doc_type":        "attack_pattern",
	}

	if filter != nil {
		if filter.Type != "" {
			metadataFilter["pattern_type"] = string(filter.Type)
		}
		if filter.TargetType != "" {
			metadataFilter["target_type"] = filter.TargetType
		}
		if filter.TargetOS != "" {
			metadataFilter["target_os"] = filter.TargetOS
		}
		if filter.SuccessOnly {
			metadataFilter["success"] = true
		}
	}

	maxResults := globalSearchMaxResults
	if filter != nil && filter.MaxResults > 0 {
		maxResults = filter.MaxResults
	}

	docs, err := gk.store.SimilaritySearch(
		ctx,
		query,
		maxResults,
		vectorstores.WithScoreThreshold(globalSearchThreshold),
		vectorstores.WithFilters(metadataFilter),
	)
	if err != nil {
		return nil, fmt.Errorf("global knowledge search failed: %w", err)
	}

	patterns := make([]ScoredPattern, 0, len(docs))
	for _, doc := range docs {
		patternJSON, ok := doc.Metadata["full_pattern"].(string)
		if !ok {
			continue
		}

		var pattern AttackPattern
		if err := json.Unmarshal([]byte(patternJSON), &pattern); err != nil {
			gk.logger.WithError(err).Warn("failed to deserialize stored attack pattern")
			continue
		}

		score := 0.0
		if s, ok := doc.Metadata["score"].(float64); ok {
			score = s
		}

		patterns = append(patterns, ScoredPattern{
			Pattern: pattern,
			Score:   score,
		})
	}

	return patterns, nil
}

// SearchForTarget finds all knowledge relevant to a specific target profile.
// This is called at the start of a new flow to load context from previous pentests.
func (gk *GlobalKnowledge) SearchForTarget(
	ctx context.Context,
	targetDescription string,
	targetType string,
	targetTech []string,
) ([]ScoredPattern, error) {
	// Build a rich query combining the target description with technology context
	queryParts := []string{targetDescription}
	if targetType != "" {
		queryParts = append(queryParts, "target type: "+targetType)
	}
	if len(targetTech) > 0 {
		queryParts = append(queryParts, "technologies: "+strings.Join(targetTech, ", "))
	}

	query := strings.Join(queryParts, ". ")

	return gk.SearchPatterns(ctx, query, &PatternSearchFilter{
		SuccessOnly: true, // Start with successful patterns
		MaxResults:  globalSearchMaxResults,
	})
}

// GetAttackPlaybook returns a structured "playbook" for the given target —
// an ordered set of recommended actions based on past successful pentests
// against similar targets.
func (gk *GlobalKnowledge) GetAttackPlaybook(
	ctx context.Context,
	targetDescription string,
	targetType string,
) (*AttackPlaybook, error) {
	// Search for successful attack patterns against similar targets
	patterns, err := gk.SearchPatterns(ctx, targetDescription, &PatternSearchFilter{
		SuccessOnly: true,
		MaxResults:  20,
	})
	if err != nil {
		return nil, err
	}

	if len(patterns) == 0 {
		return &AttackPlaybook{
			TargetType:  targetType,
			Description: "No previous attack patterns found for similar targets",
			Phases:      nil,
		}, nil
	}

	playbook := &AttackPlaybook{
		TargetType:  targetType,
		Description: fmt.Sprintf("Playbook compiled from %d previous successful attacks on similar targets", len(patterns)),
		Phases:      buildPlaybookPhases(patterns),
	}

	return playbook, nil
}

// IncrementUseCount updates the use_count and last_used timestamp for a pattern
// that was successfully reused in a new flow.
func (gk *GlobalKnowledge) IncrementUseCount(ctx context.Context, patternID string) error {
	// This would update the metadata in pgvector — for now, log it
	gk.logger.WithField("pattern_id", patternID).Info("attack pattern reused in new flow")
	return nil
}

// ============================================================================
// Supporting Types
// ============================================================================

// PatternSearchFilter controls which patterns are returned by SearchPatterns.
type PatternSearchFilter struct {
	Type        AttackPatternType // Filter by pattern type
	TargetType  string            // Filter by target type (web_app, network, etc.)
	TargetOS    string            // Filter by target OS
	SuccessOnly bool              // Only return successful patterns
	MaxResults  int               // Override default max results
}

// ScoredPattern pairs an attack pattern with its similarity score.
type ScoredPattern struct {
	Pattern AttackPattern `json:"pattern"`
	Score   float64       `json:"score"` // 0.0-1.0, higher = more similar
}

// AttackPlaybook is a structured set of recommended attack phases
// compiled from historical successful pentests.
type AttackPlaybook struct {
	TargetType  string          `json:"target_type"`
	Description string          `json:"description"`
	Phases      []PlaybookPhase `json:"phases"`
}

// PlaybookPhase represents one phase of an attack playbook.
type PlaybookPhase struct {
	Name        string   `json:"name"`        // e.g., "Reconnaissance", "Exploitation"
	Description string   `json:"description"` // What to do in this phase
	Tools       []string `json:"tools"`       // Recommended tools
	Patterns    []string `json:"patterns"`    // Pattern IDs that informed this phase
	Priority    int      `json:"priority"`    // Execution order
}

// ============================================================================
// Helpers
// ============================================================================

func buildEmbeddingText(p AttackPattern) string {
	var parts []string

	parts = append(parts, p.Title)

	if p.Description != "" {
		parts = append(parts, p.Description)
	}

	if p.TargetType != "" {
		parts = append(parts, "Target: "+p.TargetType)
	}

	if len(p.TargetTech) > 0 {
		parts = append(parts, "Technologies: "+strings.Join(p.TargetTech, ", "))
	}

	if p.TargetOS != "" {
		parts = append(parts, "OS: "+p.TargetOS)
	}

	if p.CVE != "" {
		parts = append(parts, "CVE: "+p.CVE)
	}

	if len(p.ATTACKTechniques) > 0 {
		parts = append(parts, "MITRE ATT&CK: "+strings.Join(p.ATTACKTechniques, ", "))
	}

	if p.Success {
		parts = append(parts, "Status: SUCCESSFUL")
	} else {
		parts = append(parts, "Status: FAILED")
	}

	return strings.Join(parts, ". ")
}

func buildPlaybookPhases(patterns []ScoredPattern) []PlaybookPhase {
	// Group patterns by MITRE ATT&CK tactics to form natural phases
	tacticGroups := make(map[string][]ScoredPattern)

	for _, sp := range patterns {
		if len(sp.Pattern.ATTACKTactics) == 0 {
			tacticGroups["general"] = append(tacticGroups["general"], sp)
			continue
		}
		for _, tactic := range sp.Pattern.ATTACKTactics {
			tacticGroups[tactic] = append(tacticGroups[tactic], sp)
		}
	}

	// Map tactics to pentest phases in natural order
	phaseOrder := []struct {
		tactic string
		name   string
	}{
		{"reconnaissance", "Reconnaissance"},
		{"resource-development", "Resource Development"},
		{"initial-access", "Initial Access"},
		{"execution", "Execution"},
		{"persistence", "Persistence"},
		{"privilege-escalation", "Privilege Escalation"},
		{"defense-evasion", "Defense Evasion"},
		{"credential-access", "Credential Access"},
		{"discovery", "Discovery"},
		{"lateral-movement", "Lateral Movement"},
		{"collection", "Data Collection"},
		{"exfiltration", "Exfiltration"},
		{"impact", "Impact Assessment"},
		{"general", "General"},
	}

	var phases []PlaybookPhase
	priority := 1

	for _, po := range phaseOrder {
		group, ok := tacticGroups[po.tactic]
		if !ok || len(group) == 0 {
			continue
		}

		// Collect unique tools and pattern descriptions
		toolSet := make(map[string]struct{})
		var descriptions []string
		var patternIDs []string

		for _, sp := range group {
			for _, step := range sp.Pattern.ToolChain {
				toolSet[step.ToolName] = struct{}{}
			}
			descriptions = append(descriptions, sp.Pattern.Title)
			patternIDs = append(patternIDs, sp.Pattern.ID)
		}

		tools := make([]string, 0, len(toolSet))
		for t := range toolSet {
			tools = append(tools, t)
		}

		phases = append(phases, PlaybookPhase{
			Name:        po.name,
			Description: strings.Join(descriptions, "; "),
			Tools:       tools,
			Patterns:    patternIDs,
			Priority:    priority,
		})
		priority++
	}

	return phases
}
