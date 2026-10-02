package attack

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
)

// ============================================================================
// Auto-Mapper — real-time ATT&CK technique tagging
//
// Hooks into the tool call pipeline to automatically tag every action
// with the MITRE ATT&CK techniques it maps to. Works in two passes:
//   1. Direct tool mapping — tool name → techniques (ToolTechniqueMap)
//   2. Keyword scanning — scan args/description for keywords (KeywordTechniqueMap)
//
// The mapper is concurrent-safe and accumulates a CoverageMatrix that
// can be queried at any time for reporting or visualization.
// ============================================================================

// Mapper tracks ATT&CK technique coverage for a flow.
type Mapper struct {
	flowID   int64
	mu       sync.RWMutex
	mappings []ATTCKMapping
	coverage map[string]*TechniqueCoverage // keyed by technique ID
	logger   *logrus.Entry
}

// NewMapper creates a mapper for the given flow.
func NewMapper(flowID int64) *Mapper {
	return &Mapper{
		flowID:   flowID,
		mappings: make([]ATTCKMapping, 0),
		coverage: make(map[string]*TechniqueCoverage),
		logger:   logrus.WithFields(logrus.Fields{"component": "attack-mapper", "flow_id": flowID}),
	}
}

// MapToolCall analyzes a tool call and records any ATT&CK technique mappings.
// Call this from the tool execution pipeline after each tool call completes.
func (m *Mapper) MapToolCall(
	ctx context.Context,
	toolName string,
	args json.RawMessage,
	taskID, subtaskID *int64,
	toolCallID *int64,
) []ATTCKMapping {
	var newMappings []ATTCKMapping

	// Pass 1: Direct tool name mapping
	if rules, ok := ToolTechniqueMap[toolName]; ok {
		for _, rule := range rules {
			newMappings = append(newMappings, ATTCKMapping{
				TechniqueID: rule.TechniqueID,
				Confidence:  rule.Confidence,
				Source:      fmt.Sprintf("tool:%s", toolName),
				FlowID:      m.flowID,
				TaskID:      taskID,
				SubtaskID:   subtaskID,
				ToolCallID:  toolCallID,
			})
		}
	}

	// Pass 2: Keyword scanning in tool arguments
	argsStr := strings.ToLower(string(args))
	for keyword, rules := range KeywordTechniqueMap {
		if strings.Contains(argsStr, keyword) {
			for _, rule := range rules {
				// Don't duplicate a mapping already found via direct tool mapping
				if !hasTechnique(newMappings, rule.TechniqueID) {
					newMappings = append(newMappings, ATTCKMapping{
						TechniqueID: rule.TechniqueID,
						Confidence:  rule.Confidence * 0.9, // Slightly lower confidence for keyword matches
						Source:      fmt.Sprintf("keyword:%s", keyword),
						FlowID:      m.flowID,
						TaskID:      taskID,
						SubtaskID:   subtaskID,
						ToolCallID:  toolCallID,
					})
				}
			}
		}
	}

	// Record all mappings
	if len(newMappings) > 0 {
		m.mu.Lock()
		m.mappings = append(m.mappings, newMappings...)
		for _, mapping := range newMappings {
			m.updateCoverage(mapping)
		}
		m.mu.Unlock()

		m.logger.WithFields(logrus.Fields{
			"tool":            toolName,
			"techniques_found": len(newMappings),
		}).Debug("ATT&CK techniques mapped")
	}

	return newMappings
}

// MapSubtaskDescription scans a subtask title/description for ATT&CK keywords.
// Call this when a subtask is created or updated.
func (m *Mapper) MapSubtaskDescription(
	ctx context.Context,
	title, description string,
	taskID, subtaskID *int64,
) []ATTCKMapping {
	combined := strings.ToLower(title + " " + description)
	var newMappings []ATTCKMapping

	for keyword, rules := range KeywordTechniqueMap {
		if strings.Contains(combined, keyword) {
			for _, rule := range rules {
				if !hasTechnique(newMappings, rule.TechniqueID) {
					newMappings = append(newMappings, ATTCKMapping{
						TechniqueID: rule.TechniqueID,
						Confidence:  rule.Confidence * 0.8, // Lower confidence for description matches
						Source:      fmt.Sprintf("description:%s", keyword),
						FlowID:      m.flowID,
						TaskID:      taskID,
						SubtaskID:   subtaskID,
					})
				}
			}
		}
	}

	if len(newMappings) > 0 {
		m.mu.Lock()
		m.mappings = append(m.mappings, newMappings...)
		for _, mapping := range newMappings {
			m.updateCoverage(mapping)
		}
		m.mu.Unlock()
	}

	return newMappings
}

// GetCoverageMatrix returns the current ATT&CK coverage for this flow.
func (m *Mapper) GetCoverageMatrix() CoverageMatrix {
	m.mu.RLock()
	defer m.mu.RUnlock()

	techniques := make(map[string]TechniqueCoverage, len(m.coverage))
	for id, tc := range m.coverage {
		techniques[id] = *tc
	}

	// Calculate coverage statistics
	coveredCount := 0
	tacticCoverage := make(map[string]int)
	tacticTotal := make(map[string]int)

	for _, tc := range techniques {
		if tc.Covered {
			coveredCount++
		}
	}

	// Count techniques per tactic (from our mappings)
	for _, mapping := range m.mappings {
		if rules, ok := ToolTechniqueMap[mapping.Source]; ok {
			for _, rule := range rules {
				tacticTotal[rule.Tactic]++
				if mapping.Confidence > 0.5 {
					tacticCoverage[rule.Tactic]++
				}
			}
		}
	}

	tacticCoveragePercent := make(map[string]float64)
	for tactic, total := range tacticTotal {
		if total > 0 {
			tacticCoveragePercent[tactic] = float64(tacticCoverage[tactic]) / float64(total) * 100
		}
	}

	totalTech := len(techniques)
	coveragePercent := 0.0
	if totalTech > 0 {
		coveragePercent = float64(coveredCount) / float64(totalTech) * 100
	}

	return CoverageMatrix{
		FlowID:     m.flowID,
		Tactics:    AllTactics,
		Techniques: techniques,
		Coverage: CoverageStats{
			TotalTechniques:   totalTech,
			CoveredTechniques: coveredCount,
			CoveragePercent:   coveragePercent,
			TacticCoverage:    tacticCoveragePercent,
		},
	}
}

// GetAllMappings returns all ATT&CK mappings recorded for this flow.
func (m *Mapper) GetAllMappings() []ATTCKMapping {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]ATTCKMapping, len(m.mappings))
	copy(result, m.mappings)
	return result
}

// GetTechniqueIDs returns a deduplicated list of all technique IDs mapped in this flow.
func (m *Mapper) GetTechniqueIDs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ids := make([]string, 0, len(m.coverage))
	for id := range m.coverage {
		ids = append(ids, id)
	}
	return ids
}

// ============================================================================
// Internal helpers
// ============================================================================

func (m *Mapper) updateCoverage(mapping ATTCKMapping) {
	tc, exists := m.coverage[mapping.TechniqueID]
	if !exists {
		tc = &TechniqueCoverage{
			Technique: Technique{
				ID:        mapping.TechniqueID,
				IsSubtech: strings.Contains(mapping.TechniqueID, "."),
			},
			Mappings: make([]ATTCKMapping, 0),
		}
		if tc.Technique.IsSubtech {
			parts := strings.SplitN(mapping.TechniqueID, ".", 2)
			tc.Technique.ParentID = parts[0]
		}
		m.coverage[mapping.TechniqueID] = tc
	}

	tc.Mappings = append(tc.Mappings, mapping)
	tc.Covered = true
	if mapping.Confidence > tc.Confidence {
		tc.Confidence = mapping.Confidence
	}
}

func hasTechnique(mappings []ATTCKMapping, techID string) bool {
	for _, m := range mappings {
		if m.TechniqueID == techID {
			return true
		}
	}
	return false
}
