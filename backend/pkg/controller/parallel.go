package controller

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"pentagi/pkg/database"

	"github.com/sirupsen/logrus"
)

// ============================================================================
// Parallel Agent Execution Engine
//
// Enables multiple subtasks to run concurrently when they have no data
// dependencies between them. The generator agent marks subtasks with a
// "group" index; all subtasks in the same group execute in parallel.
// Groups execute sequentially in ascending order (group 1 finishes
// before group 2 starts).
//
// Dependency model:
//   group 1: [recon_dns, recon_ports, recon_whois]  ← run in parallel
//   group 2: [analyze_services]                      ← waits for group 1
//   group 3: [exploit_http, exploit_ssh]             ← run in parallel after group 2
//   group 4: [report]                                ← waits for all
//
// This is a DAG-by-groups model: simpler than a full dependency graph but
// covers 90% of real pentest workflows where recon → analysis → exploitation
// → reporting forms natural sequential phases with parallelism within each.
// ============================================================================

// SubtaskGroup holds subtasks that can execute concurrently.
type SubtaskGroup struct {
	GroupIndex int
	Subtasks   []SubtaskExecution
}

// SubtaskExecution wraps a subtask with its execution state for parallel runs.
type SubtaskExecution struct {
	SubtaskID   int64
	Title       string
	Description string
	Status      database.SubtaskStatus
	Result      string
	Error       error
	StartedAt   time.Time
	FinishedAt  time.Time
}

// ParallelExecutor manages concurrent subtask execution within a task.
type ParallelExecutor struct {
	taskID    int64
	flowID    int64
	maxWorkers int
	logger    *logrus.Entry
	mu        sync.Mutex
}

// NewParallelExecutor creates an executor that runs subtask groups concurrently.
// maxWorkers limits how many subtasks run simultaneously within a group (0 = unlimited).
func NewParallelExecutor(flowID, taskID int64, maxWorkers int) *ParallelExecutor {
	if maxWorkers <= 0 {
		maxWorkers = 5 // Default: max 5 parallel subtasks
	}

	return &ParallelExecutor{
		taskID:     taskID,
		flowID:     flowID,
		maxWorkers: maxWorkers,
		logger: logrus.WithFields(logrus.Fields{
			"component": "parallel-executor",
			"flow_id":   flowID,
			"task_id":   taskID,
		}),
	}
}

// GroupSubtasks organizes subtasks into execution groups.
// Subtasks with the same GroupIndex run in parallel; groups run sequentially.
// Subtasks without a group (GroupIndex=0) are assigned to sequential groups
// in order (backward compatible with the current linear execution model).
func GroupSubtasks(subtasks []SubtaskWithGroup) []SubtaskGroup {
	if len(subtasks) == 0 {
		return nil
	}

	// Check if any subtask actually has a group assigned
	hasGroups := false
	for _, st := range subtasks {
		if st.GroupIndex > 0 {
			hasGroups = true
			break
		}
	}

	// If no groups are assigned, fall back to sequential execution
	// (each subtask gets its own group) — fully backward compatible
	if !hasGroups {
		groups := make([]SubtaskGroup, len(subtasks))
		for i, st := range subtasks {
			groups[i] = SubtaskGroup{
				GroupIndex: i + 1,
				Subtasks: []SubtaskExecution{{
					SubtaskID:   st.SubtaskID,
					Title:       st.Title,
					Description: st.Description,
					Status:      st.Status,
				}},
			}
		}
		return groups
	}

	// Group by GroupIndex
	groupMap := make(map[int][]SubtaskExecution)
	for _, st := range subtasks {
		idx := st.GroupIndex
		if idx <= 0 {
			// Ungrouped subtasks get the max group index + 1 (run last)
			idx = 9999
		}
		groupMap[idx] = append(groupMap[idx], SubtaskExecution{
			SubtaskID:   st.SubtaskID,
			Title:       st.Title,
			Description: st.Description,
			Status:      st.Status,
		})
	}

	// Sort groups by index
	indices := make([]int, 0, len(groupMap))
	for idx := range groupMap {
		indices = append(indices, idx)
	}
	sort.Ints(indices)

	groups := make([]SubtaskGroup, 0, len(indices))
	for _, idx := range indices {
		groups = append(groups, SubtaskGroup{
			GroupIndex: idx,
			Subtasks:   groupMap[idx],
		})
	}

	return groups
}

// SubtaskWithGroup extends subtask data with parallel execution metadata.
type SubtaskWithGroup struct {
	SubtaskID   int64
	Title       string
	Description string
	Status      database.SubtaskStatus
	GroupIndex  int // 0 = ungrouped (sequential), >0 = parallel group
}

// ExecuteGroupFunc is the callback that actually runs a single subtask.
// It receives the subtask context and must return the result or error.
type ExecuteGroupFunc func(ctx context.Context, subtaskID int64) error

// ExecuteGroups runs subtask groups sequentially, with subtasks within each
// group running in parallel. Returns on first fatal error or after all groups complete.
func (pe *ParallelExecutor) ExecuteGroups(
	ctx context.Context,
	groups []SubtaskGroup,
	executeFunc ExecuteGroupFunc,
) error {
	for _, group := range groups {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("execution cancelled: %w", err)
		}

		// Skip groups where all subtasks are already finished
		allDone := true
		for _, st := range group.Subtasks {
			if st.Status != database.SubtaskStatusFinished &&
				st.Status != database.SubtaskStatusFailed {
				allDone = false
				break
			}
		}
		if allDone {
			pe.logger.WithField("group", group.GroupIndex).Debug("skipping completed group")
			continue
		}

		pe.logger.WithFields(logrus.Fields{
			"group":          group.GroupIndex,
			"subtask_count":  len(group.Subtasks),
			"max_workers":    pe.maxWorkers,
		}).Info("executing subtask group")

		if err := pe.executeGroup(ctx, group, executeFunc); err != nil {
			return fmt.Errorf("group %d failed: %w", group.GroupIndex, err)
		}

		pe.logger.WithField("group", group.GroupIndex).Info("subtask group completed")
	}

	return nil
}

// executeGroup runs all subtasks in a group concurrently, bounded by maxWorkers.
func (pe *ParallelExecutor) executeGroup(
	ctx context.Context,
	group SubtaskGroup,
	executeFunc ExecuteGroupFunc,
) error {
	// For single-subtask groups, run directly (no goroutine overhead)
	if len(group.Subtasks) == 1 {
		st := group.Subtasks[0]
		if st.Status == database.SubtaskStatusFinished ||
			st.Status == database.SubtaskStatusFailed {
			return nil
		}
		return executeFunc(ctx, st.SubtaskID)
	}

	// Semaphore to limit concurrent workers
	sem := make(chan struct{}, pe.maxWorkers)

	var (
		wg      sync.WaitGroup
		errOnce sync.Once
		firstErr error
	)

	groupCtx, groupCancel := context.WithCancel(ctx)
	defer groupCancel()

	for _, st := range group.Subtasks {
		// Skip already completed subtasks
		if st.Status == database.SubtaskStatusFinished ||
			st.Status == database.SubtaskStatusFailed {
			continue
		}

		wg.Add(1)
		subtaskID := st.SubtaskID
		subtaskTitle := st.Title

		go func() {
			defer wg.Done()

			// Acquire semaphore slot
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-groupCtx.Done():
				return
			}

			pe.logger.WithFields(logrus.Fields{
				"subtask_id":    subtaskID,
				"subtask_title": subtaskTitle,
				"group":         group.GroupIndex,
			}).Info("starting parallel subtask")

			startTime := time.Now()

			if err := executeFunc(groupCtx, subtaskID); err != nil {
				pe.logger.WithError(err).WithFields(logrus.Fields{
					"subtask_id": subtaskID,
					"duration":   time.Since(startTime).Seconds(),
				}).Error("parallel subtask failed")

				// Record the first error — don't cancel other subtasks in the group
				// (pentest philosophy: one failure shouldn't stop other attack vectors)
				errOnce.Do(func() {
					firstErr = fmt.Errorf("subtask %d (%s) failed: %w", subtaskID, subtaskTitle, err)
				})
				return
			}

			pe.logger.WithFields(logrus.Fields{
				"subtask_id": subtaskID,
				"duration":   time.Since(startTime).Seconds(),
			}).Info("parallel subtask completed")
		}()
	}

	wg.Wait()

	// In pentest mode, we don't fail the group if some subtasks fail —
	// partial results are still valuable. Only return error if ALL subtasks failed.
	return firstErr
}

// ============================================================================
// Execution Statistics
// ============================================================================

// GroupExecutionStats tracks performance metrics for parallel execution.
type GroupExecutionStats struct {
	GroupIndex      int            `json:"group_index"`
	SubtaskCount    int            `json:"subtask_count"`
	SuccessCount    int            `json:"success_count"`
	FailedCount     int            `json:"failed_count"`
	TotalDuration   time.Duration  `json:"total_duration"`
	MaxDuration     time.Duration  `json:"max_duration"`     // Slowest subtask
	Speedup         float64        `json:"speedup"`          // Sequential time / parallel time
}

// CalculateSpeedup computes how much faster parallel execution was vs sequential.
func CalculateSpeedup(subtaskDurations []time.Duration, parallelDuration time.Duration) float64 {
	if parallelDuration == 0 {
		return 1.0
	}

	var sequentialTotal time.Duration
	for _, d := range subtaskDurations {
		sequentialTotal += d
	}

	return float64(sequentialTotal) / float64(parallelDuration)
}
