package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

type JobRepo struct {
	DB *sql.DB
}

func NewJobRepo(db *sql.DB) *JobRepo {
	return &JobRepo{DB: db}
}

type Job struct {
	ID           int
	Type         string
	Payload      json.RawMessage
	Status       string
	Priority     int
	CreatedAt    time.Time
	StartedAt    *time.Time
	FinishedAt   *time.Time
	ErrorMessage sql.NullString
	WorkerID     sql.NullString
}

func (r *JobRepo) Enqueue(ctx context.Context, jobType string, payload []byte, priority int) (int, error) {
	query := `
		INSERT INTO pentagi_jobs (type, payload, priority)
		VALUES ($1, $2, $3)
		RETURNING id
	`
	var id int
	err := r.DB.QueryRowContext(ctx, query, jobType, payload, priority).Scan(&id)
	return id, err
}

func (r *JobRepo) Dequeue(ctx context.Context, workerID string) (*Job, error) {
	query := `
		UPDATE pentagi_jobs
		SET status = 'running', worker_id = $1, started_at = CURRENT_TIMESTAMP
		WHERE id = (
			SELECT id
			FROM pentagi_jobs
			WHERE status = 'pending'
			ORDER BY priority DESC, created_at ASC
			FOR UPDATE SKIP LOCKED
			LIMIT 1
		)
		RETURNING id, type, payload, status, priority, created_at, started_at, finished_at, error_message, worker_id
	`
	var job Job
	err := r.DB.QueryRowContext(ctx, query, workerID).Scan(
		&job.ID,
		&job.Type,
		&job.Payload,
		&job.Status,
		&job.Priority,
		&job.CreatedAt,
		&job.StartedAt,
		&job.FinishedAt,
		&job.ErrorMessage,
		&job.WorkerID,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // No pending jobs
		}
		return nil, err
	}
	return &job, nil
}

func (r *JobRepo) UpdateStatus(ctx context.Context, id int, status string, errStr string) error {
	query := `
		UPDATE pentagi_jobs
		SET status = $1, error_message = $2, finished_at = CASE WHEN $1 IN ('completed', 'failed') THEN CURRENT_TIMESTAMP ELSE finished_at END
		WHERE id = $3
	`
	var errMessage sql.NullString
	if errStr != "" {
		errMessage = sql.NullString{String: errStr, Valid: true}
	}
	
	_, err := r.DB.ExecContext(ctx, query, status, errMessage, id)
	return err
}
