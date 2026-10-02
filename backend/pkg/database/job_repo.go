package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/jmoiron/sqlx"
)

type JobRepo struct {
	DB *sqlx.DB
}

func NewJobRepo(db *sqlx.DB) *JobRepo {
	return &JobRepo{DB: db}
}

type Job struct {
	ID           int            `db:"id"`
	Type         string         `db:"type"`
	Payload      json.RawMessage `db:"payload"`
	Status       string         `db:"status"`
	Priority     int            `db:"priority"`
	CreatedAt    time.Time      `db:"created_at"`
	StartedAt    *time.Time     `db:"started_at"`
	FinishedAt   *time.Time     `db:"finished_at"`
	ErrorMessage sql.NullString `db:"error_message"`
	WorkerID     sql.NullString `db:"worker_id"`
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
	err := r.DB.GetContext(ctx, &job, query, workerID)
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
