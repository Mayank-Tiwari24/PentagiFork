-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS pentagi_jobs (
    id SERIAL PRIMARY KEY,
    type VARCHAR(50) NOT NULL,
    payload JSONB NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',
    priority INT DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP WITH TIME ZONE,
    finished_at TIMESTAMP WITH TIME ZONE,
    error_message TEXT,
    worker_id VARCHAR(100)
);

CREATE INDEX idx_jobs_status_priority ON pentagi_jobs(status, priority DESC, created_at ASC);
