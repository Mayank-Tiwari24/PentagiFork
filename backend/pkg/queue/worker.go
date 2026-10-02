package queue

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"
	"pentagi/pkg/database"
)

type WorkerPool struct {
	Repo     *database.JobRepo
	WorkerID string
	Handlers map[string]func(ctx context.Context, payload []byte) error
}

func NewWorkerPool(repo *database.JobRepo, workerID string) *WorkerPool {
	return &WorkerPool{
		Repo:     repo,
		WorkerID: workerID,
		Handlers: make(map[string]func(ctx context.Context, payload []byte) error),
	}
}

func (wp *WorkerPool) RegisterHandler(jobType string, handler func(ctx context.Context, payload []byte) error) {
	wp.Handlers[jobType] = handler
}

func (wp *WorkerPool) Start(ctx context.Context, concurrency int) {
	for i := 0; i < concurrency; i++ {
		go wp.poll(ctx)
	}
	logrus.WithFields(logrus.Fields{
		"worker_id": wp.WorkerID,
		"concurrency": concurrency,
	}).Info("Started distributed job worker pool")
}

func (wp *WorkerPool) poll(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			job, err := wp.Repo.Dequeue(ctx, wp.WorkerID)
			if err != nil {
				logrus.WithError(err).Error("Failed to dequeue job")
				continue
			}
			if job == nil {
				continue // No jobs available
			}

			logrus.WithFields(logrus.Fields{
				"job_id": job.ID,
				"job_type": job.Type,
			}).Info("Processing job")

			handler, ok := wp.Handlers[job.Type]
			if !ok {
				logrus.WithField("job_type", job.Type).Error("No handler found for job type")
				_ = wp.Repo.UpdateStatus(ctx, job.ID, "failed", "no handler found")
				continue
			}

			err = handler(ctx, job.Payload)
			if err != nil {
				logrus.WithError(err).WithField("job_id", job.ID).Error("Job failed")
				_ = wp.Repo.UpdateStatus(ctx, job.ID, "failed", err.Error())
			} else {
				logrus.WithField("job_id", job.ID).Info("Job completed successfully")
				_ = wp.Repo.UpdateStatus(ctx, job.ID, "completed", "")
			}
		}
	}
}
