package embeddings

import (
	"context"
	"fmt"
	"maps"
	"sync"
	"time"

	obs "pentagi/pkg/observability"
	"pentagi/pkg/observability/langfuse"

	"github.com/vxcontrol/langchaingo/embeddings"
)

const defaultBreakerTTL = 5 * time.Minute

type wrapper struct {
	model    string
	provider string
	metadata langfuse.Metadata
	embeddings.Embedder

	// Circuit breaker: after an embedding failure, all subsequent calls
	// return immediately with the cached error during the cooldown period
	// instead of waiting for another multi-minute timeout.
	// After defaultBreakerTTL, the circuit breaker half-opens to test if
	// the provider has recovered.
	breakerMu  sync.RWMutex
	breakerErr error
	broken     bool
	brokenAt   time.Time
}

func (w *wrapper) isBreakerOpen() (bool, error) {
	w.breakerMu.RLock()
	defer w.breakerMu.RUnlock()

	if !w.broken {
		return false, nil
	}

	// Auto-recovery: if cooldown has passed, permit a probe call (half-open)
	if time.Since(w.brokenAt) > defaultBreakerTTL {
		return false, nil
	}

	return true, w.breakerErr
}

func (w *wrapper) tripBreaker(err error) {
	w.breakerMu.Lock()
	defer w.breakerMu.Unlock()
	w.broken = true
	w.brokenAt = time.Now()
	w.breakerErr = err
}

func (w *wrapper) resetBreaker() {
	w.breakerMu.Lock()
	defer w.breakerMu.Unlock()
	w.broken = false
	w.breakerErr = nil
}

func (w *wrapper) EmbedDocuments(ctx context.Context, texts []string) ([][]float32, error) {
	// Circuit breaker: if in cooldown, fail fast to avoid multi-minute hangs.
	if open, cachedErr := w.isBreakerOpen(); open {
		return nil, fmt.Errorf("embedding circuit breaker open (provider unavailable, auto-retry in cooldown): %w", cachedErr)
	}

	ctx, span := obs.Observer.NewSpan(ctx, obs.SpanKindInternal, "embeddings.EmbedDocuments")
	defer span.End()

	ctx, observation := obs.Observer.NewObservation(ctx)
	metadata := make(langfuse.Metadata, len(w.metadata)+2)
	maps.Copy(metadata, w.metadata)
	metadata["model"] = w.model
	metadata["provider"] = w.provider

	embedding := observation.Embedding(
		langfuse.WithEmbeddingName("embedding documents"),
		langfuse.WithEmbeddingInput(map[string]any{
			"documents": texts,
		}),
		langfuse.WithEmbeddingModel(w.model),
		langfuse.WithEmbeddingMetadata(metadata),
	)

	vectors, err := w.Embedder.EmbedDocuments(ctx, texts)
	opts := []langfuse.EmbeddingOption{
		langfuse.WithEmbeddingOutput(map[string]any{
			"vectors": vectors,
		}),
	}

	if err != nil {
		w.tripBreaker(err)

		opts = append(opts,
			langfuse.WithEmbeddingStatus(err.Error()),
			langfuse.WithEmbeddingLevel(langfuse.ObservationLevelError),
		)
	} else {
		w.resetBreaker()

		opts = append(opts,
			langfuse.WithEmbeddingStatus("success"),
			langfuse.WithEmbeddingLevel(langfuse.ObservationLevelDebug),
		)
	}

	if len(vectors) > 0 {
		metadata["dimensions"] = len(vectors[0])
	}
	opts = append(opts, langfuse.WithEmbeddingMetadata(metadata))
	embedding.End(opts...)

	return vectors, err
}

func (w *wrapper) EmbedQuery(ctx context.Context, text string) ([]float32, error) {
	// Circuit breaker: if in cooldown, fail fast to avoid multi-minute hangs.
	if open, cachedErr := w.isBreakerOpen(); open {
		return nil, fmt.Errorf("embedding circuit breaker open (provider unavailable, auto-retry in cooldown): %w", cachedErr)
	}

	ctx, span := obs.Observer.NewSpan(ctx, obs.SpanKindInternal, "embeddings.EmbedQuery")
	defer span.End()

	ctx, observation := obs.Observer.NewObservation(ctx)
	metadata := make(langfuse.Metadata, len(w.metadata)+2)
	maps.Copy(metadata, w.metadata)
	metadata["model"] = w.model
	metadata["provider"] = w.provider

	embedding := observation.Embedding(
		langfuse.WithEmbeddingName("embedding query"),
		langfuse.WithEmbeddingInput(map[string]any{
			"document": text,
		}),
		langfuse.WithEmbeddingModel(w.model),
		langfuse.WithEmbeddingMetadata(metadata),
	)

	vector, err := w.Embedder.EmbedQuery(ctx, text)
	opts := []langfuse.EmbeddingOption{
		langfuse.WithEmbeddingOutput(map[string]any{
			"vector": vector,
		}),
	}

	if err != nil {
		w.tripBreaker(err)

		opts = append(opts,
			langfuse.WithEmbeddingStatus(err.Error()),
			langfuse.WithEmbeddingLevel(langfuse.ObservationLevelError),
		)
	} else {
		w.resetBreaker()

		opts = append(opts,
			langfuse.WithEmbeddingStatus("success"),
			langfuse.WithEmbeddingLevel(langfuse.ObservationLevelDebug),
		)
	}

	if len(vector) > 0 {
		metadata["dimensions"] = len(vector)
	}
	opts = append(opts, langfuse.WithEmbeddingMetadata(metadata))
	embedding.End(opts...)

	return vector, err
}
