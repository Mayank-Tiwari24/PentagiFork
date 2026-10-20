package embeddings

import (
	"context"
	"fmt"
	"maps"
	"sync"

	obs "pentagi/pkg/observability"
	"pentagi/pkg/observability/langfuse"

	"github.com/vxcontrol/langchaingo/embeddings"
)

type wrapper struct {
	model    string
	provider string
	metadata langfuse.Metadata
	embeddings.Embedder

	// Circuit breaker: after the first embedding failure, all subsequent
	// calls return immediately with the cached error instead of waiting
	// for another multi-minute timeout. This prevents the cascading
	// 14-minute downtime observed when the embedding provider is down.
	breakerOnce sync.Once
	breakerErr  error
	broken      bool
}

func (w *wrapper) EmbedDocuments(ctx context.Context, texts []string) ([][]float32, error) {
	// Circuit breaker: if a previous call already failed, return immediately.
	if w.broken {
		return nil, fmt.Errorf("embedding circuit breaker open (provider unavailable): %w", w.breakerErr)
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
		// Trip the circuit breaker on the first failure so subsequent
		// calls don't each wait for an 8-minute timeout.
		w.breakerOnce.Do(func() {
			w.breakerErr = err
			w.broken = true
		})

		opts = append(opts,
			langfuse.WithEmbeddingStatus(err.Error()),
			langfuse.WithEmbeddingLevel(langfuse.ObservationLevelError),
		)
	} else {
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
	// Circuit breaker: if a previous call already failed, return immediately.
	if w.broken {
		return nil, fmt.Errorf("embedding circuit breaker open (provider unavailable): %w", w.breakerErr)
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
		// Trip the circuit breaker on query failures too.
		w.breakerOnce.Do(func() {
			w.breakerErr = err
			w.broken = true
		})

		opts = append(opts,
			langfuse.WithEmbeddingStatus(err.Error()),
			langfuse.WithEmbeddingLevel(langfuse.ObservationLevelError),
		)
	} else {
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
