package providers

import (
	"context"

	"pentagi/pkg/csum"
	"pentagi/pkg/providers/pconfig"
	"pentagi/pkg/providers/provider"
	"pentagi/pkg/tools"

	"github.com/vxcontrol/langchaingo/llms"
)

func compactChainForWindow(
	ctx context.Context,
	prv provider.Provider,
	opt pconfig.ProviderOptionsType,
	chain []llms.MessageContent,
	schemas []llms.Tool,
	handler tools.SummarizeHandler,
	tcIDTemplate string,
) ([]llms.MessageContent, bool) {
	window := provider.ModelLimitsFor(prv, opt).ContextWindow
	if window == nil {
		return chain, false
	}

	// Compact at 40% of the context window, not 100%. Without this, chains
	// grow unchecked to 60-80K tokens before the first compaction fires,
	// causing O(n²) token consumption across long subtasks. At 40% the agent
	// still keeps: full system prompt + current goal + last QA pairs +
	// compressed summary of earlier turns — zero offensive power lost.
	earlyThreshold := *window * 40 / 100
	if provider.ChainFitsWindow(chain, schemas, earlyThreshold) {
		return chain, false
	}

	budget := provider.ChainByteBudget(*window, schemas)
	if budget <= 0 {
		return chain, false
	}

	compacted, err := csum.NewSummarizer(csum.SummarizerConfig{
		PreserveLast:   true,
		UseQA:          true,
		LastSecBytes:   budget / 2,
		MaxBPBytes:     budget / 4,
		MaxQABytes:     budget,
		KeepQASections: 1,
	}).SummarizeChain(ctx, handler, chain, tcIDTemplate)
	if err != nil {
		return chain, false
	}

	return compacted, true
}
