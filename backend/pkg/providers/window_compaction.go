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

	// Cap the effective window for compaction purposes. Modern LLMs have
	// 128K - 1M token context windows (e.g. GPT-4o, Claude 3.5, Gemini).
	// Without a ceiling, 40% of a 128K-1M window is 51K - 400K tokens, meaning
	// chains grow massive before the first compaction fires, causing quadratic
	// token burn across turns.
	// Capping the effective window at 32,768 tokens ensures compaction triggers
	// when history exceeds ~16K tokens, keeping context lean while retaining the
	// full system prompt (~6-8K), goal, recent turns, and summarized history.
	const maxCompactionCeilingTokens = 32768
	effectiveWindow := min(*window, maxCompactionCeilingTokens)

	earlyThreshold := effectiveWindow * 50 / 100
	if provider.ChainFitsWindow(chain, schemas, earlyThreshold) {
		return chain, false
	}

	budget := provider.ChainByteBudget(effectiveWindow, schemas)
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
