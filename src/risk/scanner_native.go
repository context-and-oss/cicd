//go:build !unit_test

package main

import (
	"context"

	"dagger/risk/internal/dagger"
)

// nativeConversation uses dag.LLM() — requires ANTHROPIC_API_KEY or Dagger LLM config.
type nativeConversation struct {
	llm *dagger.LLM
}

func newNativeConversation() *nativeConversation {
	return &nativeConversation{llm: dag.LLM()}
}

func (c *nativeConversation) send(ctx context.Context, msg string) (string, error) {
	c.llm = c.llm.WithPrompt(msg)
	return c.llm.LastReply(ctx)
}
