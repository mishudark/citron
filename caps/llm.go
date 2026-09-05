package caps

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
)

type LLMConfig struct {
	Model    string
	APIKey   string
	Endpoint string
	Timeout  time.Duration
}

type llmClient struct {
	cfg *LLMConfig
}

var globalLLM *llmClient

// llmMu guards globalLLM: SafeExecute and Session.Execute configure the
// client per run, so concurrent executions race on the global otherwise.
var llmMu sync.RWMutex

func ConfigureLLM(cfg *LLMConfig) {
	llmMu.Lock()
	defer llmMu.Unlock()
	if cfg != nil {
		globalLLM = &llmClient{cfg: cfg}
	} else {
		globalLLM = nil
	}
}

// currentLLM returns the configured client snapshot, or nil.
func currentLLM() *llmClient {
	llmMu.RLock()
	defer llmMu.RUnlock()
	return globalLLM
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

func Chat(message string) (string, error) {
	_, span := StartSpan(context.Background(), "caps.LLM.Chat",
		attribute.Int("message_len", len(message)),
	)

	client := currentLLM()
	if client == nil {
		EndSpan(span, fmt.Errorf("cap: LLM not configured"))
		RecordOperation(context.Background(), "chat", fmt.Errorf("cap: LLM not configured"))
		return "", fmt.Errorf("cap: LLM not configured")
	}
	result, err := client.chat(message)
	EndSpan(span, err)
	RecordOperation(context.Background(), "chat", err)
	return result, err
}

func ChatClassified(message Classified[string]) (Classified[string], error) {
	_, span := StartSpan(context.Background(), "caps.LLM.ChatClassified")

	client := currentLLM()
	if client == nil {
		EndSpan(span, fmt.Errorf("cap: LLM not configured"))
		RecordOperation(context.Background(), "chat_classified", fmt.Errorf("cap: LLM not configured"))
		return Classified[string]{}, fmt.Errorf("cap: LLM not configured")
	}
	// Only pure functions can access the classified content
	result, err := client.chat(message.value)
	RecordAudit("chat_classified", client.cfg.Model, err)
	if err != nil {
		EndSpan(span, err)
		RecordOperation(context.Background(), "chat_classified", err)
		return Classified[string]{}, err
	}
	EndSpan(span, nil)
	RecordOperation(context.Background(), "chat_classified", nil)
	return Classify(result), nil
}

func (c *llmClient) chat(message string) (string, error) {
	req := chatRequest{
		Model: c.cfg.Model,
		Messages: []chatMessage{
			{Role: "user", Content: message},
		},
	}
	body, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("cap: LLM marshal error: %w", err)
	}
	timeout := c.cfg.Timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	client := &http.Client{Timeout: timeout}
	httpReq, err := http.NewRequest("POST", c.cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("cap: LLM request error: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)

	resp, err := client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("cap: LLM call failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("cap: LLM read error: %w", err)
	}

	var chatResp chatResponse
	if err := json.Unmarshal(respBody, &chatResp); err != nil {
		return "", fmt.Errorf("cap: LLM parse error: %w", err)
	}
	if len(chatResp.Choices) == 0 {
		return "", fmt.Errorf("cap: LLM returned no choices")
	}
	return chatResp.Choices[0].Message.Content, nil
}
