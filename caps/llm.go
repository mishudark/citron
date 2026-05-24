package caps

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
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

func ConfigureLLM(cfg *LLMConfig) {
	if cfg != nil {
		globalLLM = &llmClient{cfg: cfg}
	} else {
		globalLLM = nil
	}
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
	if globalLLM == nil {
		return "", fmt.Errorf("cap: LLM not configured")
	}
	return globalLLM.chat(message)
}

func ChatClassified(message Classified[string]) (Classified[string], error) {
	if globalLLM == nil {
		return Classified[string]{}, fmt.Errorf("cap: LLM not configured")
	}
	// Only pure functions can access the classified content
	result, err := globalLLM.chat(message.value)
	if err != nil {
		return Classified[string]{}, err
	}
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
