package plugins

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vxcontrol/langchaingo/llms"
)

// HTTPPlugin implements the Plugin interface for plugins that communicate
// via HTTP. This enables plugins written in ANY language (Python, Node, Rust)
// to integrate with PentAGI — they just need to expose a REST API.
//
// Plugin directory structure:
//
//	my-plugin/
//	├── manifest.json     # Plugin metadata and tool definitions
//	├── run.sh            # Optional: startup script (auto-started if present)
//	├── requirements.txt  # Optional: Python deps
//	└── main.py           # Optional: plugin implementation
type HTTPPlugin struct {
	manifest  PluginManifest
	sourceDir string
	baseURL   string
	client    *http.Client
	process   *exec.Cmd
	mu        sync.RWMutex
	available bool
	logger    *logrus.Entry
}

// NewHTTPPlugin creates an HTTP-based plugin adapter. If the plugin directory
// contains a run.sh, it will be auto-started during Init().
func NewHTTPPlugin(manifest PluginManifest, sourceDir string) *HTTPPlugin {
	return &HTTPPlugin{
		manifest:  manifest,
		sourceDir: sourceDir,
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
		logger: logrus.WithField("plugin_id", manifest.ID),
	}
}

func (p *HTTPPlugin) Manifest() PluginManifest {
	return p.manifest
}

func (p *HTTPPlugin) Init(ctx context.Context, cfg PluginConfig) error {
	// Check if plugin has a startup script
	runScript := filepath.Join(p.sourceDir, "run.sh")
	if _, err := os.Stat(runScript); err == nil {
		if err := p.startProcess(ctx, cfg); err != nil {
			return fmt.Errorf("failed to start plugin process: %w", err)
		}
	}

	// Check if the plugin specifies a URL in its env config
	if url, ok := cfg.Env["PLUGIN_URL"]; ok && url != "" {
		p.baseURL = strings.TrimRight(url, "/")
	} else {
		// Default: plugin runs on localhost with a port derived from plugin ID hash
		port := 30000 + (hashString(p.manifest.ID) % 10000)
		p.baseURL = fmt.Sprintf("http://127.0.0.1:%d", port)
	}

	// Validate all required config fields are present
	for _, field := range p.manifest.ConfigSchema {
		if field.Required {
			if val, ok := cfg.Env[field.Name]; !ok || val == "" {
				p.available = false
				p.logger.WithField("config_field", field.Name).Warn("required config field missing, plugin unavailable")
				return nil // Don't error — just mark unavailable
			}
		}
	}

	// Probe the health endpoint to verify the plugin is running
	if err := p.healthCheck(ctx); err != nil {
		p.logger.WithError(err).Warn("plugin health check failed, marking as unavailable")
		p.available = false
		return nil // Don't fail init — plugin might start later
	}

	p.mu.Lock()
	p.available = true
	p.mu.Unlock()

	return nil
}

func (p *HTTPPlugin) Tools() []llms.Tool {
	tools := make([]llms.Tool, 0, len(p.manifest.Tools))
	for _, td := range p.manifest.Tools {
		var fnDef llms.FunctionDefinition
		fnDef.Name = td.Name
		fnDef.Description = td.Description
		if td.Schema != nil {
			_ = json.Unmarshal(td.Schema, &fnDef.Parameters)
		}
		tools = append(tools, llms.Tool{
			Type:     "function",
			Function: &fnDef,
		})
	}
	return tools
}

func (p *HTTPPlugin) Handle(ctx context.Context, name string, args json.RawMessage) (string, error) {
	payload := struct {
		Tool string          `json:"tool"`
		Args json.RawMessage `json:"args"`
	}{
		Tool: name,
		Args: args,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal plugin request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+"/execute", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create plugin request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		p.mu.Lock()
		p.available = false
		p.mu.Unlock()
		return "", fmt.Errorf("plugin %q request failed: %w", p.manifest.ID, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read plugin response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("plugin %q returned status %d: %s", p.manifest.ID, resp.StatusCode, string(respBody))
	}

	// Parse the response — plugin returns { "result": "...", "error": "..." }
	var result struct {
		Result string `json:"result"`
		Error  string `json:"error,omitempty"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		// If not JSON, treat the whole body as the result
		return string(respBody), nil
	}

	if result.Error != "" {
		return "", fmt.Errorf("plugin error: %s", result.Error)
	}

	return result.Result, nil
}

func (p *HTTPPlugin) IsAvailable() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.available
}

func (p *HTTPPlugin) Shutdown(ctx context.Context) error {
	if p.process != nil && p.process.Process != nil {
		p.logger.Info("stopping plugin process")
		if err := p.process.Process.Signal(os.Interrupt); err != nil {
			_ = p.process.Process.Kill()
		}

		done := make(chan error, 1)
		go func() { done <- p.process.Wait() }()

		select {
		case <-ctx.Done():
			_ = p.process.Process.Kill()
		case <-done:
		case <-time.After(5 * time.Second):
			_ = p.process.Process.Kill()
		}
	}

	p.mu.Lock()
	p.available = false
	p.mu.Unlock()

	return nil
}

func (p *HTTPPlugin) startProcess(ctx context.Context, cfg PluginConfig) error {
	runScript := filepath.Join(p.sourceDir, "run.sh")
	p.process = exec.CommandContext(ctx, "bash", runScript)
	p.process.Dir = p.sourceDir

	// Pass plugin-specific env vars
	p.process.Env = os.Environ()
	for k, v := range cfg.Env {
		p.process.Env = append(p.process.Env, k+"="+v)
	}
	p.process.Env = append(p.process.Env, "PLUGIN_DATA_DIR="+cfg.DataDir)

	// Redirect stdout/stderr to logger
	p.process.Stdout = p.logger.WithField("stream", "stdout").Writer()
	p.process.Stderr = p.logger.WithField("stream", "stderr").Writer()

	if err := p.process.Start(); err != nil {
		return fmt.Errorf("failed to start plugin process: %w", err)
	}

	p.logger.WithField("pid", p.process.Process.Pid).Info("plugin process started")

	// Wait a bit for the process to initialize
	time.Sleep(2 * time.Second)

	return nil
}

func (p *HTTPPlugin) healthCheck(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.baseURL+"/health", nil)
	if err != nil {
		return err
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check returned %d", resp.StatusCode)
	}

	return nil
}

// hashString produces a deterministic positive integer from a string.
func hashString(s string) int {
	h := 0
	for _, c := range s {
		h = h*31 + int(c)
	}
	if h < 0 {
		h = -h
	}
	return h
}
