package plugins

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"pentagi/pkg/config"
	"pentagi/pkg/tools"

	"github.com/sirupsen/logrus"
	"github.com/vxcontrol/langchaingo/llms"
)

// PluginType classifies what a plugin provides.
type PluginType string

const (
	PluginTypeTool       PluginType = "tool"       // Adds new tools (e.g., shodan_search, cve_lookup)
	PluginTypeAgent      PluginType = "agent"      // Adds new agent types (e.g., strategist, recon)
	PluginTypeSearch     PluginType = "search"     // Adds new search engines
	PluginTypeReporter   PluginType = "reporter"   // Adds report formats (PDF, SARIF, DOCX)
	PluginTypeIntegation PluginType = "integration" // External integrations (Jira, Slack, webhooks)
)

// PluginStatus tracks the lifecycle state of a loaded plugin.
type PluginStatus string

const (
	PluginStatusLoading  PluginStatus = "loading"
	PluginStatusActive   PluginStatus = "active"
	PluginStatusDisabled PluginStatus = "disabled"
	PluginStatusError    PluginStatus = "error"
)

// PluginManifest describes a plugin's metadata and capabilities.
// Each plugin directory must contain a manifest.json with this structure.
type PluginManifest struct {
	// Required fields
	ID          string     `json:"id"`          // Unique plugin identifier (e.g., "shodan-osint")
	Name        string     `json:"name"`        // Human-readable name
	Version     string     `json:"version"`     // Semantic version
	Type        PluginType `json:"type"`        // Plugin classification
	Description string     `json:"description"` // What this plugin does
	Author      string     `json:"author"`      // Plugin author

	// Optional fields
	Homepage string   `json:"homepage,omitempty"` // Project URL
	License  string   `json:"license,omitempty"`  // License identifier
	Tags     []string `json:"tags,omitempty"`     // Searchable tags

	// Configuration schema — env vars the plugin needs
	ConfigSchema []PluginConfigField `json:"config_schema,omitempty"`

	// Tool definitions — registered when plugin loads
	Tools []PluginToolDef `json:"tools,omitempty"`

	// Agent contexts where this plugin's tools are available
	// Empty = available everywhere; otherwise restrict to listed agents
	AgentContexts []string `json:"agent_contexts,omitempty"`
}

// PluginConfigField describes a configuration parameter the plugin requires.
type PluginConfigField struct {
	Name        string `json:"name"`                  // Environment variable name
	Description string `json:"description"`           // What this config does
	Required    bool   `json:"required"`              // Whether plugin fails without it
	Default     string `json:"default,omitempty"`      // Default value if not set
	Secret      bool   `json:"secret,omitempty"`       // Whether to mask in logs
}

// PluginToolDef describes a tool that a plugin provides.
type PluginToolDef struct {
	Name        string          `json:"name"`        // Tool name (used in LLM function calls)
	Description string          `json:"description"` // Shown to the LLM
	Schema      json.RawMessage `json:"schema"`      // JSON Schema for arguments
}

// Plugin is the interface that all plugins must implement.
// For Go-native plugins, implement this directly.
// For HTTP-based plugins, use the HTTPPluginAdapter.
type Plugin interface {
	// Manifest returns the plugin's metadata and capabilities.
	Manifest() PluginManifest

	// Init is called once when the plugin is loaded. Use it to validate
	// configuration, establish connections, etc. Return an error to prevent
	// the plugin from activating.
	Init(ctx context.Context, cfg PluginConfig) error

	// Tools returns the LLM tool definitions this plugin provides.
	// These are merged into the agent's available tools at runtime.
	Tools() []llms.Tool

	// Handle processes a tool call. The name parameter matches one of the
	// tool names from Tools(). This follows the existing tools.Tool interface
	// pattern so plugins integrate seamlessly.
	Handle(ctx context.Context, name string, args json.RawMessage) (string, error)

	// IsAvailable returns true if the plugin is configured and ready.
	// Called before each use — plugins can become unavailable at runtime
	// (e.g., API key revoked, service down).
	IsAvailable() bool

	// Shutdown is called when the plugin is unloaded or the server stops.
	// Clean up resources, close connections, flush buffers.
	Shutdown(ctx context.Context) error
}

// PluginConfig provides runtime configuration to a plugin during Init().
type PluginConfig struct {
	// Env contains the environment variables relevant to this plugin,
	// filtered by the manifest's ConfigSchema.
	Env map[string]string

	// DataDir is a persistent directory the plugin can use for caching
	// or storing data. Created automatically per-plugin.
	DataDir string

	// Logger is a pre-configured logger with plugin context fields.
	Logger *logrus.Entry
}

// ============================================================================
// Plugin Registry — manages plugin lifecycle and discovery
// ============================================================================

// PluginInfo holds a loaded plugin and its runtime metadata.
type PluginInfo struct {
	Plugin    Plugin       `json:"-"`
	Manifest  PluginManifest `json:"manifest"`
	Status    PluginStatus   `json:"status"`
	LoadedAt  time.Time      `json:"loaded_at"`
	Error     string         `json:"error,omitempty"`
	SourceDir string         `json:"source_dir"`
}

// Registry manages all loaded plugins and provides lookup by ID, type, or tool name.
type Registry struct {
	mu      sync.RWMutex
	plugins map[string]*PluginInfo // keyed by plugin ID

	// Reverse index: tool name → plugin ID for fast dispatch
	toolIndex map[string]string

	cfg       *config.Config
	pluginDir string
	logger    *logrus.Entry
}

// NewRegistry creates a plugin registry that discovers plugins from the given directory.
func NewRegistry(cfg *config.Config, pluginDir string) *Registry {
	return &Registry{
		plugins:   make(map[string]*PluginInfo),
		toolIndex: make(map[string]string),
		cfg:       cfg,
		pluginDir: pluginDir,
		logger:    logrus.WithField("component", "plugin-registry"),
	}
}

// Register adds a plugin to the registry and initializes it.
// If a plugin with the same ID is already registered, it is replaced (hot-reload).
func (r *Registry) Register(ctx context.Context, plugin Plugin) error {
	manifest := plugin.Manifest()

	if manifest.ID == "" {
		return fmt.Errorf("plugin manifest missing required 'id' field")
	}
	if manifest.Name == "" {
		return fmt.Errorf("plugin %q manifest missing required 'name' field", manifest.ID)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// If replacing an existing plugin, shut down the old one first
	if existing, ok := r.plugins[manifest.ID]; ok {
		r.logger.WithField("plugin_id", manifest.ID).Info("replacing existing plugin (hot-reload)")
		if err := existing.Plugin.Shutdown(ctx); err != nil {
			r.logger.WithError(err).WithField("plugin_id", manifest.ID).Warn("error shutting down old plugin during hot-reload")
		}
		// Remove old tool index entries
		for _, td := range existing.Manifest.Tools {
			delete(r.toolIndex, td.Name)
		}
	}

	info := &PluginInfo{
		Plugin:   plugin,
		Manifest: manifest,
		Status:   PluginStatusLoading,
		LoadedAt: time.Now(),
	}

	// Check for tool name conflicts with other plugins
	for _, td := range manifest.Tools {
		if conflictID, exists := r.toolIndex[td.Name]; exists && conflictID != manifest.ID {
			info.Status = PluginStatusError
			info.Error = fmt.Sprintf("tool name %q conflicts with plugin %q", td.Name, conflictID)
			r.plugins[manifest.ID] = info
			return fmt.Errorf("tool name conflict: %q is already registered by plugin %q", td.Name, conflictID)
		}
	}

	// Build plugin config from environment
	pluginCfg := r.buildPluginConfig(manifest)

	// Initialize the plugin
	if err := plugin.Init(ctx, pluginCfg); err != nil {
		info.Status = PluginStatusError
		info.Error = err.Error()
		r.plugins[manifest.ID] = info
		return fmt.Errorf("plugin %q init failed: %w", manifest.ID, err)
	}

	// Register tool index entries
	for _, td := range manifest.Tools {
		r.toolIndex[td.Name] = manifest.ID
	}

	info.Status = PluginStatusActive
	r.plugins[manifest.ID] = info

	r.logger.WithFields(logrus.Fields{
		"plugin_id":   manifest.ID,
		"plugin_name": manifest.Name,
		"plugin_type": manifest.Type,
		"tools_count": len(manifest.Tools),
		"version":     manifest.Version,
	}).Info("plugin registered and active")

	return nil
}

// Unregister removes a plugin and shuts it down.
func (r *Registry) Unregister(ctx context.Context, pluginID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	info, ok := r.plugins[pluginID]
	if !ok {
		return fmt.Errorf("plugin %q not found", pluginID)
	}

	if err := info.Plugin.Shutdown(ctx); err != nil {
		r.logger.WithError(err).WithField("plugin_id", pluginID).Warn("error during plugin shutdown")
	}

	for _, td := range info.Manifest.Tools {
		delete(r.toolIndex, td.Name)
	}
	delete(r.plugins, pluginID)

	r.logger.WithField("plugin_id", pluginID).Info("plugin unregistered")
	return nil
}

// GetPlugin returns a plugin by ID.
func (r *Registry) GetPlugin(pluginID string) (Plugin, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	info, ok := r.plugins[pluginID]
	if !ok || info.Status != PluginStatusActive {
		return nil, false
	}
	return info.Plugin, true
}

// GetPluginForTool returns the plugin that handles the given tool name.
func (r *Registry) GetPluginForTool(toolName string) (Plugin, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	pluginID, ok := r.toolIndex[toolName]
	if !ok {
		return nil, false
	}

	info, ok := r.plugins[pluginID]
	if !ok || info.Status != PluginStatusActive {
		return nil, false
	}
	return info.Plugin, true
}

// IsPluginTool returns true if the given tool name is provided by a plugin.
func (r *Registry) IsPluginTool(toolName string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.toolIndex[toolName]
	return ok
}

// ListPlugins returns info about all registered plugins.
func (r *Registry) ListPlugins() []PluginInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]PluginInfo, 0, len(r.plugins))
	for _, info := range r.plugins {
		result = append(result, *info)
	}
	return result
}

// ListActiveTools returns all LLM tools from active plugins, optionally filtered
// by agent context. This is called when building the tool set for an agent.
func (r *Registry) ListActiveTools(agentContext string) []llms.Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var allTools []llms.Tool
	for _, info := range r.plugins {
		if info.Status != PluginStatusActive || !info.Plugin.IsAvailable() {
			continue
		}

		// Filter by agent context if the plugin restricts it
		if len(info.Manifest.AgentContexts) > 0 && agentContext != "" {
			found := false
			for _, ac := range info.Manifest.AgentContexts {
				if ac == agentContext {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		allTools = append(allTools, info.Plugin.Tools()...)
	}
	return allTools
}

// HandleToolCall dispatches a tool call to the appropriate plugin.
// Returns tools.ErrToolNotFound-equivalent if no plugin handles it.
func (r *Registry) HandleToolCall(ctx context.Context, name string, args json.RawMessage) (string, error) {
	plugin, ok := r.GetPluginForTool(name)
	if !ok {
		return "", fmt.Errorf("no plugin registered for tool %q", name)
	}

	if !plugin.IsAvailable() {
		return "", fmt.Errorf("plugin for tool %q is not available", name)
	}

	return plugin.Handle(ctx, name, args)
}

// ShutdownAll gracefully shuts down all plugins.
func (r *Registry) ShutdownAll(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for id, info := range r.plugins {
		if info.Status == PluginStatusActive {
			if err := info.Plugin.Shutdown(ctx); err != nil {
				r.logger.WithError(err).WithField("plugin_id", id).Warn("error during plugin shutdown")
			}
		}
	}

	r.plugins = make(map[string]*PluginInfo)
	r.toolIndex = make(map[string]string)
	r.logger.Info("all plugins shut down")
}

// DiscoverAndLoad scans the plugin directory for manifest.json files
// and loads all discovered plugins.
func (r *Registry) DiscoverAndLoad(ctx context.Context) error {
	if r.pluginDir == "" {
		return nil
	}

	entries, err := os.ReadDir(r.pluginDir)
	if err != nil {
		if os.IsNotExist(err) {
			r.logger.WithField("dir", r.pluginDir).Debug("plugin directory does not exist, skipping discovery")
			return nil
		}
		return fmt.Errorf("failed to read plugin directory %q: %w", r.pluginDir, err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		manifestPath := filepath.Join(r.pluginDir, entry.Name(), "manifest.json")
		if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
			continue
		}

		data, err := os.ReadFile(manifestPath)
		if err != nil {
			r.logger.WithError(err).WithField("path", manifestPath).Warn("failed to read plugin manifest")
			continue
		}

		var manifest PluginManifest
		if err := json.Unmarshal(data, &manifest); err != nil {
			r.logger.WithError(err).WithField("path", manifestPath).Warn("failed to parse plugin manifest")
			continue
		}

		// For HTTP-based plugins, create an adapter
		plugin := NewHTTPPlugin(manifest, filepath.Join(r.pluginDir, entry.Name()))

		if err := r.Register(ctx, plugin); err != nil {
			r.logger.WithError(err).WithField("plugin_id", manifest.ID).Warn("failed to register discovered plugin")
			continue
		}
	}

	return nil
}

// buildPluginConfig assembles the runtime config for a plugin from env vars.
func (r *Registry) buildPluginConfig(manifest PluginManifest) PluginConfig {
	env := make(map[string]string)
	for _, field := range manifest.ConfigSchema {
		val := os.Getenv(field.Name)
		if val == "" {
			val = field.Default
		}
		if val != "" {
			env[field.Name] = val
		}
	}

	dataDir := filepath.Join(r.cfg.DataDir, "plugins", manifest.ID)
	_ = os.MkdirAll(dataDir, 0755)

	return PluginConfig{
		Env:     env,
		DataDir: dataDir,
		Logger:  r.logger.WithField("plugin_id", manifest.ID),
	}
}

// PluginToolAdapter wraps a Plugin to satisfy the existing tools.Tool interface,
// bridging the plugin system into the existing tool execution pipeline.
type PluginToolAdapter struct {
	registry *Registry
	toolName string
}

// NewPluginToolAdapter creates an adapter that routes a specific tool name
// through the plugin registry.
func NewPluginToolAdapter(registry *Registry, toolName string) tools.Tool {
	return &PluginToolAdapter{
		registry: registry,
		toolName: toolName,
	}
}

func (a *PluginToolAdapter) Handle(ctx context.Context, name string, args json.RawMessage) (string, error) {
	return a.registry.HandleToolCall(ctx, name, args)
}

func (a *PluginToolAdapter) IsAvailable() bool {
	plugin, ok := a.registry.GetPluginForTool(a.toolName)
	if !ok {
		return false
	}
	return plugin.IsAvailable()
}
