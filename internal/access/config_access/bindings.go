package configaccess

import (
	"strings"
	"sync"

	sdkconfig "github.com/router-for-me/CLIProxyAPI/v6/sdk/config"
)

// bindingEntry holds the resolved binding for a single API key.
type bindingEntry struct {
	authFiles []string
	models    []string
}

var (
	bindingsMu sync.RWMutex
	bindings   map[string]*bindingEntry
)

// storeBindings parses APIKeyBindings and stores them for later metadata enrichment.
func storeBindings(entries []sdkconfig.APIKeyBinding) {
	m := buildBindingsMap(entries)
	bindingsMu.Lock()
	bindings = m
	bindingsMu.Unlock()
}

// applyBindingsMetadata enriches the authentication metadata with auth_files and
// allowed_models restrictions if a binding exists for the given API key.
func applyBindingsMetadata(meta map[string]string, key string) {
	bindingsMu.RLock()
	b, ok := bindings[key]
	bindingsMu.RUnlock()
	if !ok || b == nil {
		return
	}
	if len(b.authFiles) > 0 {
		meta["auth_files"] = strings.Join(b.authFiles, ",")
	}
	if len(b.models) > 0 {
		meta["allowed_models"] = strings.Join(b.models, ",")
	}
}

func buildBindingsMap(entries []sdkconfig.APIKeyBinding) map[string]*bindingEntry {
	if len(entries) == 0 {
		return nil
	}
	m := make(map[string]*bindingEntry, len(entries))
	for _, b := range entries {
		key := strings.TrimSpace(b.Key)
		if key == "" {
			continue
		}
		m[key] = &bindingEntry{
			authFiles: b.AuthFiles,
			models:    b.Models,
		}
	}
	if len(m) == 0 {
		return nil
	}
	return m
}
