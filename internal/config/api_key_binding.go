package config

// APIKeyBinding associates a client API key with specific auth files and allowed models.
type APIKeyBinding struct {
	// Key is the API key string (must match an entry in SDKConfig.APIKeys).
	Key string `yaml:"key" json:"key"`
	// Name is an optional human-readable label.
	Name string `yaml:"name,omitempty" json:"name,omitempty"`
	// AuthFiles restricts this key to credentials loaded from these auth file names.
	// An empty list means no restriction (all auth files are eligible).
	AuthFiles []string `yaml:"auth-files,omitempty" json:"auth-files,omitempty"`
	// Models restricts this key to the listed model names.
	// An empty list means no restriction (all models are allowed).
	Models []string `yaml:"models,omitempty" json:"models,omitempty"`
}
