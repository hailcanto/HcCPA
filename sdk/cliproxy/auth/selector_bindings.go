package auth

import (
	"context"
	"strings"
)

// contextGetter is satisfied by *gin.Context without requiring a gin import.
type contextGetter interface {
	Get(key string) (any, bool)
}

// filterByAuthFileBinding restricts auths to those whose FileName matches the
// auth_files binding set in the access metadata. If no binding is present, all
// auths are returned unchanged.
func filterByAuthFileBinding(ctx context.Context, auths []*Auth) []*Auth {
	ginVal := ctx.Value("gin")
	if ginVal == nil {
		return auths
	}
	getter, ok := ginVal.(contextGetter)
	if !ok {
		return auths
	}
	metaVal, exists := getter.Get("accessMetadata")
	if !exists {
		return auths
	}
	meta, ok := metaVal.(map[string]string)
	if !ok {
		return auths
	}
	raw := meta["auth_files"]
	if raw == "" {
		return auths
	}
	parts := strings.Split(raw, ",")
	allowed := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			allowed[trimmed] = struct{}{}
		}
	}
	if len(allowed) == 0 {
		return auths
	}
	filtered := make([]*Auth, 0, len(auths))
	for _, a := range auths {
		if _, ok := allowed[a.FileName]; ok {
			filtered = append(filtered, a)
		}
	}
	if len(filtered) == 0 {
		return auths // fallback: don't block all if no match
	}
	return filtered
}
