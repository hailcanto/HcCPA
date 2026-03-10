package auth

import (
	"context"
	"strings"

	log "github.com/sirupsen/logrus"
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
		log.Debug("[Binding] No gin context, returning all auths")
		return auths
	}
	getter, ok := ginVal.(contextGetter)
	if !ok {
		log.Debug("[Binding] gin context not a contextGetter, returning all auths")
		return auths
	}
	metaVal, exists := getter.Get("accessMetadata")
	if !exists {
		log.Debug("[Binding] No accessMetadata in context, returning all auths")
		return auths
	}
	meta, ok := metaVal.(map[string]string)
	if !ok {
		log.Debug("[Binding] accessMetadata not a map[string]string, returning all auths")
		return auths
	}
	raw := meta["auth_files"]
	if raw == "" {
		log.Debug("[Binding] No auth_files in metadata, returning all auths")
		return auths
	}
	log.Infof("[Binding] Found auth_files restriction: %s", raw)
	parts := strings.Split(raw, ",")
	allowed := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			allowed[trimmed] = struct{}{}
		}
	}
	if len(allowed) == 0 {
		log.Warn("[Binding] auth_files parsed to empty set, returning all auths")
		return auths
	}
	filtered := make([]*Auth, 0, len(auths))
	for _, a := range auths {
		if _, ok := allowed[a.FileName]; ok {
			filtered = append(filtered, a)
		}
	}
	log.Infof("[Binding] Filtered %d auths down to %d based on auth_files binding", len(auths), len(filtered))
	if len(filtered) == 0 {
		log.Warn("[Binding] No auths matched binding, returning all as fallback")
		return auths // fallback: don't block all if no match
	}
	return filtered
}
