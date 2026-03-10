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
	log.Infof("[Binding] filterByAuthFileBinding called with %d auths", len(auths))
	ginVal := ctx.Value("gin")
	if ginVal == nil {
		log.Warn("[Binding] No gin context found (ctx.Value('gin') == nil), returning all auths")
		return auths
	}
	log.Info("[Binding] gin context found")
	getter, ok := ginVal.(contextGetter)
	if !ok {
		log.Warnf("[Binding] gin context not a contextGetter (type=%T), returning all auths", ginVal)
		return auths
	}
	log.Info("[Binding] gin context is a contextGetter")
	metaVal, exists := getter.Get("accessMetadata")
	if !exists {
		log.Warn("[Binding] No accessMetadata in gin context, returning all auths")
		return auths
	}
	log.Infof("[Binding] accessMetadata found (type=%T)", metaVal)
	meta, ok := metaVal.(map[string]string)
	if !ok {
		log.Warnf("[Binding] accessMetadata not a map[string]string (type=%T), returning all auths", metaVal)
		return auths
	}
	log.Infof("[Binding] accessMetadata is map[string]string with %d keys: %v", len(meta), meta)
	raw := meta["auth_files"]
	if raw == "" {
		log.Warn("[Binding] No auth_files key in metadata, returning all auths")
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
	log.Infof("[Binding] Allowed auth files: %v", allowed)
	filtered := make([]*Auth, 0, len(auths))
	for _, a := range auths {
		log.Debugf("[Binding] Checking auth FileName=%s", a.FileName)
		if _, ok := allowed[a.FileName]; ok {
			filtered = append(filtered, a)
			log.Debugf("[Binding] Auth %s matched, included", a.FileName)
		}
	}
	log.Infof("[Binding] Filtered %d auths down to %d based on auth_files binding", len(auths), len(filtered))
	if len(filtered) == 0 {
		log.Warn("[Binding] No auths matched binding, returning all as fallback")
		return auths // fallback: don't block all if no match
	}
	return filtered
}
