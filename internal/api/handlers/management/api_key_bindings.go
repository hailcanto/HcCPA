package management

import (
	"encoding/json"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
)

// api-key-bindings: []APIKeyBinding

func (h *Handler) GetAPIKeyBindings(c *gin.Context) {
	c.JSON(200, gin.H{"api-key-bindings": h.cfg.APIKeyBindings})
}

func (h *Handler) PutAPIKeyBindings(c *gin.Context) {
	data, err := c.GetRawData()
	if err != nil {
		c.JSON(400, gin.H{"error": "failed to read body"})
		return
	}
	var arr []config.APIKeyBinding
	if err = json.Unmarshal(data, &arr); err != nil {
		var obj struct {
			Items []config.APIKeyBinding `json:"items"`
		}
		if err2 := json.Unmarshal(data, &obj); err2 != nil {
			c.JSON(400, gin.H{"error": "invalid body"})
			return
		}
		arr = obj.Items
	}
	h.cfg.APIKeyBindings = append([]config.APIKeyBinding(nil), arr...)
	h.persist(c)
}

func (h *Handler) DeleteAPIKeyBinding(c *gin.Context) {
	key := strings.TrimSpace(c.Query("key"))
	if key == "" {
		c.JSON(400, gin.H{"error": "missing key query parameter"})
		return
	}
	out := make([]config.APIKeyBinding, 0, len(h.cfg.APIKeyBindings))
	for _, b := range h.cfg.APIKeyBindings {
		if b.Key != key {
			out = append(out, b)
		}
	}
	h.cfg.APIKeyBindings = out
	h.persist(c)
}
