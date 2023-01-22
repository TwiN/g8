package g8

import (
	"github.com/TwiN/gocache/v2"
)

type Cache interface {
	Get(key string) (value any, exists bool)
	Set(key string, value any)
}

// Make sure that gocache.Cache is compatible with the interface
var _ Cache = (*gocache.Cache)(nil)
