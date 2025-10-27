package globalping

import "time"

type cacheEntry struct {
	ETag     string
	Data     []byte
	ExpireAt int64 // Unix timestamp
}

func (c *client) CacheClean() {
	c.cleanupCache()
}

func (c *client) CachePurge() {
	c.mu.RLock()
	defer c.mu.RUnlock()
	c.cache = map[string]*cacheEntry{}
}

func (c *client) getETag(id string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.cache[id]
	if !ok {
		return ""
	}
	return e.ETag
}

func (c *client) getCachedResponse(id string) []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.cache[id]
	if !ok {
		return nil
	}
	return e.Data
}

func (c *client) cacheResponse(id string, etag string, resp []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var expires int64
	if c.cacheExpireSeconds != 0 {
		expires = time.Now().Unix() + c.cacheExpireSeconds
	}
	e, ok := c.cache[id]
	if ok {
		e.ETag = etag
		e.Data = resp
		e.ExpireAt = expires
	} else {
		c.cache[id] = &cacheEntry{
			ETag:     etag,
			Data:     resp,
			ExpireAt: expires,
		}
	}
}

func (c *client) cleanupCache() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now().Unix()
	for k, v := range c.cache {
		if v.ExpireAt > 0 && v.ExpireAt < now {
			delete(c.cache, k)
		}
	}
}
