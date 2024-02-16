package rbac

import (
	"container/list"
	"sync"
	"time"
)

type CacheItem struct {
	key       interface{}
	value     interface{}
	timestamp time.Time
}

type LRUCache struct {
	capacity int
	ttl      time.Duration
	items    map[interface{}]*list.Element
	list     *list.List
	lock     sync.Mutex
}

func NewLRUCache(capacity int, ttl time.Duration) *LRUCache {
	return &LRUCache{
		capacity: capacity,
		ttl:      ttl,
		items:    make(map[interface{}]*list.Element),
		list:     list.New(),
	}
}

func (c *LRUCache) Get(key interface{}) (value interface{}, ok bool) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if element, found := c.items[key]; found {
		item := element.Value.(*CacheItem)
		if c.ttl > 0 && time.Since(item.timestamp) > c.ttl {
			c.list.Remove(element)
			delete(c.items, key)
			return nil, false
		}
		c.list.MoveToFront(element)
		return item.value, true
	}
	return nil, false
}

func (c *LRUCache) Put(key, value interface{}) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if element, found := c.items[key]; found {
		c.list.MoveToFront(element)
		item := element.Value.(*CacheItem)
		item.value = value
		item.timestamp = time.Now()
		return
	}

	if c.list.Len() == c.capacity {
		oldest := c.list.Back()
		if oldest != nil {
			c.list.Remove(oldest)
			delete(c.items, oldest.Value.(*CacheItem).key)
		}
	}

	item := &CacheItem{
		key:       key,
		value:     value,
		timestamp: time.Now(),
	}
	element := c.list.PushFront(item)
	c.items[key] = element
}

func (c *LRUCache) ExpireItems() {
	c.lock.Lock()
	defer c.lock.Unlock()

	for e := c.list.Back(); e != nil; {
		next := e.Prev()
		if item, ok := e.Value.(*CacheItem); ok {
			if c.ttl > 0 && time.Since(item.timestamp) > c.ttl {
				c.list.Remove(e)
				delete(c.items, item.key)
			} else {
				break
			}
		}
		e = next
	}
}
