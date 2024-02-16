package rbac

import (
	"testing"
	"time"
)

func TestLRUCache_PutAndGet(t *testing.T) {
	cache := NewLRUCache(2, 10*time.Minute)

	cache.Put("key1", "value1")
	cache.Put("key2", "value2")

	if val, found := cache.Get("key1"); !found || val != "value1" {
		t.Errorf("Get(key1) = %v, %t; want value1, true", val, found)
	}

	if val, found := cache.Get("key2"); !found || val != "value2" {
		t.Errorf("Get(key2) = %v, %t; want value2, true", val, found)
	}
}

func TestLRUCache_Eviction(t *testing.T) {
	cache := NewLRUCache(2, 10*time.Minute)

	cache.Put("key1", "value1")
	cache.Put("key2", "value2")
	cache.Put("key3", "value3")

	if _, found := cache.Get("key1"); found {
		t.Error("Expected key1 to be evicted")
	}

	if val, found := cache.Get("key2"); !found || val != "value2" {
		t.Errorf("Get(key2) = %v, %t; want value2, true", val, found)
	}

	if val, found := cache.Get("key3"); !found || val != "value3" {
		t.Errorf("Get(key3) = %v, %t; want value3, true", val, found)
	}
}

func TestLRUCache_Expiration(t *testing.T) {
	cache := NewLRUCache(2, 1*time.Millisecond)

	cache.Put("key1", "value1")
	cache.Put("key2", "value2")

	time.Sleep(2 * time.Millisecond)

	cache.ExpireItems()

	if _, found := cache.Get("key1"); found {
		t.Error("Expected key1 to be expired")
	}

	if _, found := cache.Get("key2"); found {
		t.Error("Expected key2 to be expired")
	}
}

func TestLRUCache_UpdateExistingItem(t *testing.T) {
	cache := NewLRUCache(2, 10*time.Minute)

	cache.Put("key1", "value1")
	cache.Put("key1", "value1_updated")

	if val, found := cache.Get("key1"); !found || val != "value1_updated" {
		t.Errorf("Get(key1) = %v, %t; want value1_updated, true", val, found)
	}
}
