// Package redis implements kv.Cache on Redis without importing a Redis driver.
//
// The package needs one method from your client: Eval. Wrapping go-redis takes
// about ten lines (see the Client doc comment). All operations are single Lua
// scripts, so they are atomic and need no extra round trips.
package redis

import (
	"context"
	"fmt"
	"strconv"
	"time"
)

// Client is the one capability the adapter needs from a Redis driver. Eval must
// run script with the given keys and args and return the reply: a string for
// bulk replies, an integer type for integers, and (nil, nil) for a nil reply.
//
// Wrapping github.com/redis/go-redis/v9:
//
//	type goRedis struct{ c redis.Scripter }
//
//	func (g goRedis) Eval(ctx context.Context, script string, keys []string, args ...any) (any, error) {
//	    v, err := g.c.Eval(ctx, script, keys, args...).Result()
//	    if errors.Is(err, redis.Nil) {
//	        return nil, nil
//	    }
//	    return v, err
//	}
//
//	stores := kv.FromCache(kvredis.New(goRedis{rdb}, "theauth:"))
type Client interface {
	Eval(ctx context.Context, script string, keys []string, args ...any) (any, error)
}

// Lua scripts. Exported only so test doubles can recognize them.
const (
	ScriptGet   = `return redis.call('GET', KEYS[1])`
	ScriptSet   = `if tonumber(ARGV[2]) > 0 then return redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2]) end return redis.call('SET', KEYS[1], ARGV[1])`
	ScriptSetNX = `local r if tonumber(ARGV[2]) > 0 then r = redis.call('SET', KEYS[1], ARGV[1], 'NX', 'PX', ARGV[2]) else r = redis.call('SET', KEYS[1], ARGV[1], 'NX') end if r then return 1 end return 0`
	ScriptDel   = `return redis.call('DEL', KEYS[1])`
	ScriptIncr  = `local n = redis.call('INCR', KEYS[1]) if n == 1 and tonumber(ARGV[1]) > 0 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end return n`
)

// Store implements kv.Cache over Redis.
type Store struct {
	c      Client
	prefix string
}

// New returns a Store. prefix is prepended to every key so several apps can
// share one Redis (for example "theauth:").
func New(c Client, prefix string) *Store { return &Store{c: c, prefix: prefix} }

func ms(ttl time.Duration) string {
	if ttl <= 0 {
		return "0"
	}
	m := ttl.Milliseconds()
	if m < 1 {
		m = 1
	}
	return strconv.FormatInt(m, 10)
}

// Get implements kv.Cache.
func (s *Store) Get(ctx context.Context, key string) ([]byte, bool, error) {
	v, err := s.c.Eval(ctx, ScriptGet, []string{s.prefix + key})
	if err != nil {
		return nil, false, err
	}
	switch x := v.(type) {
	case nil:
		return nil, false, nil
	case string:
		return []byte(x), true, nil
	case []byte:
		return x, true, nil
	default:
		return nil, false, fmt.Errorf("kv/redis: unexpected GET reply %T", v)
	}
}

// Set implements kv.Cache.
func (s *Store) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	_, err := s.c.Eval(ctx, ScriptSet, []string{s.prefix + key}, string(value), ms(ttl))
	return err
}

// SetNX implements kv.Cache.
func (s *Store) SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	v, err := s.c.Eval(ctx, ScriptSetNX, []string{s.prefix + key}, string(value), ms(ttl))
	if err != nil {
		return false, err
	}
	n, err := toInt(v)
	return n == 1, err
}

// Delete implements kv.Cache.
func (s *Store) Delete(ctx context.Context, key string) error {
	_, err := s.c.Eval(ctx, ScriptDel, []string{s.prefix + key})
	return err
}

// Incr implements kv.Cache.
func (s *Store) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	v, err := s.c.Eval(ctx, ScriptIncr, []string{s.prefix + key}, ms(ttl))
	if err != nil {
		return 0, err
	}
	return toInt(v)
}

func toInt(v any) (int64, error) {
	switch x := v.(type) {
	case int64:
		return x, nil
	case int:
		return int64(x), nil
	case string:
		return strconv.ParseInt(x, 10, 64)
	default:
		return 0, fmt.Errorf("kv/redis: unexpected integer reply %T", v)
	}
}
