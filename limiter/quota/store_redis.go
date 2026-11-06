package quota

import (
	"context"
	"encoding/json"

	"github.com/go-redis/redis/v8"
)

const defaultRedisQuotaKey = "gost:quota"

type RedisConfig struct {
	Addr     string
	Username string
	Password string
	DB       int
	Key      string
}

type redisQuotaClient interface {
	Get(ctx context.Context, key, field string) (string, error)
	Set(ctx context.Context, key, field string, value interface{}) error
}

type redisClient struct {
	client *redis.Client
}

func (c *redisClient) Get(ctx context.Context, key, field string) (string, error) {
	return c.client.HGet(ctx, key, field).Result()
}

func (c *redisClient) Set(ctx context.Context, key, field string, value interface{}) error {
	return c.client.HSet(ctx, key, field, value).Err()
}

type redisStore struct {
	cfg    RedisConfig
	client redisQuotaClient
}

func NewRedisStore(cfg RedisConfig) Store {
	key := cfg.Key
	if key == "" {
		key = defaultRedisQuotaKey
	}
	cfg.Key = key
	return &redisStore{
		cfg: cfg,
		client: &redisClient{client: redis.NewClient(&redis.Options{
			Addr:     cfg.Addr,
			Username: cfg.Username,
			Password: cfg.Password,
			DB:       cfg.DB,
		})},
	}
}

func (s *redisStore) Load(name string) (Record, bool, error) {
	b, err := s.client.Get(context.Background(), s.cfg.Key, name)
	if err == redis.Nil {
		return Record{}, false, nil
	}
	if err != nil {
		return Record{}, false, err
	}
	var rec Record
	if err := json.Unmarshal([]byte(b), &rec); err != nil {
		return Record{}, false, err
	}
	return rec, true, nil
}

func (s *redisStore) Save(name string, rec Record) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return s.client.Set(context.Background(), s.cfg.Key, name, b)
}
