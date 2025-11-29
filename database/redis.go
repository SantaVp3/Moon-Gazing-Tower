package database

import (
	"context"
	"fmt"
	"log"
	"sync"

	"moongazing/config"

	"github.com/go-redis/redis/v8"
)

var (
	redisClient *redis.Client
	redisOnce   sync.Once
)

func InitRedis(cfg *config.RedisConfig) *redis.Client {
	redisOnce.Do(func() {
		client := redis.NewClient(&redis.Options{
			Addr:     fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
			Password: cfg.Password,
			DB:       cfg.DB,
		})

		ctx := context.Background()
		if _, err := client.Ping(ctx).Result(); err != nil {
			log.Fatalf("Failed to connect to Redis: %v", err)
		}

		log.Println("Connected to Redis successfully")
		redisClient = client
	})

	return redisClient
}

func GetRedis() *redis.Client {
	if redisClient == nil {
		log.Fatal("Redis not initialized. Call InitRedis first.")
	}
	return redisClient
}

func CloseRedis() {
	if redisClient != nil {
		if err := redisClient.Close(); err != nil {
			log.Printf("Error closing Redis: %v", err)
		}
		fmt.Println("Redis connection closed")
	}
}
