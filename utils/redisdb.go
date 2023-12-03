package utils

import (
	"context"
	"fmt"
	"github.com/redis/go-redis/v9"
)

var Redis *redis.Client

func RedisClientDriver(redisUri string) *redis.Client {
	ctx := context.Background()
	opt, err := redis.ParseURL(redisUri)
	if err != nil {
		panic(err)
	}
	redisClient := redis.NewClient(opt)
	res, err := redisClient.Ping(ctx).Result()

	if err != nil {
		ctx.Done()
		panic(err)
	}

	if res == "PONG" {
		fmt.Println("Redis is ready")
	}

	Redis = redisClient
	return redisClient
}
