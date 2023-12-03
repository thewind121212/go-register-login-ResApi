package main

import (
	"fmt"
	"github.com/go-playground/validator/v10"
	"github.com/joho/godotenv"
	"linhdevtran99/rest-api/models"
	"linhdevtran99/rest-api/rest-api"
	"linhdevtran99/rest-api/utils"
	"log"
	"os"
)

func main() {
	if err := godotenv.Load(); err != nil {
		fmt.Println("No .env file found")
		panic(err)
	}

	redisUri := os.Getenv("REDIS_URI")
	apiTestPort := os.Getenv("API_TEST_PORT")
	mongoUri := os.Getenv("MONGO_URI")

	if redisUri == "" || apiTestPort == "" || mongoUri == "" {
		fmt.Println("Redis URI:", redisUri)
		fmt.Println("API test Port:", apiTestPort)
		fmt.Println("Mongodb Uri:", mongoUri)
		log.Fatal("Error in some value")
	}

	models.Validate = validator.New(validator.WithRequiredStructEnabled())

	utils.InitMongoDriver(mongoUri)

	server := rest_api.NewAPIServer(apiTestPort)
	utils.RedisClientDriver(redisUri)
	server.Run()
}
