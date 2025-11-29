package database

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"moongazing/config"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	mongoClient *mongo.Client
	mongoOnce   sync.Once
)

func InitMongoDB(cfg *config.MongoDBConfig) *mongo.Client {
	mongoOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Timeout)*time.Second)
		defer cancel()

		clientOptions := options.Client().ApplyURI(cfg.URI)
		client, err := mongo.Connect(ctx, clientOptions)
		if err != nil {
			log.Fatalf("Failed to connect to MongoDB: %v", err)
		}

		if err := client.Ping(ctx, nil); err != nil {
			log.Fatalf("Failed to ping MongoDB: %v", err)
		}

		log.Println("Connected to MongoDB successfully")
		mongoClient = client
	})

	return mongoClient
}

func GetMongoDB() *mongo.Client {
	if mongoClient == nil {
		log.Fatal("MongoDB not initialized. Call InitMongoDB first.")
	}
	return mongoClient
}

func GetCollection(collection string) *mongo.Collection {
	cfg := config.GetConfig()
	return GetMongoDB().Database(cfg.MongoDB.Database).Collection(collection)
}

func CloseMongoDB() {
	if mongoClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := mongoClient.Disconnect(ctx); err != nil {
			log.Printf("Error disconnecting MongoDB: %v", err)
		}
		fmt.Println("MongoDB connection closed")
	}
}
