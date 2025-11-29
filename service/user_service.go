package service

import (
	"context"
	"errors"
	"log"
	"time"

	"moongazing/database"
	"moongazing/models"
	"moongazing/utils"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type UserService struct{}

func NewUserService() *UserService {
	return &UserService{}
}

// Register creates a new user
func (s *UserService) Register(username, password, email string) (*models.User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	collection := database.GetCollection(models.CollectionUsers)
	
	// Check if username already exists
	var existingUser models.User
	err := collection.FindOne(ctx, bson.M{"username": username}).Decode(&existingUser)
	if err == nil {
		return nil, errors.New("用户名已存在")
	}
	
	// Check if email already exists
	err = collection.FindOne(ctx, bson.M{"email": email}).Decode(&existingUser)
	if err == nil {
		return nil, errors.New("邮箱已被注册")
	}
	
	// Hash password
	hashedPassword, err := utils.HashPassword(password)
	if err != nil {
		return nil, errors.New("密码加密失败")
	}
	
	user := &models.User{
		ID:        primitive.NewObjectID(),
		Username:  username,
		Password:  hashedPassword,
		Email:     email,
		Role:      "user",
		Status:    1,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	
	_, err = collection.InsertOne(ctx, user)
	if err != nil {
		return nil, errors.New("创建用户失败")
	}
	
	return user, nil
}

// Login authenticates user and returns JWT token
func (s *UserService) Login(username, password string) (string, *models.User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	collection := database.GetCollection(models.CollectionUsers)
	
	var user models.User
	err := collection.FindOne(ctx, bson.M{"username": username}).Decode(&user)
	if err != nil {
		log.Printf("[Login] User not found: %s, error: %v", username, err)
		return "", nil, errors.New("用户名或密码错误")
	}
	
	log.Printf("[Login] Found user: %s, password hash length: %d", user.Username, len(user.Password))
	log.Printf("[Login] Stored hash: %s", user.Password)
	
	if !utils.CheckPassword(password, user.Password) {
		log.Printf("[Login] Password check failed for user: %s", username)
		return "", nil, errors.New("用户名或密码错误")
	}
	
	if user.Status != 1 {
		return "", nil, errors.New("用户已被禁用")
	}
	
	// Generate JWT token
	token, err := utils.GenerateToken(user.ID.Hex(), user.Username, user.Role)
	if err != nil {
		return "", nil, errors.New("生成Token失败")
	}
	
	// Update last login time
	_, _ = collection.UpdateOne(ctx, bson.M{"_id": user.ID}, bson.M{
		"$set": bson.M{"last_login": time.Now()},
	})
	
	return token, &user, nil
}

// GetUserByID retrieves user by ID
func (s *UserService) GetUserByID(userID string) (*models.User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return nil, errors.New("无效的用户ID")
	}
	
	collection := database.GetCollection(models.CollectionUsers)
	
	var user models.User
	err = collection.FindOne(ctx, bson.M{"_id": objID}).Decode(&user)
	if err != nil {
		return nil, errors.New("用户不存在")
	}
	
	return &user, nil
}

// UpdateUser updates user information
func (s *UserService) UpdateUser(userID string, updates map[string]interface{}) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return errors.New("无效的用户ID")
	}
	
	collection := database.GetCollection(models.CollectionUsers)
	
	updates["updated_at"] = time.Now()
	_, err = collection.UpdateOne(ctx, bson.M{"_id": objID}, bson.M{"$set": updates})
	if err != nil {
		return errors.New("更新用户失败")
	}
	
	return nil
}

// ChangePassword changes user password
func (s *UserService) ChangePassword(userID, oldPassword, newPassword string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return errors.New("无效的用户ID")
	}
	
	collection := database.GetCollection(models.CollectionUsers)
	
	var user models.User
	err = collection.FindOne(ctx, bson.M{"_id": objID}).Decode(&user)
	if err != nil {
		return errors.New("用户不存在")
	}
	
	if !utils.CheckPassword(oldPassword, user.Password) {
		return errors.New("原密码错误")
	}
	
	hashedPassword, err := utils.HashPassword(newPassword)
	if err != nil {
		return errors.New("密码加密失败")
	}
	
	_, err = collection.UpdateOne(ctx, bson.M{"_id": objID}, bson.M{
		"$set": bson.M{
			"password":   hashedPassword,
			"updated_at": time.Now(),
		},
	})
	if err != nil {
		return errors.New("修改密码失败")
	}
	
	return nil
}

// ListUsers lists all users with pagination
func (s *UserService) ListUsers(page, pageSize int, keyword string) ([]*models.User, int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	collection := database.GetCollection(models.CollectionUsers)
	
	filter := bson.M{}
	if keyword != "" {
		filter["$or"] = []bson.M{
			{"username": bson.M{"$regex": keyword, "$options": "i"}},
			{"email": bson.M{"$regex": keyword, "$options": "i"}},
		}
	}
	
	// Get total count
	total, err := collection.CountDocuments(ctx, filter)
	if err != nil {
		return nil, 0, errors.New("查询用户数量失败")
	}
	
	// Query with pagination
	opts := options.Find().
		SetSkip(int64((page - 1) * pageSize)).
		SetLimit(int64(pageSize)).
		SetSort(bson.D{{Key: "created_at", Value: -1}})
	
	cursor, err := collection.Find(ctx, filter, opts)
	if err != nil {
		return nil, 0, errors.New("查询用户列表失败")
	}
	defer cursor.Close(ctx)
	
	var users []*models.User
	if err = cursor.All(ctx, &users); err != nil {
		return nil, 0, errors.New("解析用户数据失败")
	}
	
	return users, total, nil
}

// DeleteUser deletes a user
func (s *UserService) DeleteUser(userID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return errors.New("无效的用户ID")
	}
	
	collection := database.GetCollection(models.CollectionUsers)
	
	result, err := collection.DeleteOne(ctx, bson.M{"_id": objID})
	if err != nil {
		return errors.New("删除用户失败")
	}
	
	if result.DeletedCount == 0 {
		return errors.New("用户不存在")
	}
	
	return nil
}

// SetUserStatus enables or disables a user
func (s *UserService) SetUserStatus(userID string, status int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return errors.New("无效的用户ID")
	}
	
	collection := database.GetCollection(models.CollectionUsers)
	
	_, err = collection.UpdateOne(ctx, bson.M{"_id": objID}, bson.M{
		"$set": bson.M{
			"status":     status,
			"updated_at": time.Now(),
		},
	})
	if err != nil {
		return errors.New("更新用户状态失败")
	}
	
	return nil
}

// InitAdmin creates default admin user if not exists
func (s *UserService) InitAdmin() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	collection := database.GetCollection(models.CollectionUsers)
	
	// Check if admin exists
	var admin models.User
	err := collection.FindOne(ctx, bson.M{"username": "admin"}).Decode(&admin)
	if err == mongo.ErrNoDocuments {
		// Create default admin
		password := "admin123"
		hashedPassword, hashErr := utils.HashPassword(password)
		if hashErr != nil {
			log.Printf("[InitAdmin] Hash error: %v", hashErr)
			return hashErr
		}
		log.Printf("[InitAdmin] Creating admin with password: %s", password)
		log.Printf("[InitAdmin] Generated hash: %s", hashedPassword)
		
		// 验证哈希
		if !utils.CheckPassword(password, hashedPassword) {
			log.Printf("[InitAdmin] WARNING: Hash verification failed immediately after generation!")
		} else {
			log.Printf("[InitAdmin] Hash verification OK")
		}
		
		adminUser := &models.User{
			ID:        primitive.NewObjectID(),
			Username:  "admin",
			Password:  hashedPassword,
			Email:     "admin@localhost",
			Role:      "admin",
			Status:    1,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		_, err = collection.InsertOne(ctx, adminUser)
		if err != nil {
			return errors.New("创建管理员账户失败")
		}
		log.Printf("[InitAdmin] Admin user created successfully")
	} else {
		log.Printf("[InitAdmin] Admin user already exists")
	}
	
	return nil
}
