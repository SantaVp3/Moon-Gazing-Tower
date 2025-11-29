package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// User represents a user in the system
type User struct {
	ID        primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Username  string             `json:"username" bson:"username"`
	Password  string             `json:"-" bson:"password"`
	Email     string             `json:"email" bson:"email"`
	Phone     string             `json:"phone" bson:"phone"`
	Avatar    string             `json:"avatar" bson:"avatar"`
	Role      string             `json:"role" bson:"role"` // admin, user, viewer
	Status    int                `json:"status" bson:"status"` // 1: active, 0: disabled
	LastLogin time.Time          `json:"last_login" bson:"last_login"`
	CreatedAt time.Time          `json:"created_at" bson:"created_at"`
	UpdatedAt time.Time          `json:"updated_at" bson:"updated_at"`
}

// Role represents user roles
type Role struct {
	ID          primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Name        string             `json:"name" bson:"name"`
	Description string             `json:"description" bson:"description"`
	Permissions []string           `json:"permissions" bson:"permissions"`
	CreatedAt   time.Time          `json:"created_at" bson:"created_at"`
	UpdatedAt   time.Time          `json:"updated_at" bson:"updated_at"`
}

// Permission represents system permissions
type Permission struct {
	ID          primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Name        string             `json:"name" bson:"name"`
	Code        string             `json:"code" bson:"code"`
	Description string             `json:"description" bson:"description"`
	Module      string             `json:"module" bson:"module"`
	CreatedAt   time.Time          `json:"created_at" bson:"created_at"`
}

// OperationLog represents operation audit logs
type OperationLog struct {
	ID        primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	UserID    primitive.ObjectID `json:"user_id" bson:"user_id"`
	Username  string             `json:"username" bson:"username"`
	Action    string             `json:"action" bson:"action"`
	Module    string             `json:"module" bson:"module"`
	Target    string             `json:"target" bson:"target"`
	Detail    string             `json:"detail" bson:"detail"`
	IP        string             `json:"ip" bson:"ip"`
	UserAgent string             `json:"user_agent" bson:"user_agent"`
	Status    int                `json:"status" bson:"status"` // 1: success, 0: failed
	CreatedAt time.Time          `json:"created_at" bson:"created_at"`
}

// Workspace represents isolated workspace for multi-tenant
type Workspace struct {
	ID          primitive.ObjectID   `json:"id" bson:"_id,omitempty"`
	Name        string               `json:"name" bson:"name"`
	Description string               `json:"description" bson:"description"`
	OwnerID     primitive.ObjectID   `json:"owner_id" bson:"owner_id"`
	Members     []primitive.ObjectID `json:"members" bson:"members"`
	CreatedAt   time.Time            `json:"created_at" bson:"created_at"`
	UpdatedAt   time.Time            `json:"updated_at" bson:"updated_at"`
}

// Collection names
const (
	CollectionUsers        = "users"
	CollectionRoles        = "roles"
	CollectionPermissions  = "permissions"
	CollectionOperationLog = "operation_logs"
	CollectionWorkspaces   = "workspaces"
)
