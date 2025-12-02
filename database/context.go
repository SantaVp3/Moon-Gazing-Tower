package database

import (
	"context"
	"time"
)

// 数据库操作超时常量
const (
	DefaultDBTimeout   = 10 * time.Second  // 默认数据库操作超时
	LongDBTimeout      = 30 * time.Second  // 长时间数据库操作超时
	ShortDBTimeout     = 5 * time.Second   // 短时间数据库操作超时
	BatchDBTimeout     = 60 * time.Second  // 批量操作超时
	AggregateDBTimeout = 30 * time.Second  // 聚合查询超时
)

// NewContext creates a context with default timeout for database operations.
// Usage:
//
//	ctx, cancel := database.NewContext()
//	defer cancel()
func NewContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), DefaultDBTimeout)
}

// NewContextWithTimeout creates a context with custom timeout.
// Usage:
//
//	ctx, cancel := database.NewContextWithTimeout(30 * time.Second)
//	defer cancel()
func NewContextWithTimeout(timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), timeout)
}

// NewLongContext creates a context with longer timeout for heavy operations.
func NewLongContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), LongDBTimeout)
}

// NewBatchContext creates a context for batch database operations.
func NewBatchContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), BatchDBTimeout)
}
