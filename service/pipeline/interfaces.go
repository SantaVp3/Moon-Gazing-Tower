package pipeline

import "moongazing/models"

// TaskService defines the interface for task operations
type TaskService interface {
	UpdateTask(id string, updates map[string]interface{}) error
}

// ResultService defines the interface for result operations
type ResultService interface {
	CreateResult(result *models.ScanResult) error
	CreateResultWithDedup(result *models.ScanResult) error
}
