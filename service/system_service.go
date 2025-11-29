package service

import (
	"log"
	"moongazing/models"
	"runtime"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
)

type SystemService struct{}

func NewSystemService() *SystemService {
	return &SystemService{}
}

// GetSystemInfo returns system resource usage information
func (s *SystemService) GetSystemInfo(workspaceID string) (map[string]interface{}, error) {
	// Get CPU usage
	cpuPercent, err := cpu.Percent(500*time.Millisecond, false)
	var cpuUsage float64
	if err != nil {
		log.Printf("Error getting CPU usage: %v", err)
		cpuUsage = 0
	} else if len(cpuPercent) > 0 {
		cpuUsage = cpuPercent[0]
	}

	// Get memory info
	memInfo, err := mem.VirtualMemory()
	var totalMemory, usedMemory uint64
	var memoryUsage float64
	if err != nil {
		log.Printf("Error getting memory info: %v", err)
		totalMemory = 0
		usedMemory = 0
		memoryUsage = 0
	} else {
		totalMemory = memInfo.Total
		usedMemory = memInfo.Used
		memoryUsage = memInfo.UsedPercent
	}

	// Get disk info (root partition)
	diskInfo, err := disk.Usage("/")
	var totalDisk, usedDisk uint64
	var diskUsage float64
	if err != nil {
		log.Printf("Error getting disk info: %v", err)
		totalDisk = 0
		usedDisk = 0
		diskUsage = 0
	} else {
		totalDisk = diskInfo.Total
		usedDisk = diskInfo.Used
		diskUsage = diskInfo.UsedPercent
	}

	return map[string]interface{}{
		"cpu_cores":    runtime.NumCPU(),
		"memory_total": totalMemory,
		"memory_used":  usedMemory,
		"memory_usage": memoryUsage,
		"disk_total":   totalDisk,
		"disk_used":    usedDisk,
		"disk_usage":   diskUsage,
		"cpu_usage":    cpuUsage,
	}, nil
}

// GetLiveTaskData returns real-time task and scan data
func (s *SystemService) GetLiveTaskData(workspaceID string) (map[string]interface{}, error) {
	// This would connect to your actual monitoring systems
	taskService := NewTaskService()
	oldTaskStats, _, _ := taskService.ListTasks(workspaceID, "", "", 1, 1)

	var totalTasks, runningTasks, completedTasks, failedTasks int
	if oldTaskStats != nil {
		totalTasks = len(oldTaskStats)
		runningTasks = s.countByStatus(oldTaskStats, "running")
		completedTasks = s.countByStatus(oldTaskStats, "completed")
		failedTasks = s.countByStatus(oldTaskStats, "failed")
	}

	return map[string]interface{}{
		"active_users":        0, // Would need user tracking
		"today_users":         0, // Would need user tracking
		"monthly_users":       0, // Would need user tracking
		"monthly_spend":       0, // Would need spend tracking
		"monthly_revenue":     0, // Would need revenue tracking
		"monthly_transactions":0, // Would need transaction tracking
		"tasks": map[string]interface{}{
			"total":     totalTasks,
			"running":   runningTasks,
			"completed": completedTasks,
			"failed":    failedTasks,
		},
	}, nil
}

func (s *SystemService) countByStatus(tasks []*models.Task, status string) int {
	count := 0
	for _, task := range tasks {
		if string(task.Status) == status {
			count++
		}
	}
	return count
}