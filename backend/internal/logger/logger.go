package logger

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

// Logger 日志记录器
type Logger struct {
	infoLogger  *log.Logger
	errorLogger *log.Logger
	debugLogger *log.Logger
	logFile     *os.File
}

var GlobalLogger *Logger

// InitLogger 初始化日志
func InitLogger(logPath string, level string) error {
	// 创建日志目录
	logDir := filepath.Dir(logPath)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	// 打开日志文件
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}

	GlobalLogger = &Logger{
		infoLogger:  log.New(logFile, "[INFO] ", log.LstdFlags),
		errorLogger: log.New(logFile, "[ERROR] ", log.LstdFlags),
		debugLogger: log.New(logFile, "[DEBUG] ", log.LstdFlags),
		logFile:     logFile,
	}

	// 同时输出到控制台
	if level == "debug" {
		GlobalLogger.infoLogger.SetOutput(os.Stdout)
		GlobalLogger.errorLogger.SetOutput(os.Stderr)
		GlobalLogger.debugLogger.SetOutput(os.Stdout)
	}

	return nil
}

// Info 记录info日志
func (l *Logger) Info(format string, v ...interface{}) {
	l.infoLogger.Printf(format, v...)
}

// Error 记录error日志
func (l *Logger) Error(format string, v ...interface{}) {
	l.errorLogger.Printf(format, v...)
}

// Debug 记录debug日志
func (l *Logger) Debug(format string, v ...interface{}) {
	l.debugLogger.Printf(format, v...)
}

// Close 关闭日志文件
func (l *Logger) Close() error {
	if l.logFile != nil {
		return l.logFile.Close()
	}
	return nil
}

// RotateLog 日志轮转
func (l *Logger) RotateLog(logPath string) error {
	// 简单的日志轮转实现
	if l.logFile != nil {
		l.logFile.Close()
	}

	// 重命名旧文件
	timestamp := time.Now().Format("20060102_150405")
	oldPath := logPath + "." + timestamp
	os.Rename(logPath, oldPath)

	// 创建新文件
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return err
	}

	l.logFile = logFile
	l.infoLogger.SetOutput(logFile)
	l.errorLogger.SetOutput(logFile)
	l.debugLogger.SetOutput(logFile)

	return nil
}

// 便捷函数
func Info(format string, v ...interface{}) {
	if GlobalLogger != nil {
		GlobalLogger.Info(format, v...)
	} else {
		log.Printf("[INFO] "+format, v...)
	}
}

func Error(format string, v ...interface{}) {
	if GlobalLogger != nil {
		GlobalLogger.Error(format, v...)
	} else {
		log.Printf("[ERROR] "+format, v...)
	}
}

func Debug(format string, v ...interface{}) {
	if GlobalLogger != nil {
		GlobalLogger.Debug(format, v...)
	} else {
		log.Printf("[DEBUG] "+format, v...)
	}
}
