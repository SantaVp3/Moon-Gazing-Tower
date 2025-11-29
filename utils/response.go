package utils

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Response represents API response structure
type Response struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// PagedResponse represents paginated response
type PagedResponse struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
	Total   int64       `json:"total"`
	Page    int         `json:"page"`
	Size    int         `json:"size"`
}

// Success returns successful response
func Success(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, Response{
		Code:    0,
		Message: "success",
		Data:    data,
	})
}

// SuccessWithMessage returns successful response with custom message
func SuccessWithMessage(c *gin.Context, message string, data interface{}) {
	c.JSON(http.StatusOK, Response{
		Code:    0,
		Message: message,
		Data:    data,
	})
}

// SuccessWithPagination returns paginated successful response
func SuccessWithPagination(c *gin.Context, data interface{}, total int64, page, size int) {
	c.JSON(http.StatusOK, PagedResponse{
		Code:    0,
		Message: "success",
		Data:    data,
		Total:   total,
		Page:    page,
		Size:    size,
	})
}

// Error returns error response
func Error(c *gin.Context, code int, message string) {
	c.JSON(http.StatusOK, Response{
		Code:    code,
		Message: message,
	})
}

// BadRequest returns 400 error response
func BadRequest(c *gin.Context, message string) {
	c.JSON(http.StatusBadRequest, Response{
		Code:    400,
		Message: message,
	})
}

// Unauthorized returns 401 error response
func Unauthorized(c *gin.Context, message string) {
	c.JSON(http.StatusUnauthorized, Response{
		Code:    401,
		Message: message,
	})
}

// Forbidden returns 403 error response
func Forbidden(c *gin.Context, message string) {
	c.JSON(http.StatusForbidden, Response{
		Code:    403,
		Message: message,
	})
}

// NotFound returns 404 error response
func NotFound(c *gin.Context, message string) {
	c.JSON(http.StatusNotFound, Response{
		Code:    404,
		Message: message,
	})
}

// InternalError returns 500 error response
func InternalError(c *gin.Context, message string) {
	c.JSON(http.StatusInternalServerError, Response{
		Code:    500,
		Message: message,
	})
}

// Common error codes
const (
	ErrCodeSuccess          = 0
	ErrCodeInvalidParams    = 1001
	ErrCodeUnauthorized     = 1002
	ErrCodeForbidden        = 1003
	ErrCodeNotFound         = 1004
	ErrCodeDuplicate        = 1005
	ErrCodeInternalError    = 1006
	ErrCodeDatabaseError    = 1007
	ErrCodeTokenExpired     = 1008
	ErrCodeTokenInvalid     = 1009
	ErrCodeUserDisabled     = 1010
	ErrCodePasswordWrong    = 1011
	ErrCodeTaskRunning      = 2001
	ErrCodeNodeOffline      = 2002
	ErrCodeScanFailed       = 2003
	ErrCodeConfigError      = 3001
	ErrCodeThirdPartyError  = 3002
)

// Error messages
var ErrMessages = map[int]string{
	ErrCodeSuccess:          "操作成功",
	ErrCodeInvalidParams:    "参数错误",
	ErrCodeUnauthorized:     "未授权访问",
	ErrCodeForbidden:        "权限不足",
	ErrCodeNotFound:         "资源不存在",
	ErrCodeDuplicate:        "数据已存在",
	ErrCodeInternalError:    "服务器内部错误",
	ErrCodeDatabaseError:    "数据库操作失败",
	ErrCodeTokenExpired:     "Token已过期",
	ErrCodeTokenInvalid:     "Token无效",
	ErrCodeUserDisabled:     "用户已禁用",
	ErrCodePasswordWrong:    "密码错误",
	ErrCodeTaskRunning:      "任务正在运行",
	ErrCodeNodeOffline:      "节点离线",
	ErrCodeScanFailed:       "扫描失败",
}
