package api

import (
	"strconv"

	"moongazing/service"
	"moongazing/utils"

	"github.com/gin-gonic/gin"
)

type UserHandler struct {
	userService *service.UserService
}

func NewUserHandler() *UserHandler {
	return &UserHandler{
		userService: service.NewUserService(),
	}
}

// ListUsers lists all users with pagination
// GET /api/users
func (h *UserHandler) ListUsers(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "10"))
	keyword := c.Query("keyword")
	
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 10
	}
	
	users, total, err := h.userService.ListUsers(page, pageSize, keyword)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	
	// Transform users to safe response
	var userList []gin.H
	for _, user := range users {
		userList = append(userList, gin.H{
			"id":         user.ID.Hex(),
			"username":   user.Username,
			"email":      user.Email,
			"phone":      user.Phone,
			"role":       user.Role,
			"status":     user.Status,
			"last_login": user.LastLogin,
			"created_at": user.CreatedAt,
		})
	}
	
	utils.SuccessWithPagination(c, userList, total, page, pageSize)
}

// GetUser gets a user by ID
// GET /api/users/:id
func (h *UserHandler) GetUser(c *gin.Context) {
	userID := c.Param("id")
	
	user, err := h.userService.GetUserByID(userID)
	if err != nil {
		utils.NotFound(c, err.Error())
		return
	}
	
	utils.Success(c, gin.H{
		"id":         user.ID.Hex(),
		"username":   user.Username,
		"email":      user.Email,
		"phone":      user.Phone,
		"role":       user.Role,
		"status":     user.Status,
		"last_login": user.LastLogin,
		"created_at": user.CreatedAt,
	})
}

// CreateUser creates a new user (admin only)
// POST /api/users
func (h *UserHandler) CreateUser(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required,min=3,max=32"`
		Password string `json:"password" binding:"required,min=6,max=32"`
		Email    string `json:"email" binding:"required,email"`
		Role     string `json:"role" binding:"oneof=admin user viewer"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	
	user, err := h.userService.Register(req.Username, req.Password, req.Email)
	if err != nil {
		utils.Error(c, utils.ErrCodeDuplicate, err.Error())
		return
	}
	
	// Update role if specified
	if req.Role != "" && req.Role != "user" {
		h.userService.UpdateUser(user.ID.Hex(), map[string]interface{}{"role": req.Role})
	}
	
	utils.SuccessWithMessage(c, "创建成功", gin.H{
		"id":       user.ID.Hex(),
		"username": user.Username,
		"email":    user.Email,
	})
}

// UpdateUser updates a user
// PUT /api/users/:id
func (h *UserHandler) UpdateUser(c *gin.Context) {
	userID := c.Param("id")
	
	var req struct {
		Email  string `json:"email"`
		Phone  string `json:"phone"`
		Role   string `json:"role"`
		Status *int   `json:"status"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误")
		return
	}
	
	updates := make(map[string]interface{})
	if req.Email != "" {
		updates["email"] = req.Email
	}
	if req.Phone != "" {
		updates["phone"] = req.Phone
	}
	if req.Role != "" {
		updates["role"] = req.Role
	}
	if req.Status != nil {
		updates["status"] = *req.Status
	}
	
	if err := h.userService.UpdateUser(userID, updates); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}
	
	utils.SuccessWithMessage(c, "更新成功", nil)
}

// DeleteUser deletes a user
// DELETE /api/users/:id
func (h *UserHandler) DeleteUser(c *gin.Context) {
	userID := c.Param("id")
	currentUserID, _ := c.Get("user_id")
	
	// Prevent self-deletion
	if userID == currentUserID.(string) {
		utils.BadRequest(c, "不能删除自己")
		return
	}
	
	if err := h.userService.DeleteUser(userID); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}
	
	utils.SuccessWithMessage(c, "删除成功", nil)
}

// SetUserStatus enables or disables a user
// PUT /api/users/:id/status
func (h *UserHandler) SetUserStatus(c *gin.Context) {
	userID := c.Param("id")
	
	var req struct {
		Status int `json:"status" binding:"oneof=0 1"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误")
		return
	}
	
	if err := h.userService.SetUserStatus(userID, req.Status); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}
	
	utils.SuccessWithMessage(c, "状态更新成功", nil)
}

// ResetPassword resets user password (admin only)
// PUT /api/users/:id/password
func (h *UserHandler) ResetPassword(c *gin.Context) {
	userID := c.Param("id")
	
	var req struct {
		Password string `json:"password" binding:"required,min=6,max=32"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误")
		return
	}
	
	hashedPassword, _ := utils.HashPassword(req.Password)
	if err := h.userService.UpdateUser(userID, map[string]interface{}{
		"password": hashedPassword,
	}); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}
	
	utils.SuccessWithMessage(c, "密码重置成功", nil)
}
