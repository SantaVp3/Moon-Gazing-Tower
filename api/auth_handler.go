package api

import (
	"moongazing/service"
	"moongazing/utils"

	"github.com/gin-gonic/gin"
)

type AuthHandler struct {
	userService *service.UserService
}

func NewAuthHandler() *AuthHandler {
	return &AuthHandler{
		userService: service.NewUserService(),
	}
}

// Register handles user registration
// POST /api/auth/register
func (h *AuthHandler) Register(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required,min=3,max=32"`
		Password string `json:"password" binding:"required,min=6,max=32"`
		Email    string `json:"email" binding:"required,email"`
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
	
	utils.SuccessWithMessage(c, "注册成功", gin.H{
		"id":       user.ID.Hex(),
		"username": user.Username,
		"email":    user.Email,
	})
}

// Login handles user login
// POST /api/auth/login
func (h *AuthHandler) Login(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误")
		return
	}
	
	token, user, err := h.userService.Login(req.Username, req.Password)
	if err != nil {
		utils.Error(c, utils.ErrCodePasswordWrong, err.Error())
		return
	}
	
	utils.Success(c, gin.H{
		"token": token,
		"user": gin.H{
			"id":       user.ID.Hex(),
			"username": user.Username,
			"email":    user.Email,
			"role":     user.Role,
			"avatar":   user.Avatar,
		},
	})
}

// Logout handles user logout
// POST /api/auth/logout
func (h *AuthHandler) Logout(c *gin.Context) {
	// In a more complete implementation, you might want to
	// blacklist the token in Redis
	utils.SuccessWithMessage(c, "登出成功", nil)
}

// GetProfile gets current user profile
// GET /api/auth/profile
func (h *AuthHandler) GetProfile(c *gin.Context) {
	userID, _ := c.Get("user_id")
	
	user, err := h.userService.GetUserByID(userID.(string))
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
		"avatar":     user.Avatar,
		"last_login": user.LastLogin,
		"created_at": user.CreatedAt,
	})
}

// UpdateProfile updates current user profile
// PUT /api/auth/profile
func (h *AuthHandler) UpdateProfile(c *gin.Context) {
	userID, _ := c.Get("user_id")
	
	var req struct {
		Email  string `json:"email"`
		Phone  string `json:"phone"`
		Avatar string `json:"avatar"`
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
	if req.Avatar != "" {
		updates["avatar"] = req.Avatar
	}
	
	if err := h.userService.UpdateUser(userID.(string), updates); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}
	
	utils.SuccessWithMessage(c, "更新成功", nil)
}

// ChangePassword changes current user password
// PUT /api/auth/password
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	userID, _ := c.Get("user_id")
	
	var req struct {
		OldPassword string `json:"old_password" binding:"required"`
		NewPassword string `json:"new_password" binding:"required,min=6,max=32"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误")
		return
	}
	
	if err := h.userService.ChangePassword(userID.(string), req.OldPassword, req.NewPassword); err != nil {
		utils.Error(c, utils.ErrCodePasswordWrong, err.Error())
		return
	}
	
	utils.SuccessWithMessage(c, "密码修改成功", nil)
}

// RefreshToken refreshes JWT token
// POST /api/auth/refresh
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req struct {
		Token string `json:"token" binding:"required"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误")
		return
	}
	
	newToken, err := utils.RefreshToken(req.Token)
	if err != nil {
		utils.Error(c, utils.ErrCodeTokenInvalid, "Token无效或已过期")
		return
	}
	
	utils.Success(c, gin.H{
		"token": newToken,
	})
}
