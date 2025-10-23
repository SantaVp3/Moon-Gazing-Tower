package database

import (
	"log"

	"github.com/reconmaster/backend/internal/models"
	"gorm.io/gorm"
)

// InitBuiltInSensitiveRules 初始化内置敏感信息规则
func InitBuiltInSensitiveRules(db *gorm.DB) error {
	// 检查是否已经初始化过
	var count int64
	db.Model(&models.SensitiveRule{}).Where("is_built_in = ?", true).Count(&count)
	if count > 0 {
		log.Println("Built-in sensitive rules already initialized, skipping...")
		return nil
	}

	log.Println("Initializing built-in sensitive rules...")

	// 预设规则列表
	builtInRules := []models.SensitiveRule{
		// ===== API 密钥类 =====
		{
			Name:        "AWS Access Key",
			Type:        models.SensitiveRuleTypeRegex,
			Pattern:     `(AKIA[0-9A-Z]{16})`,
			Description: "检测 AWS Access Key ID",
			Severity:    models.SensitiveRuleSeverityHigh,
			Category:    "API密钥",
			Example:     "AKIAIOSFODNN7EXAMPLE",
			IsEnabled:   true,
			IsBuiltIn:   true,
		},
		{
			Name:        "AWS Secret Key",
			Type:        models.SensitiveRuleTypeRegex,
			Pattern:     `aws.{0,20}?['\"][0-9a-zA-Z/+]{40}['\"]`,
			Description: "检测 AWS Secret Access Key",
			Severity:    models.SensitiveRuleSeverityHigh,
			Category:    "API密钥",
			Example:     "aws_secret_key: \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"",
			IsEnabled:   true,
			IsBuiltIn:   true,
		},
		{
			Name:        "阿里云 AccessKey",
			Type:        models.SensitiveRuleTypeRegex,
			Pattern:     `(LTAI[A-Za-z0-9]{12,20})`,
			Description: "检测阿里云 AccessKey ID",
			Severity:    models.SensitiveRuleSeverityHigh,
			Category:    "API密钥",
			Example:     "LTAI4FnKxBpXXXXXXXXX",
			IsEnabled:   true,
			IsBuiltIn:   true,
		},
		{
			Name:        "腾讯云 SecretId",
			Type:        models.SensitiveRuleTypeRegex,
			Pattern:     `(AKI[A-Za-z0-9]{32,48})`,
			Description: "检测腾讯云 SecretId",
			Severity:    models.SensitiveRuleSeverityHigh,
			Category:    "API密钥",
			Example:     "AKIDxxxxxxxxxxxxxxxxxxxxxx",
			IsEnabled:   true,
			IsBuiltIn:   true,
		},
		{
			Name:        "GitHub Token",
			Type:        models.SensitiveRuleTypeRegex,
			Pattern:     `gh[pousr]_[A-Za-z0-9]{36}`,
			Description: "检测 GitHub Personal Access Token",
			Severity:    models.SensitiveRuleSeverityHigh,
			Category:    "API密钥",
			Example:     "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			IsEnabled:   true,
			IsBuiltIn:   true,
		},
		{
			Name:        "Google API Key",
			Type:        models.SensitiveRuleTypeRegex,
			Pattern:     `AIza[0-9A-Za-z\-_]{35}`,
			Description: "检测 Google API Key",
			Severity:    models.SensitiveRuleSeverityHigh,
			Category:    "API密钥",
			Example:     "AIzaSyDxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			IsEnabled:   true,
			IsBuiltIn:   true,
		},

		// ===== 证书和密钥类 =====
		{
			Name:        "RSA 私钥",
			Type:        models.SensitiveRuleTypeRegex,
			Pattern:     `-----BEGIN RSA PRIVATE KEY-----`,
			Description: "检测 RSA 私钥文件",
			Severity:    models.SensitiveRuleSeverityHigh,
			Category:    "证书",
			Example:     "-----BEGIN RSA PRIVATE KEY-----",
			IsEnabled:   true,
			IsBuiltIn:   true,
		},
		{
			Name:        "SSH 私钥",
			Type:        models.SensitiveRuleTypeRegex,
			Pattern:     `-----BEGIN (?:OPENSSH|EC|DSA) PRIVATE KEY-----`,
			Description: "检测 SSH 私钥文件",
			Severity:    models.SensitiveRuleSeverityHigh,
			Category:    "证书",
			Example:     "-----BEGIN OPENSSH PRIVATE KEY-----",
			IsEnabled:   true,
			IsBuiltIn:   true,
		},
		{
			Name:        "PGP 私钥",
			Type:        models.SensitiveRuleTypeRegex,
			Pattern:     `-----BEGIN PGP PRIVATE KEY BLOCK-----`,
			Description: "检测 PGP 私钥",
			Severity:    models.SensitiveRuleSeverityHigh,
			Category:    "证书",
			Example:     "-----BEGIN PGP PRIVATE KEY BLOCK-----",
			IsEnabled:   true,
			IsBuiltIn:   true,
		},

		// ===== 数据库连接类 =====
		{
			Name:        "数据库连接字符串",
			Type:        models.SensitiveRuleTypeRegex,
			Pattern:     `(mysql|postgres|mongodb|redis)://[^\s'"]*:[^\s'"]*@[^\s'"]*`,
			Description: "检测数据库连接字符串（包含用户名密码）",
			Severity:    models.SensitiveRuleSeverityHigh,
			Category:    "数据库",
			Example:     "mysql://user:pass@localhost:3306/db",
			IsEnabled:   true,
			IsBuiltIn:   true,
		},
		{
			Name:        "JDBC 连接字符串",
			Type:        models.SensitiveRuleTypeRegex,
			Pattern:     `jdbc:[a-z]+://[^\s'"]+password=[^\s'";]+`,
			Description: "检测 JDBC 数据库连接字符串",
			Severity:    models.SensitiveRuleSeverityHigh,
			Category:    "数据库",
			Example:     "jdbc:mysql://host/db?user=root&password=secret",
			IsEnabled:   true,
			IsBuiltIn:   true,
		},

		// ===== JWT Token 类 =====
		{
			Name:        "JWT Token",
			Type:        models.SensitiveRuleTypeRegex,
			Pattern:     `eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`,
			Description: "检测 JWT Token",
			Severity:    models.SensitiveRuleSeverityMedium,
			Category:    "API密钥",
			Example:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
			IsEnabled:   true,
			IsBuiltIn:   true,
		},

		// ===== 个人信息类 =====
		{
			Name:        "身份证号",
			Type:        models.SensitiveRuleTypeRegex,
			Pattern:     `[1-9]\d{5}(18|19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]`,
			Description: "检测中国大陆身份证号码",
			Severity:    models.SensitiveRuleSeverityHigh,
			Category:    "个人信息",
			Example:     "110101199001011234",
			IsEnabled:   true,
			IsBuiltIn:   true,
		},
		{
			Name:        "手机号码",
			Type:        models.SensitiveRuleTypeRegex,
			Pattern:     `1[3-9]\d{9}`,
			Description: "检测中国大陆手机号码",
			Severity:    models.SensitiveRuleSeverityMedium,
			Category:    "个人信息",
			Example:     "13812345678",
			IsEnabled:   true,
			IsBuiltIn:   true,
		},
		{
			Name:        "邮箱地址",
			Type:        models.SensitiveRuleTypeRegex,
			Pattern:     `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`,
			Description: "检测邮箱地址",
			Severity:    models.SensitiveRuleSeverityLow,
			Category:    "个人信息",
			Example:     "user@example.com",
			IsEnabled:   false, // 默认禁用，避免误报
			IsBuiltIn:   true,
		},

		// ===== 密码类 =====
		{
			Name:        "明文密码（关键词）",
			Type:        models.SensitiveRuleTypeKeyword,
			Pattern:     "password,passwd,pwd,secret,token,api_key,apikey,access_token,auth_token",
			Description: "检测可能包含密码的关键词",
			Severity:    models.SensitiveRuleSeverityMedium,
			Category:    "密码",
			Example:     "password: 123456",
			IsEnabled:   false, // 默认禁用，避免误报
			IsBuiltIn:   true,
		},

		// ===== 配置文件类 =====
		{
			Name:        "Docker 配置泄露",
			Type:        models.SensitiveRuleTypeRegex,
			Pattern:     `"auths":\s*{[^}]*"auth":\s*"[A-Za-z0-9+/=]+"`,
			Description: "检测 Docker 配置文件中的认证信息",
			Severity:    models.SensitiveRuleSeverityHigh,
			Category:    "配置文件",
			Example:     `"auths": {"registry.example.com": {"auth": "dXNlcjpwYXNzd29yZA=="}}`,
			IsEnabled:   true,
			IsBuiltIn:   true,
		},

		// ===== 云服务类 =====
		{
			Name:        "Slack Webhook",
			Type:        models.SensitiveRuleTypeRegex,
			Pattern:     `https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}`,
			Description: "检测 Slack Webhook URL",
			Severity:    models.SensitiveRuleSeverityMedium,
			Category:    "API密钥",
			Example:     "hooks.slack.com/services/TXXXXXXXX/BXXXXXXXX/XXXXXXXXXXXXXXXXXXXXXXXX",
			IsEnabled:   true,
			IsBuiltIn:   true,
		},
		{
			Name:        "Telegram Bot Token",
			Type:        models.SensitiveRuleTypeRegex,
			Pattern:     `\d{8,10}:[A-Za-z0-9_-]{35}`,
			Description: "检测 Telegram Bot Token",
			Severity:    models.SensitiveRuleSeverityMedium,
			Category:    "API密钥",
			Example:     "123456789:ABCdefGHIjklMNOpqrsTUVwxyz-1234567890",
			IsEnabled:   true,
			IsBuiltIn:   true,
		},
	}

	// 批量创建规则
	for i := range builtInRules {
		if err := db.Create(&builtInRules[i]).Error; err != nil {
			log.Printf("Failed to create built-in rule '%s': %v", builtInRules[i].Name, err)
			continue
		}
	}

	log.Printf("Successfully initialized %d built-in sensitive rules", len(builtInRules))
	return nil
}
