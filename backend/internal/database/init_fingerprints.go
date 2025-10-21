package database

import (
	"log"

	"github.com/reconmaster/backend/internal/models"
)

// InitDefaultFingerprints 初始化默认指纹库
func InitDefaultFingerprints() error {
	// 检查是否已有指纹数据
	var count int64
	DB.Model(&models.Fingerprint{}).Count(&count)
	if count > 0 {
		log.Println("Fingerprint library already initialized")
		return nil
	}

	log.Println("Initializing default fingerprint library...")

	fingerprints := []models.Fingerprint{
		// CMS 系统
		{
			Name:        "WordPress",
			Category:    "CMS",
			RuleType:    "body",
			RuleContent: "wp-content|wp-includes",
			Confidence:  95,
			Description: "WordPress内容管理系统",
			IsEnabled:   true,
		},
		{
			Name:        "Drupal",
			Category:    "CMS",
			RuleType:    "body",
			RuleContent: "Drupal|drupal",
			Confidence:  90,
			Description: "Drupal内容管理系统",
			IsEnabled:   true,
		},
		{
			Name:        "Joomla",
			Category:    "CMS",
			RuleType:    "body",
			RuleContent: "/components/com_|/media/jui/",
			Confidence:  90,
			Description: "Joomla内容管理系统",
			IsEnabled:   true,
		},
		{
			Name:        "Discuz",
			Category:    "论坛",
			RuleType:    "body",
			RuleContent: "Powered by Discuz!|discuz",
			Confidence:  95,
			Description: "Discuz论坛系统",
			IsEnabled:   true,
		},
		{
			Name:        "DedeCMS",
			Category:    "CMS",
			RuleType:    "body",
			RuleContent: "DedeCMS|织梦内容管理系统",
			Confidence:  95,
			Description: "织梦内容管理系统",
			IsEnabled:   true,
		},

		// Web 服务器
		{
			Name:        "Nginx",
			Category:    "Web服务器",
			RuleType:    "header",
			RuleContent: "Server: nginx",
			Confidence:  100,
			Description: "Nginx Web服务器",
			IsEnabled:   true,
		},
		{
			Name:        "Apache",
			Category:    "Web服务器",
			RuleType:    "header",
			RuleContent: "Server: Apache",
			Confidence:  100,
			Description: "Apache Web服务器",
			IsEnabled:   true,
		},
		{
			Name:        "IIS",
			Category:    "Web服务器",
			RuleType:    "header",
			RuleContent: "Server: Microsoft-IIS",
			Confidence:  100,
			Description: "Microsoft IIS服务器",
			IsEnabled:   true,
		},
		{
			Name:        "Tomcat",
			Category:    "应用服务器",
			RuleType:    "header",
			RuleContent: "Server: Apache-Coyote",
			Confidence:  90,
			Description: "Apache Tomcat应用服务器",
			IsEnabled:   true,
		},

		// 开发框架
		{
			Name:        "Laravel",
			Category:    "PHP框架",
			RuleType:    "header",
			RuleContent: "X-Powered-By: PHP|laravel_session",
			Confidence:  85,
			Description: "Laravel PHP框架",
			IsEnabled:   true,
		},
		{
			Name:        "ThinkPHP",
			Category:    "PHP框架",
			RuleType:    "body",
			RuleContent: "thinkphp|ThinkPHP",
			Confidence:  90,
			Description: "ThinkPHP框架",
			IsEnabled:   true,
		},
		{
			Name:        "Spring Boot",
			Category:    "Java框架",
			RuleType:    "header",
			RuleContent: "X-Application-Context",
			Confidence:  85,
			Description: "Spring Boot框架",
			IsEnabled:   true,
		},
		{
			Name:        "Django",
			Category:    "Python框架",
			RuleType:    "header",
			RuleContent: "csrftoken|sessionid",
			Confidence:  80,
			Description: "Django Python框架",
			IsEnabled:   true,
		},
		{
			Name:        "Flask",
			Category:    "Python框架",
			RuleType:    "header",
			RuleContent: "session=\\.",
			Confidence:  75,
			Description: "Flask Python框架",
			IsEnabled:   true,
		},
		{
			Name:        "React",
			Category:    "前端框架",
			RuleType:    "body",
			RuleContent: "react|__REACT|data-reactroot",
			Confidence:  85,
			Description: "React前端框架",
			IsEnabled:   true,
		},
		{
			Name:        "Vue.js",
			Category:    "前端框架",
			RuleType:    "body",
			RuleContent: "vue\\.js|data-v-",
			Confidence:  85,
			Description: "Vue.js前端框架",
			IsEnabled:   true,
		},
		{
			Name:        "Angular",
			Category:    "前端框架",
			RuleType:    "body",
			RuleContent: "ng-|angular",
			Confidence:  85,
			Description: "Angular前端框架",
			IsEnabled:   true,
		},
		{
			Name:        "jQuery",
			Category:    "JavaScript库",
			RuleType:    "body",
			RuleContent: "jquery",
			Confidence:  95,
			Description: "jQuery JavaScript库",
			IsEnabled:   true,
		},
		{
			Name:        "Bootstrap",
			Category:    "CSS框架",
			RuleType:    "body",
			RuleContent: "bootstrap",
			Confidence:  90,
			Description: "Bootstrap CSS框架",
			IsEnabled:   true,
		},

		// 电商系统
		{
			Name:        "Magento",
			Category:    "电商",
			RuleType:    "body",
			RuleContent: "Mage\\.Cookies|/skin/frontend/",
			Confidence:  90,
			Description: "Magento电商系统",
			IsEnabled:   true,
		},
		{
			Name:        "Shopify",
			Category:    "电商",
			RuleType:    "body",
			RuleContent: "cdn\\.shopify\\.com|shopify",
			Confidence:  95,
			Description: "Shopify电商平台",
			IsEnabled:   true,
		},
		{
			Name:        "ECShop",
			Category:    "电商",
			RuleType:    "body",
			RuleContent: "Powered by ECShop|ecshop",
			Confidence:  95,
			Description: "ECShop电商系统",
			IsEnabled:   true,
		},

		// 中间件
		{
			Name:        "Redis",
			Category:    "缓存",
			RuleType:    "header",
			RuleContent: "X-Powered-By: Redis",
			Confidence:  100,
			Description: "Redis缓存服务",
			IsEnabled:   true,
		},
		{
			Name:        "Elasticsearch",
			Category:    "搜索引擎",
			RuleType:    "body",
			RuleContent: "\"cluster_name\"|\"tagline\" : \"You Know",
			Confidence:  95,
			Description: "Elasticsearch搜索引擎",
			IsEnabled:   true,
		},

		// WAF
		{
			Name:        "Cloudflare",
			Category:    "WAF/CDN",
			RuleType:    "header",
			RuleContent: "Server: cloudflare",
			Confidence:  100,
			Description: "Cloudflare CDN/WAF",
			IsEnabled:   true,
		},
		{
			Name:        "阿里云WAF",
			Category:    "WAF/CDN",
			RuleType:    "header",
			RuleContent: "X-Tengine-Error|Ali-CDN-Via",
			Confidence:  95,
			Description: "阿里云WAF",
			IsEnabled:   true,
		},
	}

	// 批量插入
	if err := DB.Create(&fingerprints).Error; err != nil {
		log.Printf("Failed to initialize fingerprints: %v", err)
		return err
	}

	log.Printf("Successfully initialized %d default fingerprints", len(fingerprints))
	return nil
}

