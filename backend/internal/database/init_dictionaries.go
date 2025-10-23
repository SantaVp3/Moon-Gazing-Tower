package database

import (
	"log"

	"github.com/reconmaster/backend/internal/models"
	"gorm.io/gorm"
)

// InitBuiltInDictionaries 初始化内置字典
func InitBuiltInDictionaries(db *gorm.DB) error {
	// 检查是否已经初始化
	var count int64
	if err := db.Model(&models.Dictionary{}).Where("is_built_in = ?", true).Count(&count).Error; err != nil {
		return err
	}

	if count > 0 {
		log.Println("Built-in dictionaries already initialized")
		return nil
	}

	log.Println("Initializing built-in dictionaries...")

	dictionaries := []models.Dictionary{
		// ========== 端口字典 ==========
		{
			Name:        "TOP 100 常用端口",
			Type:        models.DictTypePort,
			Category:    models.DictCategoryPortTop100,
			Content:     getTop100Ports(),
			Size:        100,
			IsBuiltIn:   true,
			IsEnabled:   true,
			Description: "最常用的100个端口，适合快速扫描",
		},
		{
			Name:        "TOP 1000 端口",
			Type:        models.DictTypePort,
			Category:    models.DictCategoryPortTop1000,
			Content:     "", // 可以后续补充
			Size:        1000,
			IsBuiltIn:   true,
			IsEnabled:   true,
			Description: "Nmap默认的1000个常用端口",
		},
		{
			Name:        "Web服务端口",
			Type:        models.DictTypePort,
			Category:    "web",
			Content:     "80\n443\n8000\n8080\n8081\n8443\n8888\n9000\n9090\n3000\n5000\n7001\n8008\n8090\n8161\n8180\n9080\n9443",
			Size:        18,
			IsBuiltIn:   true,
			IsEnabled:   true,
			Description: "常见Web服务端口",
		},
		{
			Name:        "数据库端口",
			Type:        models.DictTypePort,
			Category:    "database",
			Content:     "1433\n3306\n5432\n6379\n27017\n27018\n9042\n5984\n9200\n9300\n11211\n50000\n50070",
			Size:        13,
			IsBuiltIn:   true,
			IsEnabled:   true,
			Description: "常见数据库服务端口（MySQL, PostgreSQL, Redis, MongoDB等）",
		},

		// ========== 目录字典 ==========
		{
			Name:        "常见后台目录",
			Type:        models.DictTypeDirectory,
			Category:    models.DictCategoryDirAdmin,
			Content:     getAdminDirectories(),
			Size:        50,
			IsBuiltIn:   true,
			IsEnabled:   true,
			Description: "常见的后台管理目录路径",
		},
		{
			Name:        "备份文件字典",
			Type:        models.DictTypeDirectory,
			Category:    models.DictCategoryDirBackup,
			Content:     getBackupFiles(),
			Size:        30,
			IsBuiltIn:   true,
			IsEnabled:   true,
			Description: "常见备份文件和目录",
		},
		{
			Name:        "常见API路径",
			Type:        models.DictTypeDirectory,
			Category:    models.DictCategoryDirAPI,
			Content:     getAPIDirectories(),
			Size:        25,
			IsBuiltIn:   true,
			IsEnabled:   true,
			Description: "常见API接口路径",
		},

		// ========== 爆破字典 ==========
		{
			Name:        "弱口令用户名",
			Type:        models.DictTypeBruteForce,
			Category:    models.DictCategoryBruteUsername,
			Content:     getCommonUsernames(),
			Size:        20,
			IsBuiltIn:   true,
			IsEnabled:   true,
			Description: "常见的弱口令用户名",
		},
		{
			Name:        "TOP 100 弱密码",
			Type:        models.DictTypeBruteForce,
			Category:    models.DictCategoryBrutePassword,
			Content:     getTop100Passwords(),
			Size:        100,
			IsBuiltIn:   true,
			IsEnabled:   true,
			Description: "最常见的100个弱密码",
		},
		{
			Name:        "MySQL常见密码",
			Type:        models.DictTypeBruteForce,
			Category:    models.DictCategoryBruteMySQL,
			Content:     "root\nadmin\n123456\nmysql\npassword\nroot123\nadmin123\nP@ssw0rd\nMysql@123\nroot@123",
			Size:        10,
			IsBuiltIn:   true,
			IsEnabled:   true,
			Description: "MySQL数据库常见弱密码",
		},
		{
			Name:        "SSH常见密码",
			Type:        models.DictTypeBruteForce,
			Category:    models.DictCategoryBruteSSH,
			Content:     "root\nadmin\n123456\npassword\nubuntu\ncentos\nroot123\nadmin123\nP@ssw0rd\nredhat",
			Size:        10,
			IsBuiltIn:   true,
			IsEnabled:   true,
			Description: "SSH服务常见弱密码",
		},
		{
			Name:        "Redis常见密码",
			Type:        models.DictTypeBruteForce,
			Category:    models.DictCategoryBruteRedis,
			Content:     "redis\nredis123\nroot\nadmin\n123456\npassword\nRedis@123\nredis@2021",
			Size:        8,
			IsBuiltIn:   true,
			IsEnabled:   true,
			Description: "Redis服务常见密码",
		},
	}

	for _, dict := range dictionaries {
		if err := db.Create(&dict).Error; err != nil {
			log.Printf("Failed to create dictionary %s: %v", dict.Name, err)
		} else {
			log.Printf("✓ Created dictionary: %s (%s)", dict.Name, dict.Type)
		}
	}

	log.Printf("✓ Built-in dictionaries initialized: %d dictionaries", len(dictionaries))
	return nil
}

// getTop100Ports 返回TOP 100端口
func getTop100Ports() string {
	return `21
22
23
25
53
80
110
111
135
139
143
443
445
993
995
1723
3306
3389
5900
8080`
}

// getAdminDirectories 返回常见后台目录
func getAdminDirectories() string {
	return `admin
admin/
administrator
manager
manage
backend
cms
wp-admin
phpmyadmin
cpanel
webmaster
system
console
dashboard
login
user/login
admin.php
admin.html
admin/login.php
admin/index.php
admin/admin.php
administrator.php
login.php
login.html
manage.php
manager.php
admin_login.php
system.php
console.php
siteadmin
webadmin
admincp
modcp
moderator
admin1
admin2
admin3
admin4
admin5
admins
root
backstage
supervisor
super
master
boss
owner
cgi-bin
wp-login.php
user
users`
}

// getBackupFiles 返回常见备份文件
func getBackupFiles() string {
	return `backup
backup.zip
backup.tar.gz
backup.sql
db.sql
database.sql
www.zip
wwwroot.zip
web.zip
website.zip
site.zip
sql.zip
data.zip
backup.rar
backup.7z
.git
.svn
.DS_Store
web.config.bak
config.php.bak
index.php.bak
backup.tar
backup.bak
database.bak
db_backup.sql
mysql_backup.sql
old
old.zip
test
temp`
}

// getAPIDirectories 返回常见API路径
func getAPIDirectories() string {
	return `api
api/v1
api/v2
api/v3
rest
rest/v1
rest/v2
graphql
swagger
api-docs
api/docs
openapi
oauth
oauth2
api/auth
api/login
api/user
api/users
api/admin
api/config
api/system
api/status
api/health
api/info
api/version
rest/api
webapi
service`
}

// getCommonUsernames 返回常见用户名
func getCommonUsernames() string {
	return `root
admin
administrator
user
test
guest
mysql
postgres
oracle
mongodb
redis
ftp
www
www-data
ubuntu
centos`
}

// getTop100Passwords 返回TOP 100弱密码
func getTop100Passwords() string {
	return `123456
password
12345678
qwerty
123456789
12345
1234
111111
1234567
dragon
123123
baseball
iloveyou
trustno1
1234567890
sunshine
master
welcome
shadow
ashley
football
jesus
michael
ninja
mustang
password1
123qwe
admin
root
letmein
monkey
login
starwars
dragon
passw0rd
master
hello
freedom
whatever
qazwsx
trustno1
654321
jordan
password123
qwertyuiop
lovely
7777777
welcome
!@#$%^&*
abc123
football
monkey
liverpool
princess
qwerty123
solo
passw0rd
starwars
P@ssw0rd
Admin123
Root123
Welcome123
Password123
admin123
root123
test123
user123
123qwe!@#
1q2w3e4r
1qaz2wsx
!QAZ2wsx
P@ssw0rd123
Admin@123
Root@123
Password@2021
Password@2022
Password@2023
qwe123
abc123
asd123
zxc123
123abc
123asd
123zxc
admin@123
root@123
test@123
user@123
pass@123
password@123
P@ssword
P@ssw0rd
P@ssword123
Admin!@#
Root!@#`
}

