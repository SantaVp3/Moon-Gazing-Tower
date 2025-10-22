package database

import (
"log"

"github.com/reconmaster/backend/internal/models"
)

// InitDefaultFingerprints 初始化默认指纹库
// 注意：这个函数已被弃用，现在使用 services.FingerprintLoader.LoadDefaultFingerprints()
// 从 finger.yaml 文件加载指纹数据
func InitDefaultFingerprints() error {
	// 检查是否已有指纹数据
	var count int64
	DB.Model(&models.Fingerprint{}).Count(&count)
	if count > 0 {
		log.Println("Fingerprint library already initialized")
		return nil
	}

	log.Println("Fingerprint library is empty. Please use FingerprintLoader to load from finger.yaml")
	return nil
}
