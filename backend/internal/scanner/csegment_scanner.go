package scanner

import (
	"fmt"
	"net"
	"strings"

	"github.com/reconmaster/backend/internal/models"
)

// CSegmentScanner C段扫描器
type CSegmentScanner struct{}

// NewCSegmentScanner 创建C段扫描器
func NewCSegmentScanner() *CSegmentScanner {
	return &CSegmentScanner{}
}

// Scan 扫描C段IP
func (cs *CSegmentScanner) Scan(ctx *ScanContext) error {
	if !ctx.Task.Options.EnableCSegment {
		return nil
	}

	// 获取所有已解析的IP
	var ips []models.IP
	ctx.DB.Where("task_id = ?", ctx.Task.ID).Find(&ips)

	if len(ips) == 0 {
		ctx.Logger.Printf("No IPs found for C segment scanning")
		return nil
	}

	ctx.Logger.Printf("Starting C segment scanning for %d IPs", len(ips))

	// 用于去重
	existingIPs := make(map[string]bool)
	for _, ip := range ips {
		existingIPs[ip.IPAddress] = true
	}

	// 生成C段IP
	cSegmentIPs := make(map[string]bool)
	for _, ip := range ips {
		// 跳过CDN IP
		if ip.CDN {
			ctx.Logger.Printf("Skipping CDN IP for C segment: %s", ip.IPAddress)
			continue
		}

		// 生成该IP的C段
		segment := cs.generateCSegment(ip.IPAddress)
		for _, segmentIP := range segment {
			// 跳过已存在的IP
			if !existingIPs[segmentIP] && !cSegmentIPs[segmentIP] {
				cSegmentIPs[segmentIP] = true
			}
		}
	}

	ctx.Logger.Printf("Generated %d C segment IPs", len(cSegmentIPs))

	// 保存C段IP到数据库
	count := 0
	for segmentIP := range cSegmentIPs {
		ipModel := &models.IP{
			TaskID:    ctx.Task.ID,
			IPAddress: segmentIP,
			Source:    "c_segment",
		}

		// 使用FirstOrCreate避免重复
		if err := ctx.DB.Where("task_id = ? AND ip_address = ?", ctx.Task.ID, segmentIP).
			FirstOrCreate(ipModel).Error; err != nil {
			ctx.Logger.Printf("Failed to save C segment IP %s: %v", segmentIP, err)
			continue
		}
		count++
	}

	ctx.Logger.Printf("C segment scanning completed, added %d new IPs", count)
	return nil
}

// generateCSegment 生成C段IP列表
func (cs *CSegmentScanner) generateCSegment(ipAddr string) []string {
	var result []string

	// 解析IP地址
	ip := net.ParseIP(ipAddr)
	if ip == nil {
		return result
	}

	// 只处理IPv4
	ip = ip.To4()
	if ip == nil {
		return result
	}

	// 提取前三段
	parts := strings.Split(ipAddr, ".")
	if len(parts) != 4 {
		return result
	}

	// 生成C段：xxx.xxx.xxx.1-254
	prefix := fmt.Sprintf("%s.%s.%s", parts[0], parts[1], parts[2])
	for i := 1; i <= 254; i++ {
		segmentIP := fmt.Sprintf("%s.%d", prefix, i)
		// 跳过原始IP
		if segmentIP != ipAddr {
			result = append(result, segmentIP)
		}
	}

	return result
}

