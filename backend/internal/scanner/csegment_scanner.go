package scanner

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/reconmaster/backend/internal/models"
)

// CSegmentScanner C段扫描器
type CSegmentScanner struct{}

// NewCSegmentScanner 创建C段扫描器
func NewCSegmentScanner() *CSegmentScanner {
	return &CSegmentScanner{}
}

// Scan 扫描C段IP（带存活性检测）
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

	ctx.Logger.Printf("Generated %d C segment IPs, checking liveness...", len(cSegmentIPs))

	// 存活性检测并保存（使用快速端口探测）
	count := 0
	aliveCount := 0

	// 转换为切片用于并发处理
	ipList := make([]string, 0, len(cSegmentIPs))
	for ip := range cSegmentIPs {
		ipList = append(ipList, ip)
	}

	// 并发探测存活IP
	aliveChan := make(chan string, len(ipList))
	semaphore := make(chan struct{}, 50) // 并发50个

	for _, segmentIP := range ipList {
		semaphore <- struct{}{}
		go func(ip string) {
			defer func() { <-semaphore }()

			// 快速检测：尝试连接常用端口
			if cs.isAlive(ip) {
				aliveChan <- ip
			}
		}(segmentIP)
	}

	// 等待所有探测完成
	go func() {
		for i := 0; i < 50; i++ {
			semaphore <- struct{}{}
		}
		close(aliveChan)
	}()

	// 保存存活的IP
	for aliveIP := range aliveChan {
		ipModel := &models.IP{
			TaskID:    ctx.Task.ID,
			IPAddress: aliveIP,
			Source:    "c_segment",
		}

		// 使用FirstOrCreate避免重复
		if err := ctx.DB.Where("task_id = ? AND ip_address = ?", ctx.Task.ID, aliveIP).
			FirstOrCreate(ipModel).Error; err != nil {
			ctx.Logger.Printf("Failed to save C segment IP %s: %v", aliveIP, err)
			continue
		}
		count++
		aliveCount++

		if aliveCount%10 == 0 {
			ctx.Logger.Printf("C segment: found %d alive IPs so far...", aliveCount)
		}
	}

	ctx.Logger.Printf("C segment scanning completed: scanned %d IPs, found %d alive, saved %d new IPs",
		len(ipList), aliveCount, count)
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

// isAlive 快速检测IP是否存活（探测常用端口）
func (cs *CSegmentScanner) isAlive(ip string) bool {
	// 常用端口列表（快速探测）
	commonPorts := []int{80, 443, 22, 3389, 8080, 8443}

	timeout := 500 // 500ms超时

	for _, port := range commonPorts {
		address := fmt.Sprintf("%s:%d", ip, port)
		conn, err := net.DialTimeout("tcp", address, time.Duration(timeout)*time.Millisecond)
		if err == nil {
			conn.Close()
			return true // 有任一端口开放，认为存活
		}
	}

	return false
}
