package scanner

import (
	"context"
	"log"
	"net"
	"strings"

	"github.com/reconmaster/backend/internal/models"
	"gorm.io/gorm"
)

// ScanContext 扫描上下文
type ScanContext struct {
	Task         *models.Task
	DB           *gorm.DB
	Logger       *log.Logger
	Ctx          context.Context // 用于取消任务
	ProgressChan chan *ScanProgress // WebSocket 进度推送通道
}

// Engine 扫描引擎
type Engine struct {
	domainScanner      *DomainScanner
	portScanner        *PortScanner
	cSegmentScanner    *CSegmentScanner
	serviceScanner     *ServiceScanner
	siteScanner        *SiteScanner
	hostCollision      *HostCollisionScanner
	osDetector         *OSDetector
	customScriptRunner *CustomScriptRunner
	passiveScanner     *PassiveScanner
	takeoverScanner    *SubdomainTakeoverScanner
	assetMapper        *AssetMapper
	smartPoCScanner    *SmartPoCScanner // 智能PoC扫描器(替代Nuclei/XPOC/Afrog)
}

// NewEngine 创建扫描引擎
func NewEngine() *Engine {
	return &Engine{
		domainScanner:      NewDomainScanner(),
		portScanner:        NewPortScanner(),
		cSegmentScanner:    NewCSegmentScanner(),
		serviceScanner:     NewServiceScanner(),
		siteScanner:        NewSiteScanner(),
		hostCollision:      NewHostCollisionScanner(),
		osDetector:         NewOSDetector(),
		customScriptRunner: NewCustomScriptRunner(),
		passiveScanner:     NewPassiveScanner(),
		takeoverScanner:    NewSubdomainTakeoverScanner(),
		assetMapper:        NewAssetMapper(),
		smartPoCScanner:    NewSmartPoCScanner(), // 智能PoC扫描器
	}
}

// DiscoverDomains 域名发现
func (e *Engine) DiscoverDomains(ctx *ScanContext) error {
	return e.domainScanner.Scan(ctx)
}

// ResolveIPs IP解析（已在域名扫描中完成，保留此方法以保持兼容性）
func (e *Engine) ResolveIPs(ctx *ScanContext) error {
	// IP解析已经在域名扫描过程中自动完成
	// 这里处理直接输入的IP或CIDR格式

	// 获取目标列表
	targets := strings.Split(ctx.Task.Target, ",")

	for _, target := range targets {
		target = strings.TrimSpace(target)

		// 检查是否是CIDR格式
		if strings.Contains(target, "/") {
			ctx.Logger.Printf("Parsing CIDR target: %s", target)
			ips, err := e.parseCIDR(target)
			if err != nil {
				ctx.Logger.Printf("Failed to parse CIDR %s: %v", target, err)
				continue
			}

			// 保存所有CIDR中的IP
			for _, ip := range ips {
				ipModel := &models.IP{
					TaskID:    ctx.Task.ID,
					IPAddress: ip,
					Source:    "cidr",
				}
				ctx.DB.Where("task_id = ? AND ip_address = ?", ctx.Task.ID, ip).FirstOrCreate(ipModel)
			}
			ctx.Logger.Printf("Parsed %d IPs from CIDR %s", len(ips), target)
		} else if net.ParseIP(target) != nil {
			// 单个IP地址
			ctx.Logger.Printf("Parsing single IP: %s", target)
			ipModel := &models.IP{
				TaskID:    ctx.Task.ID,
				IPAddress: target,
				Source:    "input",
			}
			ctx.DB.Where("task_id = ? AND ip_address = ?", ctx.Task.ID, target).FirstOrCreate(ipModel)
		}
	}

	ctx.Logger.Printf("IP resolution completed")
	return nil
}

// parseCIDR 解析CIDR格式的IP段
func (e *Engine) parseCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	// 移除网络地址和广播地址（CIDR的第一个和最后一个IP）
	if len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}

	return ips, nil
}

// inc 递增IP地址
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// ScanCSegment C段扫描
func (e *Engine) ScanCSegment(ctx *ScanContext) error {
	return e.cSegmentScanner.Scan(ctx)
}

// ScanPorts 端口扫描
func (e *Engine) ScanPorts(ctx *ScanContext) error {
	return e.portScanner.Scan(ctx)
}

// DetectServices 服务识别
func (e *Engine) DetectServices(ctx *ScanContext) error {
	return e.serviceScanner.Detect(ctx)
}

// DetectSites 站点识别
func (e *Engine) DetectSites(ctx *ScanContext) error {
	return e.siteScanner.Detect(ctx)
}

// TakeScreenshots 站点截图
func (e *Engine) TakeScreenshots(ctx *ScanContext) error {
	return e.siteScanner.TakeScreenshots(ctx)
}

// CheckFileLeaks 文件泄露检测
func (e *Engine) CheckFileLeaks(ctx *ScanContext) error {
	return e.siteScanner.CheckFileLeaks(ctx)
}

// RunPoCScanning 运行智能PoC扫描 - 基于指纹匹配(替代Nuclei/XPOC/Afrog)
func (e *Engine) RunPoCScanning(ctx *ScanContext) error {
	ctx.Logger.Printf("Starting smart PoC scanning with fingerprint matching...")
	return e.smartPoCScanner.ScanWithFingerprints(ctx)
}

// CheckHostCollision 检测Host碰撞
func (e *Engine) CheckHostCollision(ctx *ScanContext) error {
	return e.hostCollision.Scan(ctx)
}

// DetectOS 检测操作系统
func (e *Engine) DetectOS(ctx *ScanContext) error {
	if !ctx.Task.Options.EnableOSDetect {
		return nil
	}

	var ips []models.IP
	ctx.DB.Where("task_id = ? AND os IS NULL OR os = ''", ctx.Task.ID).Find(&ips)

	ctx.Logger.Printf("Detecting OS for %d IPs", len(ips))

	for _, ip := range ips {
		// 获取该IP的开放端口
		var ports []models.Port
		ctx.DB.Where("task_id = ? AND ip_address = ?", ctx.Task.ID, ip.IPAddress).Find(&ports)

		if len(ports) == 0 {
			continue
		}

		openPorts := make([]int, len(ports))
		for i, p := range ports {
			openPorts[i] = p.Port
		}

		// 检测OS
		os := e.osDetector.Detect(ip.IPAddress, openPorts)
		if os != "" && os != "Unknown" {
			ctx.DB.Model(&ip).Update("os", os)
			ctx.Logger.Printf("OS detected: %s -> %s", ip.IPAddress, os)
		}
	}

	return nil
}

// RunCustomScript 运行自定义脚本
func (e *Engine) RunCustomScript(ctx *ScanContext, scriptPath string) error {
	// 获取所有站点作为目标
	var sites []models.Site
	ctx.DB.Where("task_id = ?", ctx.Task.ID).Find(&sites)

	if len(sites) == 0 {
		ctx.Logger.Printf("No sites found for custom script")
		return nil
	}

	ctx.Logger.Printf("Running custom script: %s for %d sites", scriptPath, len(sites))

	// 提取目标URLs
	var targets []string
	for _, site := range sites {
		targets = append(targets, site.URL)
	}

	// 执行脚本
	vulns, err := e.customScriptRunner.RunScript(ctx, scriptPath, targets)
	if err != nil {
		return err
	}

	// 保存漏洞
	for _, vuln := range vulns {
		ctx.DB.Create(vuln)
	}

	ctx.Logger.Printf("Custom script completed, found %d vulnerabilities", len(vulns))
	return nil
}

// RunPassiveScan 运行被动扫描
func (e *Engine) RunPassiveScan(ctx *ScanContext) error {
	return e.passiveScanner.Scan(ctx)
}

// CheckSubdomainTakeover 子域名接管检测
func (e *Engine) CheckSubdomainTakeover(ctx *ScanContext) error {
	return e.takeoverScanner.Scan(ctx)
}

// MapAssets 资产测绘
func (e *Engine) MapAssets(ctx *ScanContext) error {
	return e.assetMapper.MapAssets(ctx)
}
