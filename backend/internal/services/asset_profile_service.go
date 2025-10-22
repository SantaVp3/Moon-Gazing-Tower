package services

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
)

// AssetProfileService 资产画像服务
type AssetProfileService struct{}

// NewAssetProfileService 创建资产画像服务
func NewAssetProfileService() *AssetProfileService {
	return &AssetProfileService{}
}

// GetAssetProfile 获取资产画像
func (s *AssetProfileService) GetAssetProfile(assetType, assetID string) (*models.AssetProfile, error) {
	// 根据资产类型获取不同的画像
	switch assetType {
	case "domain":
		return s.getDomainProfile(assetID)
	case "ip":
		return s.getIPProfile(assetID)
	case "site":
		return s.getSiteProfile(assetID)
	case "port":
		return s.getPortProfile(assetID)
	default:
		return nil, fmt.Errorf("unsupported asset type: %s", assetType)
	}
}

// getDomainProfile 获取域名画像
func (s *AssetProfileService) getDomainProfile(domainID string) (*models.AssetProfile, error) {
	var domain models.Domain
	if err := database.DB.First(&domain, "id = ?", domainID).Error; err != nil {
		return nil, err
	}

	profile := &models.AssetProfile{
		AssetType: "domain",
		AssetID:   domainID,
		AssetName: domain.Domain,
		CreatedAt: domain.CreatedAt,
		UpdatedAt: domain.UpdatedAt,
	}

	// 获取标签
	profile.Tags = s.getAssetTags("domain", domainID)

	// 统计关联资产
	s.countRelatedAssets(profile, "domain", domainID)

	// 统计漏洞
	profile.VulnStats = s.getVulnStats("domain", domain.Domain)

	// 域名特征
	profile.Features.IsCDN = domain.CDN
	profile.Features.TakeoverVulnerable = domain.TakeoverVulnerable
	
	// 统计子域名数量
	var subdomainCount int64
	rootDomain := extractRootDomain(domain.Domain)
	database.DB.Model(&models.Domain{}).
		Where("domain LIKE ?", "%."+rootDomain).
		Count(&subdomainCount)
	profile.Features.SubdomainCount = int(subdomainCount)

	// 计算风险评分
	profile.RiskScore, profile.RiskLevel, profile.RiskReasons = s.calculateDomainRisk(domain, profile)

	return profile, nil
}

// getIPProfile 获取IP画像
func (s *AssetProfileService) getIPProfile(ipID string) (*models.AssetProfile, error) {
	var ip models.IP
	if err := database.DB.First(&ip, "id = ?", ipID).Error; err != nil {
		return nil, err
	}

	profile := &models.AssetProfile{
		AssetType: "ip",
		AssetID:   ipID,
		AssetName: ip.IPAddress,
		CreatedAt: ip.CreatedAt,
		UpdatedAt: ip.UpdatedAt,
	}

	// 获取标签
	profile.Tags = s.getAssetTags("ip", ipID)

	// 统计关联资产
	s.countRelatedAssets(profile, "ip", ipID)

	// 统计漏洞
	profile.VulnStats = s.getVulnStats("ip", ip.IPAddress)

	// IP特征
	profile.Features.Location = ip.Location
	profile.Features.OS = ip.OS
	
	// 获取开放端口
	var ports []models.Port
	database.DB.Where("ip_address = ?", ip.IPAddress).Find(&ports)
	openPorts := make([]int, len(ports))
	for i, p := range ports {
		openPorts[i] = p.Port
	}
	profile.Features.OpenPorts = openPorts

	// 计算风险评分
	profile.RiskScore, profile.RiskLevel, profile.RiskReasons = s.calculateIPRisk(ip, profile)

	return profile, nil
}

// getSiteProfile 获取站点画像
func (s *AssetProfileService) getSiteProfile(siteID string) (*models.AssetProfile, error) {
	var site models.Site
	if err := database.DB.First(&site, "id = ?", siteID).Error; err != nil {
		return nil, err
	}

	profile := &models.AssetProfile{
		AssetType: "site",
		AssetID:   siteID,
		AssetName: site.URL,
		CreatedAt: site.CreatedAt,
		UpdatedAt: site.UpdatedAt,
	}

	// 获取标签
	profile.Tags = s.getAssetTags("site", siteID)

	// 统计关联资产
	s.countRelatedAssets(profile, "site", siteID)

	// 统计漏洞
	profile.VulnStats = s.getVulnStats("site", site.URL)

	// 站点特征
	profile.Features.Title = site.Title
	profile.Features.StatusCode = site.StatusCode
	profile.Features.Fingerprints = site.Fingerprints
	profile.Features.HasScreenshot = site.Screenshot != ""

	// 计算风险评分
	profile.RiskScore, profile.RiskLevel, profile.RiskReasons = s.calculateSiteRisk(site, profile)

	return profile, nil
}

// getPortProfile 获取端口画像
func (s *AssetProfileService) getPortProfile(portID string) (*models.AssetProfile, error) {
	var port models.Port
	if err := database.DB.First(&port, "id = ?", portID).Error; err != nil {
		return nil, err
	}

	profile := &models.AssetProfile{
		AssetType: "port",
		AssetID:   portID,
		AssetName: fmt.Sprintf("%s:%d", port.IPAddress, port.Port),
		CreatedAt: port.CreatedAt,
		UpdatedAt: port.UpdatedAt,
	}

	// 获取标签
	profile.Tags = s.getAssetTags("port", portID)

	// 统计关联资产
	s.countRelatedAssets(profile, "port", portID)

	// 统计漏洞
	profile.VulnStats = s.getVulnStats("port", fmt.Sprintf("%s:%d", port.IPAddress, port.Port))

	// 端口特征
	profile.Features.Service = port.Service
	profile.Features.Version = port.Version
	profile.Features.Banner = port.Banner

	// 计算风险评分
	profile.RiskScore, profile.RiskLevel, profile.RiskReasons = s.calculatePortRisk(port, profile)

	return profile, nil
}

// getAssetTags 获取资产标签
func (s *AssetProfileService) getAssetTags(assetType, assetID string) []models.AssetTag {
	var relations []models.AssetTagRelation
	database.DB.Where("asset_type = ? AND asset_id = ?", assetType, assetID).Find(&relations)

	if len(relations) == 0 {
		return []models.AssetTag{}
	}

	tagIDs := make([]string, len(relations))
	for i, rel := range relations {
		tagIDs[i] = rel.TagID
	}

	var tags []models.AssetTag
	database.DB.Where("id IN ?", tagIDs).Find(&tags)

	return tags
}

// countRelatedAssets 统计关联资产
func (s *AssetProfileService) countRelatedAssets(profile *models.AssetProfile, assetType, assetID string) {
	switch assetType {
	case "domain":
		var domain models.Domain
		database.DB.First(&domain, "id = ?", assetID)
		
		// 关联IP
		if domain.IPAddress != "" {
			var ipCount int64
			database.DB.Model(&models.IP{}).Where("ip_address = ?", domain.IPAddress).Count(&ipCount)
			profile.RelatedIPs = int(ipCount)
		}
		
		// 关联端口
		if domain.IPAddress != "" {
			var portCount int64
			database.DB.Model(&models.Port{}).Where("ip_address = ?", domain.IPAddress).Count(&portCount)
			profile.RelatedPorts = int(portCount)
		}
		
		// 关联站点
		var siteCount int64
		database.DB.Model(&models.Site{}).Where("url LIKE ?", "%"+domain.Domain+"%").Count(&siteCount)
		profile.RelatedSites = int(siteCount)

	case "ip":
		var ip models.IP
		database.DB.First(&ip, "id = ?", assetID)
		
		// 关联域名
		var domainCount int64
		database.DB.Model(&models.Domain{}).Where("ip_address = ?", ip.IPAddress).Count(&domainCount)
		profile.RelatedDomains = int(domainCount)
		
		// 关联端口
		var portCount int64
		database.DB.Model(&models.Port{}).Where("ip_address = ?", ip.IPAddress).Count(&portCount)
		profile.RelatedPorts = int(portCount)
		
		// 关联站点
		var siteCount int64
		database.DB.Model(&models.Site{}).Where("ip = ?", ip.IPAddress).Count(&siteCount)
		profile.RelatedSites = int(siteCount)

	case "site":
		var site models.Site
		database.DB.First(&site, "id = ?", assetID)
		
		// 从URL提取域名和IP
		domain := extractDomainFromURL(site.URL)
		if domain != "" {
			var domainCount int64
			database.DB.Model(&models.Domain{}).Where("domain = ?", domain).Count(&domainCount)
			profile.RelatedDomains = int(domainCount)
		}
		
		if site.IP != "" {
			var ipCount int64
			database.DB.Model(&models.IP{}).Where("ip_address = ?", site.IP).Count(&ipCount)
			profile.RelatedIPs = int(ipCount)
			
			var portCount int64
			database.DB.Model(&models.Port{}).Where("ip_address = ?", site.IP).Count(&portCount)
			profile.RelatedPorts = int(portCount)
		}
	}
}

// getVulnStats 获取漏洞统计
func (s *AssetProfileService) getVulnStats(assetType, assetValue string) models.VulnerabilityStats {
	var stats models.VulnerabilityStats
	
	query := database.DB.Model(&models.Vulnerability{})
	
	// 根据资产类型构建查询
	switch assetType {
	case "domain":
		query = query.Where("url LIKE ?", "%"+assetValue+"%")
	case "ip":
		query = query.Where("url LIKE ?", "%"+assetValue+"%")
	case "site":
		query = query.Where("url = ?", assetValue)
	case "port":
		query = query.Where("url LIKE ?", "%"+assetValue+"%")
	}
	
	var total int64
	query.Count(&total)
	stats.Total = int(total)
	
	var critical, high, medium, low, info int64
	database.DB.Model(&models.Vulnerability{}).Where("url LIKE ? AND severity = ?", "%"+assetValue+"%", "critical").Count(&critical)
	database.DB.Model(&models.Vulnerability{}).Where("url LIKE ? AND severity = ?", "%"+assetValue+"%", "high").Count(&high)
	database.DB.Model(&models.Vulnerability{}).Where("url LIKE ? AND severity = ?", "%"+assetValue+"%", "medium").Count(&medium)
	database.DB.Model(&models.Vulnerability{}).Where("url LIKE ? AND severity = ?", "%"+assetValue+"%", "low").Count(&low)
	database.DB.Model(&models.Vulnerability{}).Where("url LIKE ? AND severity = ?", "%"+assetValue+"%", "info").Count(&info)
	
	stats.Critical = int(critical)
	stats.High = int(high)
	stats.Medium = int(medium)
	stats.Low = int(low)
	stats.Info = int(info)
	
	return stats
}

// calculateDomainRisk 计算域名风险评分
func (s *AssetProfileService) calculateDomainRisk(domain models.Domain, profile *models.AssetProfile) (int, string, []string) {
	score := 0
	reasons := []string{}

	// 子域名接管 +40
	if domain.TakeoverVulnerable {
		score += 40
		reasons = append(reasons, "存在子域名接管风险")
	}

	// 漏洞数量
	if profile.VulnStats.Critical > 0 {
		score += 30
		reasons = append(reasons, fmt.Sprintf("存在 %d 个严重漏洞", profile.VulnStats.Critical))
	}
	if profile.VulnStats.High > 0 {
		score += 20
		reasons = append(reasons, fmt.Sprintf("存在 %d 个高危漏洞", profile.VulnStats.High))
	}
	if profile.VulnStats.Medium > 0 {
		score += 10
		reasons = append(reasons, fmt.Sprintf("存在 %d 个中危漏洞", profile.VulnStats.Medium))
	}

	// CDN保护 -5
	if domain.CDN {
		score -= 5
	}

	level := getRiskLevel(score)
	return score, level, reasons
}

// calculateIPRisk 计算IP风险评分
func (s *AssetProfileService) calculateIPRisk(ip models.IP, profile *models.AssetProfile) (int, string, []string) {
	score := 0
	reasons := []string{}

	// 开放端口数量
	openPortCount := len(profile.Features.OpenPorts)
	if openPortCount > 20 {
		score += 20
		reasons = append(reasons, fmt.Sprintf("开放端口过多 (%d个)", openPortCount))
	} else if openPortCount > 10 {
		score += 10
		reasons = append(reasons, fmt.Sprintf("开放端口较多 (%d个)", openPortCount))
	}

	// 漏洞数量
	if profile.VulnStats.Critical > 0 {
		score += 30
		reasons = append(reasons, fmt.Sprintf("存在 %d 个严重漏洞", profile.VulnStats.Critical))
	}
	if profile.VulnStats.High > 0 {
		score += 20
		reasons = append(reasons, fmt.Sprintf("存在 %d 个高危漏洞", profile.VulnStats.High))
	}

	// 危险端口
	dangerousPorts := []int{21, 22, 23, 3389, 445, 135, 1433, 3306, 5432, 6379, 27017}
	for _, port := range profile.Features.OpenPorts {
		for _, dangerPort := range dangerousPorts {
			if port == dangerPort {
				score += 5
				reasons = append(reasons, fmt.Sprintf("开放危险端口 %d", port))
				break
			}
		}
	}

	level := getRiskLevel(score)
	return score, level, reasons
}

// calculateSiteRisk 计算站点风险评分
func (s *AssetProfileService) calculateSiteRisk(site models.Site, profile *models.AssetProfile) (int, string, []string) {
	score := 0
	reasons := []string{}

	// 漏洞数量
	if profile.VulnStats.Critical > 0 {
		score += 30
		reasons = append(reasons, fmt.Sprintf("存在 %d 个严重漏洞", profile.VulnStats.Critical))
	}
	if profile.VulnStats.High > 0 {
		score += 20
		reasons = append(reasons, fmt.Sprintf("存在 %d 个高危漏洞", profile.VulnStats.High))
	}
	if profile.VulnStats.Medium > 0 {
		score += 10
		reasons = append(reasons, fmt.Sprintf("存在 %d 个中危漏洞", profile.VulnStats.Medium))
	}

	// 指纹数量（可能暴露的信息）
	if len(profile.Features.Fingerprints) > 5 {
		score += 5
		reasons = append(reasons, "暴露过多指纹信息")
	}

	// HTTP状态码
	if site.StatusCode == 403 || site.StatusCode == 401 {
		score += 5
		reasons = append(reasons, "存在认证/授权端点")
	}

	level := getRiskLevel(score)
	return score, level, reasons
}

// calculatePortRisk 计算端口风险评分
func (s *AssetProfileService) calculatePortRisk(port models.Port, profile *models.AssetProfile) (int, string, []string) {
	score := 0
	reasons := []string{}

	// 危险端口
	dangerousPorts := map[int]string{
		21:    "FTP",
		22:    "SSH",
		23:    "Telnet",
		3389:  "RDP",
		445:   "SMB",
		135:   "RPC",
		1433:  "MSSQL",
		3306:  "MySQL",
		5432:  "PostgreSQL",
		6379:  "Redis",
		27017: "MongoDB",
	}

	if serviceName, isDangerous := dangerousPorts[port.Port]; isDangerous {
		score += 15
		reasons = append(reasons, fmt.Sprintf("危险服务 %s (%d)", serviceName, port.Port))
	}

	// 漏洞数量
	if profile.VulnStats.Critical > 0 {
		score += 30
		reasons = append(reasons, fmt.Sprintf("存在 %d 个严重漏洞", profile.VulnStats.Critical))
	}
	if profile.VulnStats.High > 0 {
		score += 20
		reasons = append(reasons, fmt.Sprintf("存在 %d 个高危漏洞", profile.VulnStats.High))
	}

	// Banner信息泄露
	if port.Banner != "" && len(port.Banner) > 50 {
		score += 5
		reasons = append(reasons, "Banner信息过度暴露")
	}

	level := getRiskLevel(score)
	return score, level, reasons
}

// getRiskLevel 根据分数获取风险等级
func getRiskLevel(score int) string {
	if score >= 50 {
		return "critical"
	} else if score >= 30 {
		return "high"
	} else if score >= 15 {
		return "medium"
	}
	return "low"
}

// extractRootDomain 提取根域名
func extractRootDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return domain
}

// extractDomainFromURL 从URL提取域名
func extractDomainFromURL(url string) string {
	// 简化版本，实际应该用url.Parse
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "https://")
	if idx := strings.Index(url, "/"); idx != -1 {
		url = url[:idx]
	}
	if idx := strings.Index(url, ":"); idx != -1 {
		url = url[:idx]
	}
	return url
}

// GetAssetRelations 获取资产关系
func (s *AssetProfileService) GetAssetRelations(assetType, assetID string) ([]models.AssetRelation, error) {
	relations := []models.AssetRelation{}

	switch assetType {
	case "domain":
		var domain models.Domain
		if err := database.DB.First(&domain, "id = ?", assetID).Error; err != nil {
			return nil, err
		}

		// 域名 -> IP
		if domain.IPAddress != "" {
			var ips []models.IP
			database.DB.Where("ip_address = ?", domain.IPAddress).Find(&ips)
			for _, ip := range ips {
				relations = append(relations, models.AssetRelation{
					SourceType: "domain",
					SourceID:   domain.ID,
					SourceName: domain.Domain,
					TargetType: "ip",
					TargetID:   ip.ID,
					TargetName: ip.IPAddress,
					Relation:   "resolves_to",
					CreatedAt:  time.Now(),
				})
			}
		}

	case "ip":
		var ip models.IP
		if err := database.DB.First(&ip, "id = ?", assetID).Error; err != nil {
			return nil, err
		}

		// IP -> 端口
		var ports []models.Port
		database.DB.Where("ip_address = ?", ip.IPAddress).Find(&ports)
		for _, port := range ports {
			relations = append(relations, models.AssetRelation{
				SourceType: "ip",
				SourceID:   ip.ID,
				SourceName: ip.IPAddress,
				TargetType: "port",
				TargetID:   port.ID,
				TargetName: fmt.Sprintf("%d/%s", port.Port, port.Protocol),
				Relation:   "hosts",
				CreatedAt:  time.Now(),
			})
		}

		// IP -> 站点
		var sites []models.Site
		database.DB.Where("ip = ?", ip.IPAddress).Find(&sites)
		for _, site := range sites {
			relations = append(relations, models.AssetRelation{
				SourceType: "ip",
				SourceID:   ip.ID,
				SourceName: ip.IPAddress,
				TargetType: "site",
				TargetID:   site.ID,
				TargetName: site.URL,
				Relation:   "hosts",
				CreatedAt:  time.Now(),
			})
		}
	}

	return relations, nil
}

// GetAssetGraph 获取资产关系图谱
func (s *AssetProfileService) GetAssetGraph(assetType, assetID string, depth int) (*models.AssetGraph, error) {
	graph := &models.AssetGraph{
		Nodes: []models.AssetGraphNode{},
		Edges: []models.AssetGraphEdge{},
	}

	visited := make(map[string]bool)
	s.buildGraph(graph, assetType, assetID, depth, visited)

	return graph, nil
}

// buildGraph 递归构建关系图谱
func (s *AssetProfileService) buildGraph(graph *models.AssetGraph, assetType, assetID string, depth int, visited map[string]bool) {
	if depth <= 0 {
		return
	}

	key := assetType + ":" + assetID
	if visited[key] {
		return
	}
	visited[key] = true

	// 添加当前节点
	node := s.createGraphNode(assetType, assetID)
	if node != nil {
		graph.Nodes = append(graph.Nodes, *node)
	}

	// 获取关系
	relations, _ := s.GetAssetRelations(assetType, assetID)
	for _, rel := range relations {
		// 添加边
		edge := models.AssetGraphEdge{
			ID:       fmt.Sprintf("%s_%s", rel.SourceID, rel.TargetID),
			Source:   rel.SourceID,
			Target:   rel.TargetID,
			Relation: rel.Relation,
			Label:    rel.Relation,
		}
		graph.Edges = append(graph.Edges, edge)

		// 递归添加目标节点
		s.buildGraph(graph, rel.TargetType, rel.TargetID, depth-1, visited)
	}
}

// createGraphNode 创建图谱节点
func (s *AssetProfileService) createGraphNode(assetType, assetID string) *models.AssetGraphNode {
	node := &models.AssetGraphNode{
		ID:   assetID,
		Type: assetType,
	}

	switch assetType {
	case "domain":
		var domain models.Domain
		if err := database.DB.First(&domain, "id = ?", assetID).Error; err == nil {
			node.Name = domain.Domain
			node.Label = domain.Domain
		}
	case "ip":
		var ip models.IP
		if err := database.DB.First(&ip, "id = ?", assetID).Error; err == nil {
			node.Name = ip.IPAddress
			node.Label = ip.IPAddress
		}
	case "site":
		var site models.Site
		if err := database.DB.First(&site, "id = ?", assetID).Error; err == nil {
			node.Name = site.URL
			node.Label = site.Title
			if node.Label == "" {
				node.Label = site.URL
			}
		}
	case "port":
		var port models.Port
		if err := database.DB.First(&port, "id = ?", assetID).Error; err == nil {
			node.Name = fmt.Sprintf("%s:%d", port.IPAddress, port.Port)
			node.Label = fmt.Sprintf("%d/%s", port.Port, port.Service)
		}
	}

	return node
}

// AnalyzeCSegment C段分析
func (s *AssetProfileService) AnalyzeCSegment(ipAddress string) (*models.CSegmentAnalysis, error) {
	// 提取C段
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address")
	}

	ipv4 := ip.To4()
	if ipv4 == nil {
		return nil, fmt.Errorf("only IPv4 supported")
	}

	// C段: x.x.x.0/24
	cSegment := fmt.Sprintf("%d.%d.%d.0/24", ipv4[0], ipv4[1], ipv4[2])
	cSegmentPrefix := fmt.Sprintf("%d.%d.%d.", ipv4[0], ipv4[1], ipv4[2])

	analysis := &models.CSegmentAnalysis{
		CSegment: cSegment,
	}

	// 查询该C段的所有IP
	var ips []models.IP
	database.DB.Where("ip_address LIKE ?", cSegmentPrefix+"%").Find(&ips)
	
	analysis.TotalIPs = len(ips)
	analysis.ActiveIPs = make([]string, len(ips))
	for i, ip := range ips {
		analysis.ActiveIPs[i] = ip.IPAddress
	}

	// 统计端口
	var totalPorts int64
	database.DB.Model(&models.Port{}).
		Where("ip_address LIKE ?", cSegmentPrefix+"%").
		Count(&totalPorts)
	analysis.TotalPorts = int(totalPorts)

	// 统计站点
	var totalSites int64
	database.DB.Model(&models.Site{}).
		Where("ip LIKE ?", cSegmentPrefix+"%").
		Count(&totalSites)
	analysis.TotalSites = int(totalSites)

	// 统计常见端口
	type PortCount struct {
		Port  int
		Count int
	}
	var portCounts []PortCount
	database.DB.Model(&models.Port{}).
		Select("port, COUNT(*) as count").
		Where("ip_address LIKE ?", cSegmentPrefix+"%").
		Group("port").
		Order("count DESC").
		Limit(10).
		Scan(&portCounts)
	
	analysis.CommonPorts = make([]int, len(portCounts))
	for i, pc := range portCounts {
		analysis.CommonPorts[i] = pc.Port
	}

	// 简单风险评估
	if analysis.TotalPorts > 100 {
		analysis.RiskLevel = "high"
	} else if analysis.TotalPorts > 50 {
		analysis.RiskLevel = "medium"
	} else {
		analysis.RiskLevel = "low"
	}

	return analysis, nil
}
