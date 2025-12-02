package api

import (
	"context"
	"fmt"
	"time"

	"moongazing/scanner/enscan"
	"moongazing/scanner/subdomain/thirdparty"
	"moongazing/utils"

	"github.com/gin-gonic/gin"
)

// ThirdPartyHandler 第三方 API 处理器
type ThirdPartyHandler struct {
	manager *thirdparty.APIManager
}

// NewThirdPartyHandler 创建第三方 API 处理器
func NewThirdPartyHandler() *ThirdPartyHandler {
	// 从配置或数据库加载 API 密钥
	// 这里先创建空管理器，后续通过配置 API 设置
	return &ThirdPartyHandler{
		manager: thirdparty.NewAPIManager(nil),
	}
}

// UpdateConfig 更新第三方 API 配置
// PUT /api/thirdparty/config
func (h *ThirdPartyHandler) UpdateConfig(c *gin.Context) {
	var config thirdparty.APIConfig
	if err := c.ShouldBindJSON(&config); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	h.manager.UpdateConfig(&config)

	utils.Success(c, gin.H{
		"message":            "配置更新成功",
		"configured_sources": h.manager.GetConfiguredSources(),
	})
}

// GetConfig 获取第三方 API 配置
// GET /api/thirdparty/config
func (h *ThirdPartyHandler) GetConfig(c *gin.Context) {
	config := h.manager.GetConfig()
	utils.Success(c, gin.H{
		"config": config,
	})
}

// GetConfiguredSources 获取已配置的数据源
// GET /api/thirdparty/sources
func (h *ThirdPartyHandler) GetConfiguredSources(c *gin.Context) {
	sources := h.manager.GetConfiguredSources()
	utils.Success(c, gin.H{
		"sources": sources,
	})
}

// CollectSubdomains 收集子域名
// POST /api/thirdparty/subdomains
func (h *ThirdPartyHandler) CollectSubdomains(c *gin.Context) {
	var req struct {
		Domain     string   `json:"domain" binding:"required"`
		Sources    []string `json:"sources"`
		MaxResults int      `json:"max_results"`
		Timeout    int      `json:"timeout"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	timeout := 60 * time.Second
	if req.Timeout > 0 {
		timeout = time.Duration(req.Timeout) * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	start := time.Now()
	result := h.manager.CollectSubdomains(ctx, req.Domain, req.Sources, req.MaxResults)
	result.Duration = time.Since(start).String()

	utils.Success(c, result)
}

// SearchByIP 根据 IP 搜索资产
// POST /api/thirdparty/search/ip
func (h *ThirdPartyHandler) SearchByIP(c *gin.Context) {
	var req struct {
		IP         string   `json:"ip" binding:"required"`
		Sources    []string `json:"sources"`
		MaxResults int      `json:"max_results"`
		Timeout    int      `json:"timeout"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	timeout := 60 * time.Second
	if req.Timeout > 0 {
		timeout = time.Duration(req.Timeout) * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	assets := h.manager.SearchByIP(ctx, req.IP, req.Sources, req.MaxResults)

	utils.Success(c, gin.H{
		"ip":     req.IP,
		"total":  len(assets),
		"assets": assets,
	})
}

// SearchByCert 根据证书搜索
// POST /api/thirdparty/search/cert
func (h *ThirdPartyHandler) SearchByCert(c *gin.Context) {
	var req struct {
		Keyword    string   `json:"keyword" binding:"required"`
		Sources    []string `json:"sources"`
		MaxResults int      `json:"max_results"`
		Timeout    int      `json:"timeout"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	timeout := 60 * time.Second
	if req.Timeout > 0 {
		timeout = time.Duration(req.Timeout) * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	assets := h.manager.SearchByCert(ctx, req.Keyword, req.Sources, req.MaxResults)

	utils.Success(c, gin.H{
		"keyword": req.Keyword,
		"total":   len(assets),
		"assets":  assets,
	})
}

// SearchByIconHash 根据图标哈希搜索
// POST /api/thirdparty/search/icon
func (h *ThirdPartyHandler) SearchByIconHash(c *gin.Context) {
	var req struct {
		Hash       string   `json:"hash" binding:"required"`
		Sources    []string `json:"sources"`
		MaxResults int      `json:"max_results"`
		Timeout    int      `json:"timeout"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	timeout := 60 * time.Second
	if req.Timeout > 0 {
		timeout = time.Duration(req.Timeout) * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	assets := h.manager.SearchByIconHash(ctx, req.Hash, req.Sources, req.MaxResults)

	utils.Success(c, gin.H{
		"icon_hash": req.Hash,
		"total":     len(assets),
		"assets":    assets,
	})
}

// SearchByTitle 根据网站标题搜索
// POST /api/thirdparty/search/title
func (h *ThirdPartyHandler) SearchByTitle(c *gin.Context) {
	var req struct {
		Title      string   `json:"title" binding:"required"`
		Sources    []string `json:"sources"`
		MaxResults int      `json:"max_results"`
		Timeout    int      `json:"timeout"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	timeout := 60 * time.Second
	if req.Timeout > 0 {
		timeout = time.Duration(req.Timeout) * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var allAssets []thirdparty.UnifiedAsset

	// Fofa 搜索
	if h.manager.Fofa != nil && h.manager.Fofa.IsConfigured() {
		assets, err := h.manager.Fofa.SearchByTitle(ctx, req.Title, req.MaxResults)
		if err == nil {
			for _, a := range assets {
				port := 0
				if a.Port != "" {
					_, _ = fmt.Sscanf(a.Port, "%d", &port)
				}
				allAssets = append(allAssets, thirdparty.UnifiedAsset{
					Host:     a.Host,
					IP:       a.IP,
					Port:     port,
					Protocol: a.Protocol,
					Domain:   a.Domain,
					Title:    a.Title,
					Server:   a.Server,
					Source:   "fofa",
				})
			}
		}
	}

	// Quake 搜索
	if h.manager.Quake != nil && h.manager.Quake.IsConfigured() {
		assets, err := h.manager.Quake.SearchByTitle(ctx, req.Title, req.MaxResults)
		if err == nil {
			for _, a := range assets {
				allAssets = append(allAssets, thirdparty.UnifiedAsset{
					Host:     a.Hostname,
					IP:       a.IP,
					Port:     a.Port,
					Protocol: a.Transport,
					Domain:   a.Domain,
					Title:    a.Service.HTTP.Title,
					Server:   a.Service.HTTP.Server,
					Source:   "quake",
				})
			}
		}
	}

	utils.Success(c, gin.H{
		"title":  req.Title,
		"total":  len(allAssets),
		"assets": allAssets,
	})
}

// FofaSearch Fofa 自定义查询
// POST /api/thirdparty/fofa/search
func (h *ThirdPartyHandler) FofaSearch(c *gin.Context) {
	var req struct {
		Query   string `json:"query" binding:"required"`
		Fields  string `json:"fields"`
		Page    int    `json:"page"`
		Size    int    `json:"size"`
		Timeout int    `json:"timeout"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	if h.manager.Fofa == nil || !h.manager.Fofa.IsConfigured() {
		utils.Error(c, utils.ErrCodeConfigError, "Fofa API 未配置")
		return
	}

	if req.Page <= 0 {
		req.Page = 1
	}
	if req.Size <= 0 {
		req.Size = 100
	}

	timeout := 30 * time.Second
	if req.Timeout > 0 {
		timeout = time.Duration(req.Timeout) * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	result, err := h.manager.Fofa.Search(ctx, req.Query, req.Page, req.Size, req.Fields)
	if err != nil {
		utils.Error(c, utils.ErrCodeThirdPartyError, err.Error())
		return
	}

	utils.Success(c, result)
}

// HunterSearch Hunter 自定义查询
// POST /api/thirdparty/hunter/search
func (h *ThirdPartyHandler) HunterSearch(c *gin.Context) {
	var req struct {
		Query     string `json:"query" binding:"required"`
		Page      int    `json:"page"`
		PageSize  int    `json:"page_size"`
		StartTime string `json:"start_time"`
		EndTime   string `json:"end_time"`
		Timeout   int    `json:"timeout"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	if h.manager.Hunter == nil || !h.manager.Hunter.IsConfigured() {
		utils.Error(c, utils.ErrCodeConfigError, "Hunter API 未配置")
		return
	}

	if req.Page <= 0 {
		req.Page = 1
	}
	if req.PageSize <= 0 {
		req.PageSize = 100
	}

	timeout := 30 * time.Second
	if req.Timeout > 0 {
		timeout = time.Duration(req.Timeout) * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	result, err := h.manager.Hunter.Search(ctx, req.Query, req.Page, req.PageSize, req.StartTime, req.EndTime)
	if err != nil {
		utils.Error(c, utils.ErrCodeThirdPartyError, err.Error())
		return
	}

	utils.Success(c, result)
}

// QuakeSearch Quake 自定义查询
// POST /api/thirdparty/quake/search
func (h *ThirdPartyHandler) QuakeSearch(c *gin.Context) {
	var req struct {
		Query   string `json:"query" binding:"required"`
		Start   int    `json:"start"`
		Size    int    `json:"size"`
		Timeout int    `json:"timeout"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	if h.manager.Quake == nil || !h.manager.Quake.IsConfigured() {
		utils.Error(c, utils.ErrCodeConfigError, "Quake API 未配置")
		return
	}

	if req.Size <= 0 {
		req.Size = 100
	}

	timeout := 30 * time.Second
	if req.Timeout > 0 {
		timeout = time.Duration(req.Timeout) * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	result, err := h.manager.Quake.Search(ctx, req.Query, req.Start, req.Size)
	if err != nil {
		utils.Error(c, utils.ErrCodeThirdPartyError, err.Error())
		return
	}

	utils.Success(c, result)
}

// GetCertSubdomains 通过证书透明度查询子域名 (免费)
// GET /api/thirdparty/crtsh/subdomains
func (h *ThirdPartyHandler) GetCertSubdomains(c *gin.Context) {
	domain := c.Query("domain")
	if domain == "" {
		utils.BadRequest(c, "domain 参数必填")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	subdomains, err := h.manager.CrtSh.SearchSubdomains(ctx, domain)
	if err != nil {
		utils.Error(c, utils.ErrCodeThirdPartyError, err.Error())
		return
	}

	utils.Success(c, gin.H{
		"domain":     domain,
		"total":      len(subdomains),
		"subdomains": subdomains,
		"source":     "crt.sh",
	})
}

// ===================== ENScan 企业信息查询 =====================

// ENScanHandler ENScan 处理器
type ENScanHandler struct {
	scanner *enscan.ENScanScanner
}

// NewENScanHandler 创建 ENScan 处理器
func NewENScanHandler() *ENScanHandler {
	return &ENScanHandler{
		scanner: enscan.NewENScanScanner(),
	}
}

// GetStatus 获取 ENScan 状态
// GET /api/enscan/status
func (h *ENScanHandler) GetStatus(c *gin.Context) {
	utils.Success(c, gin.H{
		"available": h.scanner.IsAvailable(),
	})
}

// QueryCompany 查询公司信息
// POST /api/enscan/query
func (h *ENScanHandler) QueryCompany(c *gin.Context) {
	var req struct {
		Company     string   `json:"company" binding:"required"`
		Fields      []string `json:"fields"`
		Source      string   `json:"source"`
		InvestRatio int      `json:"invest_ratio"`
		Depth       int      `json:"depth"`
		Branch      bool     `json:"branch"`
		Timeout     int      `json:"timeout"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	if !h.scanner.IsAvailable() {
		utils.InternalError(c, "ENScan 工具不可用，请先安装")
		return
	}

	timeout := 120 * time.Second
	if req.Timeout > 0 {
		timeout = time.Duration(req.Timeout) * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	opts := &enscan.ENScanQueryOptions{
		Fields:      req.Fields,
		Source:      req.Source,
		InvestRatio: req.InvestRatio,
		Depth:       req.Depth,
		Branch:      req.Branch,
	}

	if len(opts.Fields) == 0 {
		opts.Fields = []string{"app", "wx_app", "wechat", "icp"}
	}
	if opts.Source == "" {
		opts.Source = "aqc"
	}

	result, err := h.scanner.QueryCompany(ctx, req.Company, opts)
	if err != nil {
		utils.InternalError(c, "查询失败: "+err.Error())
		return
	}

	utils.Success(c, result)
}

// QueryApps 查询公司 APP 信息
// GET /api/enscan/apps
func (h *ENScanHandler) QueryApps(c *gin.Context) {
	company := c.Query("company")
	if company == "" {
		utils.BadRequest(c, "company 参数必填")
		return
	}

	if !h.scanner.IsAvailable() {
		utils.InternalError(c, "ENScan 工具不可用")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	apps, err := h.scanner.QueryApps(ctx, company)
	if err != nil {
		utils.InternalError(c, "查询失败: "+err.Error())
		return
	}

	utils.Success(c, gin.H{
		"company": company,
		"total":   len(apps),
		"apps":    apps,
	})
}

// QueryWxApps 查询公司微信小程序
// GET /api/enscan/wxapps
func (h *ENScanHandler) QueryWxApps(c *gin.Context) {
	company := c.Query("company")
	if company == "" {
		utils.BadRequest(c, "company 参数必填")
		return
	}

	if !h.scanner.IsAvailable() {
		utils.InternalError(c, "ENScan 工具不可用")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	wxApps, err := h.scanner.QueryWxApps(ctx, company)
	if err != nil {
		utils.InternalError(c, "查询失败: "+err.Error())
		return
	}

	utils.Success(c, gin.H{
		"company": company,
		"total":   len(wxApps),
		"wx_apps": wxApps,
	})
}

// QueryWechats 查询公司微信公众号
// GET /api/enscan/wechats
func (h *ENScanHandler) QueryWechats(c *gin.Context) {
	company := c.Query("company")
	if company == "" {
		utils.BadRequest(c, "company 参数必填")
		return
	}

	if !h.scanner.IsAvailable() {
		utils.InternalError(c, "ENScan 工具不可用")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	wechats, err := h.scanner.QueryWechats(ctx, company)
	if err != nil {
		utils.InternalError(c, "查询失败: "+err.Error())
		return
	}

	utils.Success(c, gin.H{
		"company": company,
		"total":   len(wechats),
		"wechats": wechats,
	})
}

// QueryICPs 查询公司 ICP 备案
// GET /api/enscan/icps
func (h *ENScanHandler) QueryICPs(c *gin.Context) {
	company := c.Query("company")
	if company == "" {
		utils.BadRequest(c, "company 参数必填")
		return
	}

	if !h.scanner.IsAvailable() {
		utils.InternalError(c, "ENScan 工具不可用")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	icps, err := h.scanner.QueryICPs(ctx, company)
	if err != nil {
		utils.InternalError(c, "查询失败: "+err.Error())
		return
	}

	utils.Success(c, gin.H{
		"company": company,
		"total":   len(icps),
		"icps":    icps,
	})
}

// QueryAll 查询公司所有信息
// GET /api/enscan/all
func (h *ENScanHandler) QueryAll(c *gin.Context) {
	company := c.Query("company")
	if company == "" {
		utils.BadRequest(c, "company 参数必填")
		return
	}

	if !h.scanner.IsAvailable() {
		utils.InternalError(c, "ENScan 工具不可用")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	result, err := h.scanner.QueryAll(ctx, company)
	if err != nil {
		utils.InternalError(c, "查询失败: "+err.Error())
		return
	}

	utils.Success(c, result)
}

// BatchQuery 批量查询公司信息
// POST /api/enscan/batch
func (h *ENScanHandler) BatchQuery(c *gin.Context) {
	var req struct {
		Companies   []string `json:"companies" binding:"required"`
		Fields      []string `json:"fields"`
		Source      string   `json:"source"`
		Timeout     int      `json:"timeout"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	if len(req.Companies) > 50 {
		utils.BadRequest(c, "一次最多查询 50 个公司")
		return
	}

	if !h.scanner.IsAvailable() {
		utils.InternalError(c, "ENScan 工具不可用")
		return
	}

	timeout := 300 * time.Second
	if req.Timeout > 0 {
		timeout = time.Duration(req.Timeout) * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	opts := &enscan.ENScanQueryOptions{
		Fields: req.Fields,
		Source: req.Source,
	}

	if len(opts.Fields) == 0 {
		opts.Fields = []string{"app", "wx_app", "icp"}
	}
	if opts.Source == "" {
		opts.Source = "aqc"
	}

	results, err := h.scanner.BatchQuery(ctx, req.Companies, opts)
	if err != nil {
		utils.InternalError(c, "批量查询失败: "+err.Error())
		return
	}

	// 统计
	totalApps := 0
	totalWxApps := 0
	totalICPs := 0
	for _, r := range results {
		totalApps += len(r.Apps)
		totalWxApps += len(r.WxApps)
		totalICPs += len(r.ICPs)
	}

	utils.Success(c, gin.H{
		"total":        len(results),
		"total_apps":   totalApps,
		"total_wxapps": totalWxApps,
		"total_icps":   totalICPs,
		"results":      results,
	})
}
