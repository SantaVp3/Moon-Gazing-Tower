package subdomain

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// TakeoverScanner 子域名接管检测器
type TakeoverScanner struct {
	client      *http.Client
	concurrency int
	fingerprints []TakeoverFingerprint
}

// TakeoverFingerprint 接管指纹
type TakeoverFingerprint struct {
	Service     string   `json:"service"`
	CNames      []string `json:"cnames"`
	Fingerprint []string `json:"fingerprint"`
	NXDomain    bool     `json:"nxdomain"`
	HTTPCheck   bool     `json:"http_check"`
	Vulnerable  bool     `json:"vulnerable"`
	Discussion  string   `json:"discussion,omitempty"`
}

// TakeoverResult 接管检测结果
type TakeoverResult struct {
	Domain       string   `json:"domain"`
	CNAME        string   `json:"cname"`
	Service      string   `json:"service"`
	Vulnerable   bool     `json:"vulnerable"`
	Fingerprints []string `json:"fingerprints"`
	Reason       string   `json:"reason"`
	Discussion   string   `json:"discussion,omitempty"`
}

// NewTakeoverScanner 创建子域名接管检测器
func NewTakeoverScanner(concurrency int) *TakeoverScanner {
	return &TakeoverScanner{
		client: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		concurrency:  concurrency,
		fingerprints: getDefaultFingerprints(),
	}
}

// getDefaultFingerprints 获取默认指纹库
func getDefaultFingerprints() []TakeoverFingerprint {
	return []TakeoverFingerprint{
		// AWS S3
		{
			Service:     "Amazon S3",
			CNames:      []string{".s3.amazonaws.com", ".s3-website", "s3.amazonaws.com"},
			Fingerprint: []string{"NoSuchBucket", "The specified bucket does not exist"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// AWS CloudFront
		{
			Service:     "Amazon CloudFront",
			CNames:      []string{".cloudfront.net"},
			Fingerprint: []string{"Bad Request", "ERROR: The request could not be satisfied"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// GitHub Pages
		{
			Service:     "GitHub Pages",
			CNames:      []string{".github.io", ".github.com"},
			Fingerprint: []string{"There isn't a GitHub Pages site here", "For root URLs (like http://example.com/) you must provide an index.html file"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Heroku
		{
			Service:     "Heroku",
			CNames:      []string{".herokuapp.com", ".herokussl.com", ".herokudns.com"},
			Fingerprint: []string{"No such app", "there is no app configured at that hostname"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Shopify
		{
			Service:     "Shopify",
			CNames:      []string{".myshopify.com"},
			Fingerprint: []string{"Sorry, this shop is currently unavailable", "Only one step left!"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Tumblr
		{
			Service:     "Tumblr",
			CNames:      []string{".tumblr.com"},
			Fingerprint: []string{"There's nothing here", "Whatever you were looking for doesn't currently exist at this address"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Wordpress
		{
			Service:     "WordPress",
			CNames:      []string{".wordpress.com"},
			Fingerprint: []string{"Do you want to register"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Ghost
		{
			Service:     "Ghost",
			CNames:      []string{".ghost.io"},
			Fingerprint: []string{"The thing you were looking for is no longer here"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Surge.sh
		{
			Service:     "Surge.sh",
			CNames:      []string{".surge.sh"},
			Fingerprint: []string{"project not found"},
			NXDomain:    true,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Pantheon
		{
			Service:     "Pantheon",
			CNames:      []string{".pantheonsite.io", ".pantheon.io"},
			Fingerprint: []string{"The gods are wise, but do not know of the site which you seek"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Zendesk
		{
			Service:     "Zendesk",
			CNames:      []string{".zendesk.com"},
			Fingerprint: []string{"Help Center Closed", "This help center no longer exists"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Fastly
		{
			Service:     "Fastly",
			CNames:      []string{".fastly.net", ".fastlylb.net"},
			Fingerprint: []string{"Fastly error: unknown domain"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Unbounce
		{
			Service:     "Unbounce",
			CNames:      []string{".unbounce.com", "unbouncepages.com"},
			Fingerprint: []string{"The requested URL was not found on this server", "The requested URL / was not found on this server"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Readme.io
		{
			Service:     "Readme.io",
			CNames:      []string{".readme.io"},
			Fingerprint: []string{"Project doesnt exist"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Bitbucket
		{
			Service:     "Bitbucket",
			CNames:      []string{".bitbucket.io"},
			Fingerprint: []string{"Repository not found"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Cargocollective
		{
			Service:     "Cargo Collective",
			CNames:      []string{".cargocollective.com", "subdomain.cargocollective.com"},
			Fingerprint: []string{"404 Not Found"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Statuspage
		{
			Service:     "Statuspage",
			CNames:      []string{".statuspage.io"},
			Fingerprint: []string{"You are being redirected", "Status page pushed a DNS verification", "Status page removed"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// UserVoice
		{
			Service:     "UserVoice",
			CNames:      []string{".uservoice.com"},
			Fingerprint: []string{"This UserVoice subdomain is currently available!"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Tilda
		{
			Service:     "Tilda",
			CNames:      []string{".tilda.ws"},
			Fingerprint: []string{"Please renew your subscription"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Webflow
		{
			Service:     "Webflow",
			CNames:      []string{".webflow.io"},
			Fingerprint: []string{"The page you are looking for doesn't exist or has been moved"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Azure
		{
			Service:     "Azure",
			CNames:      []string{".azurewebsites.net", ".cloudapp.net", ".cloudapp.azure.com", ".trafficmanager.net", ".blob.core.windows.net", ".azure-api.net"},
			Fingerprint: []string{"404 Web Site not found", "The resource you are looking for has been removed"},
			NXDomain:    true,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Fly.io
		{
			Service:     "Fly.io",
			CNames:      []string{".fly.dev"},
			Fingerprint: []string{"404 Not Found"},
			NXDomain:    true,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Netlify
		{
			Service:     "Netlify",
			CNames:      []string{".netlify.app", ".netlify.com"},
			Fingerprint: []string{"Not Found - Request ID"},
			NXDomain:    true,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Vercel
		{
			Service:     "Vercel",
			CNames:      []string{".vercel.app", ".now.sh"},
			Fingerprint: []string{"The deployment could not be found on Vercel"},
			NXDomain:    true,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Agile CRM
		{
			Service:     "Agile CRM",
			CNames:      []string{".agilecrm.com"},
			Fingerprint: []string{"Sorry, this page is no longer available"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Aha.io
		{
			Service:     "Aha.io",
			CNames:      []string{".ideas.aha.io"},
			Fingerprint: []string{"There is no portal here ... check portal"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Airee.ru
		{
			Service:     "Airee.ru",
			CNames:      []string{".airee.ru"},
			Fingerprint: []string{"Ошибка 402. Сервис"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Anima
		{
			Service:     "Anima",
			CNames:      []string{".animaapp.io"},
			Fingerprint: []string{"If this is your website and you've just created it, try refreshing in a minute"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Announcekit
		{
			Service:     "Announcekit",
			CNames:      []string{".announcekit.app"},
			Fingerprint: []string{"Error 404 - AnnounceKit"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Campaign Monitor
		{
			Service:     "Campaign Monitor",
			CNames:      []string{".createsend.com"},
			Fingerprint: []string{"Trying to access your account?"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Canny
		{
			Service:     "Canny",
			CNames:      []string{".canny.io"},
			Fingerprint: []string{"Company Not Found", "There is no such company. Did you enter the right URL?"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Desk
		{
			Service:     "Desk",
			CNames:      []string{".desk.com"},
			Fingerprint: []string{"Please try again or try Desk.com free for 14 days", "Sorry, We Couldn't Find That Page"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Getresponse
		{
			Service:     "Getresponse",
			CNames:      []string{".gr8.com"},
			Fingerprint: []string{"With GetResponse Landing Pages, lead generation has never been easier"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// HelpJuice
		{
			Service:     "HelpJuice",
			CNames:      []string{".helpjuice.com"},
			Fingerprint: []string{"We could not find what you're looking for"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// HelpRace
		{
			Service:     "HelpRace",
			CNames:      []string{".helprace.com"},
			Fingerprint: []string{"Alias not configured!", "Admin of this HelpRace account needs to set up domain alias"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// HelpScout
		{
			Service:     "HelpScout",
			CNames:      []string{".helpscoutdocs.com"},
			Fingerprint: []string{"No settings were found for this company"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Intercom
		{
			Service:     "Intercom",
			CNames:      []string{".custom.intercom.help"},
			Fingerprint: []string{"This page is reserved for a Intercom"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// JetBrains
		{
			Service:     "JetBrains",
			CNames:      []string{".myjetbrains.com"},
			Fingerprint: []string{"is not a registered InCloud YouTrack"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Kajabi
		{
			Service:     "Kajabi",
			CNames:      []string{".kajabi.com", ".mykajabi.com"},
			Fingerprint: []string{"The page you were looking for doesn't exist"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Kinsta
		{
			Service:     "Kinsta",
			CNames:      []string{".kinsta.cloud"},
			Fingerprint: []string{"No Site For Domain"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// LaunchRock
		{
			Service:     "LaunchRock",
			CNames:      []string{".launchrock.com"},
			Fingerprint: []string{"It looks like you may have taken a wrong turn somewhere"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Ngrok
		{
			Service:     "Ngrok",
			CNames:      []string{".ngrok.io"},
			Fingerprint: []string{"Tunnel *.ngrok.io not found", "ngrok.io not found"},
			NXDomain:    true,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Pingdom
		{
			Service:     "Pingdom",
			CNames:      []string{".stats.pingdom.com"},
			Fingerprint: []string{"This public report page has not been activated by the user"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Proposify
		{
			Service:     "Proposify",
			CNames:      []string{".proposify.biz"},
			Fingerprint: []string{"If you need immediate assistance, please contact Proposify Support"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Short.io
		{
			Service:     "Short.io",
			CNames:      []string{".short.io"},
			Fingerprint: []string{"Link does not exist"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// SmartJobBoard
		{
			Service:     "SmartJobBoard",
			CNames:      []string{".smartjobboard.com"},
			Fingerprint: []string{"This job board website is either expired or its domain name is invalid"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Smugmug
		{
			Service:     "Smugmug",
			CNames:      []string{".smugmug.com"},
			Fingerprint: []string{"Page Not Found"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Strikingly
		{
			Service:     "Strikingly",
			CNames:      []string{".strikingly.com", ".s.strikinglydns.com"},
			Fingerprint: []string{"page not found", "But if you're looking to build your own website"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Surveygizmo
		{
			Service:     "Surveygizmo",
			CNames:      []string{".surveygizmo.com", ".surveygizmo.eu"},
			Fingerprint: []string{"data-html-name"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Tave
		{
			Service:     "Tave",
			CNames:      []string{".tave.com"},
			Fingerprint: []string{"<h1>Error 404: Page Not Found</h1>"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Teamwork
		{
			Service:     "Teamwork",
			CNames:      []string{".teamwork.com"},
			Fingerprint: []string{"Oops - We didn't find your site"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Thinkific
		{
			Service:     "Thinkific",
			CNames:      []string{".thinkific.com"},
			Fingerprint: []string{"You may have mistyped the address or the page may have moved"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Tictail
		{
			Service:     "Tictail",
			CNames:      []string{".tictail.com"},
			Fingerprint: []string{"to target URL: <a href=\"https://tictail.com", "Building a brand of your own?"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Uberflip
		{
			Service:     "Uberflip",
			CNames:      []string{".uberflip.com"},
			Fingerprint: []string{"Non-hub domain, The URL you've accessed does not provide a hub"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Uptimerobot
		{
			Service:     "Uptimerobot",
			CNames:      []string{".uptimerobot.com"},
			Fingerprint: []string{"page not found"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Wix
		{
			Service:     "Wix",
			CNames:      []string{".wixsite.com"},
			Fingerprint: []string{"Error ConnectYourDomain occurred", "Looks Like This Domain Isn't Connected To A Website Yet!"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
		// Worksites
		{
			Service:     "Worksites",
			CNames:      []string{".worksites.net"},
			Fingerprint: []string{"Hello! Sorry, but the website you&rsquo;re looking for doesn&rsquo;t exist"},
			NXDomain:    false,
			HTTPCheck:   true,
			Vulnerable:  true,
		},
	}
}

// Scan 扫描单个域名
func (s *TakeoverScanner) Scan(ctx context.Context, domain string) (*TakeoverResult, error) {
	result := &TakeoverResult{
		Domain:     domain,
		Vulnerable: false,
	}

	// 获取 CNAME 记录
	cname, err := s.getCNAME(domain)
	if err != nil {
		// 检查是否 NXDOMAIN
		if strings.Contains(err.Error(), "no such host") {
			result.CNAME = "NXDOMAIN"
			result.Reason = "Domain does not exist (NXDOMAIN)"
			return result, nil
		}
		return result, nil
	}

	if cname == "" {
		result.Reason = "No CNAME record found"
		return result, nil
	}

	result.CNAME = cname

	// 检查 CNAME 是否匹配已知的可接管服务
	for _, fp := range s.fingerprints {
		if s.matchCNAME(cname, fp.CNames) {
			result.Service = fp.Service

			// 首先检查 CNAME 目标是否可以解析
			if fp.NXDomain {
				_, err := net.LookupHost(cname)
				if err != nil {
					// CNAME 目标无法解析，可能存在接管风险
					result.Vulnerable = true
					result.Reason = fmt.Sprintf("Dangling CNAME: %s does not resolve (potential %s takeover)", cname, fp.Service)
					result.Discussion = fp.Discussion
					return result, nil
				}
			}

			// 如果需要 HTTP 检查
			if fp.HTTPCheck {
				vulnerable, fingerprints := s.checkHTTP(ctx, domain, fp.Fingerprint)
				if vulnerable {
					result.Vulnerable = true
					result.Fingerprints = fingerprints
					result.Reason = fmt.Sprintf("Potential %s takeover detected", fp.Service)
					result.Discussion = fp.Discussion
				}
			}

			break
		}
	}

	// 即使没有匹配已知服务，也检查悬挂 CNAME
	if result.Service == "" && result.CNAME != "" {
		// 尝试解析 CNAME 目标
		_, err := net.LookupHost(cname)
		if err != nil && strings.Contains(err.Error(), "no such host") {
			result.Vulnerable = true
			result.Service = "Unknown"
			result.Reason = fmt.Sprintf("Dangling CNAME detected: %s does not resolve", cname)
		}
	}

	return result, nil
}

// ScanBatch 批量扫描
func (s *TakeoverScanner) ScanBatch(ctx context.Context, domains []string) ([]*TakeoverResult, error) {
	results := make([]*TakeoverResult, 0, len(domains))
	resultsMu := sync.Mutex{}
	
	sem := make(chan struct{}, s.concurrency)
	var wg sync.WaitGroup
	
	for _, domain := range domains {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		case sem <- struct{}{}:
		}
		
		wg.Add(1)
		go func(d string) {
			defer wg.Done()
			defer func() { <-sem }()
			
			result, err := s.Scan(ctx, d)
			if err != nil {
				return
			}
			
			resultsMu.Lock()
			results = append(results, result)
			resultsMu.Unlock()
		}(domain)
	}
	
	wg.Wait()
	return results, nil
}

// getCNAME 获取域名的 CNAME 记录
func (s *TakeoverScanner) getCNAME(domain string) (string, error) {
	cname, err := net.LookupCNAME(domain)
	if err != nil {
		return "", err
	}
	
	// 移除末尾的点
	cname = strings.TrimSuffix(cname, ".")
	
	// 如果 CNAME 与原域名相同，说明没有 CNAME
	if strings.EqualFold(cname, domain) {
		return "", nil
	}
	
	return cname, nil
}

// matchCNAME 检查 CNAME 是否匹配模式
func (s *TakeoverScanner) matchCNAME(cname string, patterns []string) bool {
	cname = strings.ToLower(cname)
	for _, pattern := range patterns {
		if strings.Contains(cname, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// checkHTTP 检查 HTTP 响应中的指纹
func (s *TakeoverScanner) checkHTTP(ctx context.Context, domain string, fingerprints []string) (bool, []string) {
	matched := make([]string, 0)
	
	urls := []string{
		"http://" + domain,
		"https://" + domain,
	}
	
	for _, u := range urls {
		req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
		if err != nil {
			continue
		}
		
		resp, err := s.client.Do(req)
		if err != nil {
			continue
		}
		
		body := make([]byte, 1024*100) // 读取前 100KB
		n, _ := resp.Body.Read(body)
		resp.Body.Close()
		
		bodyStr := string(body[:n])
		
		for _, fp := range fingerprints {
			if strings.Contains(bodyStr, fp) {
				matched = append(matched, fp)
			}
		}
		
		if len(matched) > 0 {
			return true, matched
		}
	}
	
	return false, nil
}

// GetFingerprints 获取指纹列表
func (s *TakeoverScanner) GetFingerprints() []TakeoverFingerprint {
	return s.fingerprints
}

// AddFingerprint 添加自定义指纹
func (s *TakeoverScanner) AddFingerprint(fp TakeoverFingerprint) {
	s.fingerprints = append(s.fingerprints, fp)
}
