package scanner

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"
)

// SSLCertInfo SSL证书信息
type SSLCertInfo struct {
	Subject        string
	Issuer         string
	NotBefore      time.Time
	NotAfter       time.Time
	DNSNames       []string
	EmailAddresses []string
	IPAddresses    []string
	CommonName     string
	Organization   string
	IsExpired      bool
	DaysRemaining  int
}

// SSLScanner SSL扫描器
type SSLScanner struct {
	timeout time.Duration
}

// NewSSLScanner 创建SSL扫描器
func NewSSLScanner() *SSLScanner {
	return &SSLScanner{
		timeout: 10 * time.Second,
	}
}

// GetCertificate 获取SSL证书
func (ss *SSLScanner) GetCertificate(host string, port int) (*SSLCertInfo, error) {
	address := fmt.Sprintf("%s:%d", host, port)
	
	dialer := &net.Dialer{
		Timeout: ss.timeout,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// 获取证书
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}

	cert := certs[0]
	
	// 解析证书信息
	info := &SSLCertInfo{
		Subject:        cert.Subject.String(),
		Issuer:         cert.Issuer.String(),
		NotBefore:      cert.NotBefore,
		NotAfter:       cert.NotAfter,
		DNSNames:       cert.DNSNames,
		EmailAddresses: cert.EmailAddresses,
		CommonName:     cert.Subject.CommonName,
		IsExpired:      time.Now().After(cert.NotAfter),
	}

	// 计算剩余天数
	daysRemaining := int(time.Until(cert.NotAfter).Hours() / 24)
	info.DaysRemaining = daysRemaining

	// 获取组织信息
	if len(cert.Subject.Organization) > 0 {
		info.Organization = cert.Subject.Organization[0]
	}

	// IP地址
	for _, ip := range cert.IPAddresses {
		info.IPAddresses = append(info.IPAddresses, ip.String())
	}

	return info, nil
}

// ExtractDomains 从证书中提取域名
func (ss *SSLScanner) ExtractDomains(cert *x509.Certificate) []string {
	domains := make(map[string]bool)

	// CommonName
	if cert.Subject.CommonName != "" {
		cn := strings.TrimSpace(cert.Subject.CommonName)
		if !strings.HasPrefix(cn, "*") && isValidDomain(cn) {
			domains[cn] = true
		}
	}

	// SANs (Subject Alternative Names)
	for _, name := range cert.DNSNames {
		name = strings.TrimSpace(name)
		if !strings.HasPrefix(name, "*") && isValidDomain(name) {
			domains[name] = true
		}
	}

	result := make([]string, 0, len(domains))
	for d := range domains {
		result = append(result, d)
	}

	return result
}

// isValidDomain 验证域名格式
func isValidDomain(domain string) bool {
	if domain == "" || len(domain) > 255 {
		return false
	}

	// 简单的域名格式检查
	if !strings.Contains(domain, ".") {
		return false
	}

	// 不包含空格
	if strings.Contains(domain, " ") {
		return false
	}

	return true
}

// FormatCertInfo 格式化证书信息为字符串
func (ss *SSLScanner) FormatCertInfo(info *SSLCertInfo) string {
	var builder strings.Builder

	builder.WriteString(fmt.Sprintf("Common Name: %s\n", info.CommonName))
	builder.WriteString(fmt.Sprintf("Organization: %s\n", info.Organization))
	builder.WriteString(fmt.Sprintf("Issuer: %s\n", info.Issuer))
	builder.WriteString(fmt.Sprintf("Valid From: %s\n", info.NotBefore.Format("2006-01-02")))
	builder.WriteString(fmt.Sprintf("Valid Until: %s\n", info.NotAfter.Format("2006-01-02")))
	builder.WriteString(fmt.Sprintf("Days Remaining: %d\n", info.DaysRemaining))

	if len(info.DNSNames) > 0 {
		builder.WriteString(fmt.Sprintf("DNS Names: %s\n", strings.Join(info.DNSNames, ", ")))
	}

	if info.IsExpired {
		builder.WriteString("Status: EXPIRED\n")
	} else if info.DaysRemaining < 30 {
		builder.WriteString("Status: EXPIRING SOON\n")
	} else {
		builder.WriteString("Status: Valid\n")
	}

	return builder.String()
}
