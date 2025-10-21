package utils

import (
	"github.com/reconmaster/backend/internal/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// SaveDomainWithDedup 保存域名并去重
func SaveDomainWithDedup(db *gorm.DB, domain *models.Domain) error {
	// 使用 FirstOrCreate 来避免重复
	return db.Where("domain = ?", domain.Domain).
		Assign(models.Domain{
			IPAddress: domain.IPAddress,
			CDN:       domain.CDN,
			Source:    domain.Source,
		}).
		FirstOrCreate(domain).Error
}

// SaveIPWithDedup 保存IP并去重
func SaveIPWithDedup(db *gorm.DB, ip *models.IP) error {
	return db.Where("ip_address = ?", ip.IPAddress).
		Assign(models.IP{
			Domain:   ip.Domain,
			OS:       ip.OS,
			CDN:      ip.CDN,
			Location: ip.Location,
		}).
		FirstOrCreate(ip).Error
}

// SavePortWithDedup 保存端口并去重
func SavePortWithDedup(db *gorm.DB, port *models.Port) error {
	return db.Where("ip_address = ? AND port = ?", port.IPAddress, port.Port).
		Assign(models.Port{
			Protocol: port.Protocol,
			Service:  port.Service,
			Version:  port.Version,
			Banner:   port.Banner,
			SSLCert:  port.SSLCert,
		}).
		FirstOrCreate(port).Error
}

// SaveSiteWithDedup 保存站点并去重
func SaveSiteWithDedup(db *gorm.DB, site *models.Site) error {
	return db.Where("url = ?", site.URL).
		Assign(models.Site{
			Title:        site.Title,
			StatusCode:   site.StatusCode,
			IP:           site.IP,
			ContentType:  site.ContentType,
			Server:       site.Server,
			Fingerprint:  site.Fingerprint,
			Fingerprints: site.Fingerprints,
			Screenshot:   site.Screenshot,
		}).
		FirstOrCreate(site).Error
}

// BatchSaveDomainsWithDedup 批量保存域名并去重
func BatchSaveDomainsWithDedup(db *gorm.DB, domains []models.Domain) error {
	if len(domains) == 0 {
		return nil
	}

	// 使用 Upsert 批量插入/更新
	return db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "domain"}},
		DoUpdates: clause.AssignmentColumns([]string{"ip_address", "cdn", "source", "updated_at"}),
	}).Create(&domains).Error
}

// BatchSaveIPsWithDedup 批量保存IP并去重
func BatchSaveIPsWithDedup(db *gorm.DB, ips []models.IP) error {
	if len(ips) == 0 {
		return nil
	}

	return db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "ip_address"}},
		DoUpdates: clause.AssignmentColumns([]string{"domain", "os", "cdn", "location", "updated_at"}),
	}).Create(&ips).Error
}

// BatchSavePortsWithDedup 批量保存端口并去重
func BatchSavePortsWithDedup(db *gorm.DB, ports []models.Port) error {
	if len(ports) == 0 {
		return nil
	}

	return db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "ip_address"}, {Name: "port"}},
		DoUpdates: clause.AssignmentColumns([]string{"protocol", "service", "version", "banner", "ssl_cert", "updated_at"}),
	}).Create(&ports).Error
}

// BatchSaveSitesWithDedup 批量保存站点并去重
func BatchSaveSitesWithDedup(db *gorm.DB, sites []models.Site) error {
	if len(sites) == 0 {
		return nil
	}

	return db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "url"}},
		DoUpdates: clause.AssignmentColumns([]string{"title", "status_code", "ip", "content_type", "server", "fingerprint", "fingerprints", "screenshot", "updated_at"}),
	}).Create(&sites).Error
}

