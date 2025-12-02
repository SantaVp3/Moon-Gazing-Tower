package nuclei

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// TemplateLoader 模板加载器
type TemplateLoader struct {
	templates    map[string]*NucleiTemplate
	templateDirs []string
	mu           sync.RWMutex
}

// NewTemplateLoader 创建模板加载器
func NewTemplateLoader() *TemplateLoader {
	return &TemplateLoader{
		templates:    make(map[string]*NucleiTemplate),
		templateDirs: make([]string, 0),
	}
}

// AddTemplateDir 添加模板目录
func (l *TemplateLoader) AddTemplateDir(dir string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.templateDirs = append(l.templateDirs, dir)
}

// LoadAll 加载所有模板
func (l *TemplateLoader) LoadAll() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	for _, dir := range l.templateDirs {
		if err := l.loadDir(dir); err != nil {
			return fmt.Errorf("failed to load templates from %s: %w", dir, err)
		}
	}

	return nil
}

// loadDir 加载目录中的模板
func (l *TemplateLoader) loadDir(dir string) error {
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		// 只处理 yaml 文件
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		template, err := l.LoadFile(path)
		if err != nil {
			// 跳过解析失败的模板
			fmt.Printf("[Nuclei] Warning: failed to parse %s: %v\n", path, err)
			return nil
		}

		l.templates[template.ID] = template
		return nil
	})
}

// LoadFile 加载单个模板文件
func (l *TemplateLoader) LoadFile(path string) (*NucleiTemplate, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return l.Parse(content, path)
}

// Parse 解析模板内容
func (l *TemplateLoader) Parse(content []byte, filePath string) (*NucleiTemplate, error) {
	var template NucleiTemplate

	if err := yaml.Unmarshal(content, &template); err != nil {
		return nil, fmt.Errorf("yaml parse error: %w", err)
	}

	// 验证必要字段
	if template.ID == "" {
		return nil, fmt.Errorf("template id is required")
	}

	if template.Info.Name == "" {
		return nil, fmt.Errorf("template name is required")
	}

	// 设置原始内容和路径
	template.RawContent = string(content)
	template.FilePath = filePath

	// 编译正则表达式
	if err := l.compileMatchers(&template); err != nil {
		return nil, fmt.Errorf("compile matchers error: %w", err)
	}

	if err := l.compileExtractors(&template); err != nil {
		return nil, fmt.Errorf("compile extractors error: %w", err)
	}

	return &template, nil
}

// compileMatchers 编译匹配器的正则
func (l *TemplateLoader) compileMatchers(template *NucleiTemplate) error {
	for i := range template.HTTP {
		for j := range template.HTTP[i].Matchers {
			if err := template.HTTP[i].Matchers[j].Compile(); err != nil {
				return err
			}
		}
	}

	for i := range template.DNS {
		for j := range template.DNS[i].Matchers {
			if err := template.DNS[i].Matchers[j].Compile(); err != nil {
				return err
			}
		}
	}

	for i := range template.TCP {
		for j := range template.TCP[i].Matchers {
			if err := template.TCP[i].Matchers[j].Compile(); err != nil {
				return err
			}
		}
	}

	return nil
}

// compileExtractors 编译提取器的正则
func (l *TemplateLoader) compileExtractors(template *NucleiTemplate) error {
	for i := range template.HTTP {
		for j := range template.HTTP[i].Extractors {
			if err := template.HTTP[i].Extractors[j].Compile(); err != nil {
				return err
			}
		}
	}

	for i := range template.DNS {
		for j := range template.DNS[i].Extractors {
			if err := template.DNS[i].Extractors[j].Compile(); err != nil {
				return err
			}
		}
	}

	for i := range template.TCP {
		for j := range template.TCP[i].Extractors {
			if err := template.TCP[i].Extractors[j].Compile(); err != nil {
				return err
			}
		}
	}

	return nil
}

// Compile 编译匹配器正则
func (m *Matcher) Compile() error {
	if m.Type != "regex" && len(m.Regex) == 0 {
		return nil
	}

	m.CompiledRegex = make([]*regexp.Regexp, 0, len(m.Regex))
	for _, pattern := range m.Regex {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("invalid regex pattern '%s': %w", pattern, err)
		}
		m.CompiledRegex = append(m.CompiledRegex, re)
	}

	return nil
}

// Compile 编译提取器正则
func (e *Extractor) Compile() error {
	if e.Type != "regex" && len(e.Regex) == 0 {
		return nil
	}

	e.CompiledRegex = make([]*regexp.Regexp, 0, len(e.Regex))
	for _, pattern := range e.Regex {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("invalid regex pattern '%s': %w", pattern, err)
		}
		e.CompiledRegex = append(e.CompiledRegex, re)
	}

	return nil
}

// GetTemplate 获取模板
func (l *TemplateLoader) GetTemplate(id string) (*NucleiTemplate, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	t, ok := l.templates[id]
	return t, ok
}

// GetTemplates 获取所有模板
func (l *TemplateLoader) GetTemplates() []*NucleiTemplate {
	l.mu.RLock()
	defer l.mu.RUnlock()

	templates := make([]*NucleiTemplate, 0, len(l.templates))
	for _, t := range l.templates {
		templates = append(templates, t)
	}
	return templates
}

// GetTemplatesByTags 根据标签获取模板
func (l *TemplateLoader) GetTemplatesByTags(tags ...string) []*NucleiTemplate {
	l.mu.RLock()
	defer l.mu.RUnlock()

	templates := make([]*NucleiTemplate, 0)
	for _, t := range l.templates {
		for _, tag := range tags {
			if strings.Contains(t.Info.Tags, tag) {
				templates = append(templates, t)
				break
			}
		}
	}
	return templates
}

// GetTemplatesBySeverity 根据严重程度获取模板
func (l *TemplateLoader) GetTemplatesBySeverity(severity Severity) []*NucleiTemplate {
	l.mu.RLock()
	defer l.mu.RUnlock()

	templates := make([]*NucleiTemplate, 0)
	for _, t := range l.templates {
		if t.Info.Severity == severity {
			templates = append(templates, t)
		}
	}
	return templates
}

// Count 获取模板数量
func (l *TemplateLoader) Count() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.templates)
}

// Clear 清空所有模板
func (l *TemplateLoader) Clear() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.templates = make(map[string]*NucleiTemplate)
}

// AddTemplate 添加单个模板
func (l *TemplateLoader) AddTemplate(template *NucleiTemplate) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.templates[template.ID] = template
}

// RemoveTemplate 移除模板
func (l *TemplateLoader) RemoveTemplate(id string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.templates, id)
}

// GetStatistics 获取模板统计
func (l *TemplateLoader) GetStatistics() map[string]int {
	l.mu.RLock()
	defer l.mu.RUnlock()

	stats := map[string]int{
		"total":    len(l.templates),
		"info":     0,
		"low":      0,
		"medium":   0,
		"high":     0,
		"critical": 0,
		"http":     0,
		"dns":      0,
		"tcp":      0,
		"headless": 0,
	}

	for _, t := range l.templates {
		switch t.Info.Severity {
		case SeverityInfo:
			stats["info"]++
		case SeverityLow:
			stats["low"]++
		case SeverityMedium:
			stats["medium"]++
		case SeverityHigh:
			stats["high"]++
		case SeverityCritical:
			stats["critical"]++
		}

		if len(t.HTTP) > 0 {
			stats["http"]++
		}
		if len(t.DNS) > 0 {
			stats["dns"]++
		}
		if len(t.TCP) > 0 {
			stats["tcp"]++
		}
		if len(t.Headless) > 0 {
			stats["headless"]++
		}
	}

	return stats
}

// GetAllTags 获取所有模板标签
func (l *TemplateLoader) GetAllTags() []string {
	l.mu.RLock()
	defer l.mu.RUnlock()

	tagSet := make(map[string]bool)
	for _, t := range l.templates {
		if t.Info.Tags != "" {
			// Tags 是逗号分隔的字符串
			for _, tag := range strings.Split(t.Info.Tags, ",") {
				tag = strings.TrimSpace(tag)
				if tag != "" {
					tagSet[tag] = true
				}
			}
		}
	}

	tags := make([]string, 0, len(tagSet))
	for tag := range tagSet {
		tags = append(tags, tag)
	}

	return tags
}
