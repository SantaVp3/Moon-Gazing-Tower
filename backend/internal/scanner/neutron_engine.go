package scanner

import (
	"fmt"
	"log"

	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/neutron/templates"
	"github.com/reconmaster/backend/internal/models"
	"gopkg.in/yaml.v3"
)

// NeutronEngine Neutron引擎包装器
type NeutronEngine struct {
	options *protocols.ExecuterOptions
}

// NewNeutronEngine 创建Neutron引擎
func NewNeutronEngine() *NeutronEngine {
	return &NeutronEngine{
		options: &protocols.ExecuterOptions{
			Options: &protocols.Options{
				Timeout: 30,
			},
		},
	}
}

// NeutronResult Neutron执行结果
type NeutronResult struct {
	Vulnerable    bool
	TemplateID    string
	MatcherName   string
	ExtractedData []string
	Message       string
	Details       string
}

// ExecutePoC 使用Neutron执行PoC
func (ne *NeutronEngine) ExecutePoC(poc *models.PoC, target string) (*NeutronResult, error) {
	// 解析 PoC 模板
	tmpl := &templates.Template{}
	if err := yaml.Unmarshal([]byte(poc.PoCContent), tmpl); err != nil {
		return nil, fmt.Errorf("failed to parse template: %w", err)
	}

	// 编译模板
	if err := tmpl.Compile(ne.options); err != nil {
		return nil, fmt.Errorf("failed to compile template: %w", err)
	}

	// 执行模板
	result, err := tmpl.Execute(target, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to execute template: %w", err)
	}

	// 转换结果
	neutronResult := &NeutronResult{
		Vulnerable: result.Matched,
		TemplateID: tmpl.Id,
		Message:    "No vulnerabilities detected",
	}

	if result.Matched {
		// 收集匹配的规则名称
		var matcherNames []string
		for matcherName := range result.Matches {
			matcherNames = append(matcherNames, matcherName)
		}
		if len(matcherNames) > 0 {
			neutronResult.MatcherName = matcherNames[0]
		}

		// 收集提取的数据
		var extracted []string
		for _, values := range result.Extracts {
			extracted = append(extracted, values...)
		}
		neutronResult.ExtractedData = extracted

		neutronResult.Message = fmt.Sprintf("Vulnerability detected: %s", neutronResult.MatcherName)
		neutronResult.Details = fmt.Sprintf("Template: %s, Matched: %v", tmpl.Id, matcherNames)
	}

	return neutronResult, nil
}

// ExecutePoCBatch 批量执行PoC
func (ne *NeutronEngine) ExecutePoCBatch(pocs []*models.PoC, targets []string) (map[string][]*NeutronResult, error) {
	results := make(map[string][]*NeutronResult)

	// 解析所有模板
	var tmpls []*templates.Template
	for _, poc := range pocs {
		tmpl := &templates.Template{}
		if err := yaml.Unmarshal([]byte(poc.PoCContent), tmpl); err != nil {
			log.Printf("Warning: Failed to parse template %s: %v", poc.Name, err)
			continue
		}

		if err := tmpl.Compile(ne.options); err != nil {
			log.Printf("Warning: Failed to compile template %s: %v", poc.Name, err)
			continue
		}

		tmpls = append(tmpls, tmpl)
	}

	if len(tmpls) == 0 {
		return results, fmt.Errorf("no valid templates to execute")
	}

	// 对每个目标执行所有模板
	for _, target := range targets {
		for _, tmpl := range tmpls {
			result, err := tmpl.Execute(target, nil)
			if err != nil {
				log.Printf("Warning: Failed to execute template %s on %s: %v", tmpl.Id, target, err)
				continue
			}

			neutronResult := &NeutronResult{
				Vulnerable: result.Matched,
				TemplateID: tmpl.Id,
				Message:    "No vulnerabilities detected",
			}

			if result.Matched {
				var matcherNames []string
				for matcherName := range result.Matches {
					matcherNames = append(matcherNames, matcherName)
				}
				if len(matcherNames) > 0 {
					neutronResult.MatcherName = matcherNames[0]
				}

				var extracted []string
				for _, values := range result.Extracts {
					extracted = append(extracted, values...)
				}
				neutronResult.ExtractedData = extracted

				neutronResult.Message = fmt.Sprintf("Vulnerability detected: %s", neutronResult.MatcherName)
				neutronResult.Details = fmt.Sprintf("Template: %s, Matched: %v", tmpl.Id, matcherNames)
			}

			results[target] = append(results[target], neutronResult)
		}
	}

	return results, nil
}

// SetTimeout 设置超时时间
func (ne *NeutronEngine) SetTimeout(timeout int) {
	ne.options.Options.Timeout = timeout
}

