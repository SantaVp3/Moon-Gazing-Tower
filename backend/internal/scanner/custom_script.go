package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/reconmaster/backend/internal/models"
)

// CustomScriptRunner 自定义脚本运行器
type CustomScriptRunner struct{}

// NewCustomScriptRunner 创建自定义脚本运行器
func NewCustomScriptRunner() *CustomScriptRunner {
	return &CustomScriptRunner{}
}

// ScriptResult 脚本执行结果
type ScriptResult struct {
	Vulnerabilities []VulnResult `json:"vulnerabilities"`
	Message         string       `json:"message"`
	Error           string       `json:"error"`
}

// VulnResult 漏洞结果
type VulnResult struct {
	URL         string `json:"url"`
	VulnType    string `json:"vuln_type"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Payload     string `json:"payload"`
	Proof       string `json:"proof"`
}

// RunScript 运行脚本
func (csr *CustomScriptRunner) RunScript(ctx *ScanContext, scriptPath string, targets []string) ([]*models.Vulnerability, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	ctx.Logger.Printf("Running custom script: %s on %d targets", scriptPath, len(targets))

	// 检查脚本文件是否存在
	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("script file not found: %s", scriptPath)
	}

	// 根据文件扩展名确定执行方式
	ext := strings.ToLower(filepath.Ext(scriptPath))
	
	var vulnerabilities []*models.Vulnerability
	var err error

	switch ext {
	case ".py":
		vulnerabilities, err = csr.runPythonScript(ctx, scriptPath, targets)
	case ".go":
		vulnerabilities, err = csr.runGoScript(ctx, scriptPath, targets)
	case ".sh":
		vulnerabilities, err = csr.runShellScript(ctx, scriptPath, targets)
	default:
		return nil, fmt.Errorf("unsupported script type: %s", ext)
	}

	if err != nil {
		return nil, err
	}

	ctx.Logger.Printf("Custom script completed, found %d vulnerabilities", len(vulnerabilities))
	return vulnerabilities, nil
}

// runPythonScript 运行Python脚本
func (csr *CustomScriptRunner) runPythonScript(ctx *ScanContext, scriptPath string, targets []string) ([]*models.Vulnerability, error) {
	// 创建临时JSON文件传递目标
	tmpFile, err := os.CreateTemp("", "script-targets-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	targetsJSON, _ := json.Marshal(map[string]interface{}{
		"targets": targets,
		"task_id": ctx.Task.ID,
	})
	tmpFile.Write(targetsJSON)
	tmpFile.Close()

	// 执行Python脚本
	cmd := exec.Command("python3", scriptPath, tmpFile.Name())
	
	// 设置超时
	cmdCtx, cancel := context.WithTimeout(ctx.Ctx, 30*time.Minute)
	defer cancel()
	cmd = exec.CommandContext(cmdCtx, "python3", scriptPath, tmpFile.Name())

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("script execution failed: %w, output: %s", err, string(output))
	}

	// 解析结果
	return csr.parseScriptOutput(ctx, output)
}

// runGoScript 运行Go脚本
func (csr *CustomScriptRunner) runGoScript(ctx *ScanContext, scriptPath string, targets []string) ([]*models.Vulnerability, error) {
	// Go脚本需要先编译
	scriptDir := filepath.Dir(scriptPath)
	binaryPath := filepath.Join(os.TempDir(), "custom-script-"+filepath.Base(scriptPath)+".bin")
	defer os.Remove(binaryPath)

	// 编译
	ctx.Logger.Printf("Compiling Go script: %s", scriptPath)
	compileCmd := exec.Command("go", "build", "-o", binaryPath, scriptPath)
	compileCmd.Dir = scriptDir
	if output, err := compileCmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("script compilation failed: %w, output: %s", err, string(output))
	}

	// 创建临时JSON文件传递目标
	tmpFile, err := os.CreateTemp("", "script-targets-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	targetsJSON, _ := json.Marshal(map[string]interface{}{
		"targets": targets,
		"task_id": ctx.Task.ID,
	})
	tmpFile.Write(targetsJSON)
	tmpFile.Close()

	// 执行编译后的二进制
	cmdCtx, cancel := context.WithTimeout(ctx.Ctx, 30*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, binaryPath, tmpFile.Name())

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("script execution failed: %w, output: %s", err, string(output))
	}

	// 解析结果
	return csr.parseScriptOutput(ctx, output)
}

// runShellScript 运行Shell脚本
func (csr *CustomScriptRunner) runShellScript(ctx *ScanContext, scriptPath string, targets []string) ([]*models.Vulnerability, error) {
	// 将目标作为参数传递
	args := append([]string{scriptPath}, targets...)
	
	cmdCtx, cancel := context.WithTimeout(ctx.Ctx, 30*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, "bash", args...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("script execution failed: %w, output: %s", err, string(output))
	}

	// 解析结果
	return csr.parseScriptOutput(ctx, output)
}

// parseScriptOutput 解析脚本输出
func (csr *CustomScriptRunner) parseScriptOutput(ctx *ScanContext, output []byte) ([]*models.Vulnerability, error) {
	// 期望脚本输出JSON格式的结果
	var result ScriptResult
	if err := json.Unmarshal(output, &result); err != nil {
		// 如果解析失败，尝试按行解析
		return csr.parseLineByLine(ctx, output)
	}

	// 检查是否有错误
	if result.Error != "" {
		return nil, fmt.Errorf("script error: %s", result.Error)
	}

	// 转换为漏洞模型
	var vulnerabilities []*models.Vulnerability
	for _, vulnResult := range result.Vulnerabilities {
		vuln := &models.Vulnerability{
			TaskID:      ctx.Task.ID,
			URL:         vulnResult.URL,
			VulnType:    vulnResult.VulnType,
			Severity:    vulnResult.Severity,
			Title:       vulnResult.Title,
			Description: vulnResult.Description,
			Payload:     vulnResult.Payload,
			Proof:       vulnResult.Proof,
			Source:      "custom_script",
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}

	return vulnerabilities, nil
}

// parseLineByLine 按行解析输出（每行一个JSON漏洞）
func (csr *CustomScriptRunner) parseLineByLine(ctx *ScanContext, output []byte) ([]*models.Vulnerability, error) {
	lines := strings.Split(string(output), "\n")
	var vulnerabilities []*models.Vulnerability

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var vulnResult VulnResult
		if err := json.Unmarshal([]byte(line), &vulnResult); err != nil {
			// 跳过非JSON行
			ctx.Logger.Printf("Skipping non-JSON line: %s", line)
			continue
		}

		vuln := &models.Vulnerability{
			TaskID:      ctx.Task.ID,
			URL:         vulnResult.URL,
			VulnType:    vulnResult.VulnType,
			Severity:    vulnResult.Severity,
			Title:       vulnResult.Title,
			Description: vulnResult.Description,
			Payload:     vulnResult.Payload,
			Proof:       vulnResult.Proof,
			Source:      "custom_script",
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}

	return vulnerabilities, nil
}


