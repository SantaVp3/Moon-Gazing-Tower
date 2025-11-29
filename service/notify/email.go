package notify

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/smtp"
	"strings"
)

// EmailNotifier 邮件通知
type EmailNotifier struct {
	host     string
	port     int
	user     string
	password string
	from     string
	to       []string
}

// NewEmailNotifier 创建邮件通知器
func NewEmailNotifier(host string, port int, user, password, from string, to []string) *EmailNotifier {
	return &EmailNotifier{
		host:     host,
		port:     port,
		user:     user,
		password: password,
		from:     from,
		to:       to,
	}
}

func (n *EmailNotifier) Type() NotifyType {
	return NotifyTypeEmail
}

func (n *EmailNotifier) Send(ctx context.Context, msg *NotifyMessage) error {
	subject := fmt.Sprintf("[%s] %s", msg.Level, msg.Title)
	
	// 构建 HTML 邮件内容
	body := n.buildHTMLBody(msg)
	
	// 构建邮件头
	headers := make(map[string]string)
	headers["From"] = n.from
	headers["To"] = strings.Join(n.to, ",")
	headers["Subject"] = subject
	headers["MIME-Version"] = "1.0"
	headers["Content-Type"] = "text/html; charset=UTF-8"
	
	var message strings.Builder
	for k, v := range headers {
		message.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	message.WriteString("\r\n")
	message.WriteString(body)
	
	// 发送邮件
	return n.sendMail(message.String())
}

func (n *EmailNotifier) buildHTMLBody(msg *NotifyMessage) string {
	color := "#3b82f6" // info - blue
	switch msg.Level {
	case NotifyLevelCritical:
		color = "#ef4444" // red
	case NotifyLevelWarning:
		color = "#f97316" // orange
	}
	
	return fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: %s; color: white; padding: 20px; border-radius: 8px 8px 0 0; }
        .content { background: #f9fafb; padding: 20px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 8px 8px; }
        .info { color: #6b7280; font-size: 14px; margin-bottom: 16px; }
        .message { background: white; padding: 16px; border-radius: 4px; border: 1px solid #e5e7eb; }
        .footer { text-align: center; color: #9ca3af; font-size: 12px; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2 style="margin: 0;">%s</h2>
        </div>
        <div class="content">
            <div class="info">
                <strong>级别:</strong> %s &nbsp;&nbsp;
                <strong>来源:</strong> %s &nbsp;&nbsp;
                <strong>时间:</strong> %s
            </div>
            <div class="message">
                %s
            </div>
        </div>
        <div class="footer">
            Moon Gazing Tower 安全扫描平台
        </div>
    </div>
</body>
</html>
`, color, msg.Title, msg.Level, msg.Source, msg.Timestamp.Format("2006-01-02 15:04:05"), 
		strings.ReplaceAll(msg.Content, "\n", "<br>"))
}

func (n *EmailNotifier) sendMail(message string) error {
	addr := fmt.Sprintf("%s:%d", n.host, n.port)
	
	auth := smtp.PlainAuth("", n.user, n.password, n.host)
	
	// 对于 SSL/TLS 端口 (465)，需要特殊处理
	if n.port == 465 {
		return n.sendMailTLS(addr, auth, message)
	}
	
	// 对于 STARTTLS 端口 (587) 或普通端口 (25)
	return smtp.SendMail(addr, auth, n.from, n.to, []byte(message))
}

func (n *EmailNotifier) sendMailTLS(addr string, auth smtp.Auth, message string) error {
	tlsConfig := &tls.Config{
		ServerName: n.host,
	}
	
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return err
	}
	defer conn.Close()
	
	client, err := smtp.NewClient(conn, n.host)
	if err != nil {
		return err
	}
	defer client.Close()
	
	if err := client.Auth(auth); err != nil {
		return err
	}
	
	if err := client.Mail(n.from); err != nil {
		return err
	}
	
	for _, to := range n.to {
		if err := client.Rcpt(to); err != nil {
			return err
		}
	}
	
	w, err := client.Data()
	if err != nil {
		return err
	}
	
	_, err = w.Write([]byte(message))
	if err != nil {
		return err
	}
	
	err = w.Close()
	if err != nil {
		return err
	}
	
	return client.Quit()
}
