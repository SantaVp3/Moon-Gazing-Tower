package scanner

// PortScanResult 端口扫描结果
type PortScanResult struct {
	IP       string
	Port     int
	Protocol string
	Open     bool
	Service  string
	Version  string // 服务版本（通过gonmap识别）
	Product  string // 产品名称（通过gonmap识别）
	Banner   string
}

// getCommonPortServices 获取常见端口和服务映射 (共享函数)
func getCommonPortServices() map[int]string {
	return map[int]string{
		// Web服务
		80:   "http",
		443:  "https",
		8000: "http-alt",
		8008: "http-alt",
		8080: "http-proxy",
		8081: "http-alt",
		8088: "http-alt",
		8443: "https-alt",
		8888: "http-alt",
		9000: "http-alt",

		// 数据库
		3306:  "mysql",
		5432:  "postgresql",
		1433:  "mssql",
		1521:  "oracle",
		27017: "mongodb",
		27018: "mongodb-shard",
		6379:  "redis",
		11211: "memcached",
		9200:  "elasticsearch",
		9300:  "elasticsearch-cluster",

		// 远程访问
		22:   "ssh",
		23:   "telnet",
		3389: "rdp",
		5900: "vnc",
		5901: "vnc",

		// 邮件服务
		25:  "smtp",
		110: "pop3",
		143: "imap",
		465: "smtps",
		587: "submission",
		993: "imaps",
		995: "pop3s",

		// 文件服务
		21:   "ftp",
		20:   "ftp-data",
		69:   "tftp",
		139:  "netbios-ssn",
		445:  "smb",
		2049: "nfs",

		// DNS和目录服务
		53:  "dns",
		389: "ldap",
		636: "ldaps",

		// 中间件和应用服务器
		8009: "ajp13",
		8161: "activemq",
		9043: "websphere-admin",
		7001: "weblogic",
		7002: "weblogic-ssl",
		9080: "websphere",
		9090: "websphere-admin",

		// 消息队列
		5672:  "amqp/rabbitmq",
		61616: "activemq",
		9092:  "kafka",
		4369:  "rabbitmq-epmd",

		// 容器和编排
		2375:  "docker",
		2376:  "docker-ssl",
		6443:  "kubernetes-api",
		10250: "kubelet",

		// 其他常见服务
		161:   "snmp",
		162:   "snmptrap",
		514:   "syslog",
		873:   "rsync",
		1080:  "socks",
		1883:  "mqtt",
		3000:  "grafana",
		3128:  "squid-proxy",
		4848:  "glassfish-admin",
		5000:  "docker-registry",
		5984:  "couchdb",
		6000:  "x11",
		7000:  "afs3-fileserver",
		7070:  "realserver",
		9091:  "xmltec-xmlmail",
		10000: "webmin",
		50000: "db2",
		50070: "hadoop-namenode",
	}
}

// min 返回两个整数中的较小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
