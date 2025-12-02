package service

import "net"

// isIPAddress 判断是否为 IP 地址
func isIPAddress(s string) bool {
	return net.ParseIP(s) != nil
}
