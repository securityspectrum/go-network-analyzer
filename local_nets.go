// File: local_nets.go

package main

import (
	"net"
)

var localNetworks = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"224.0.0.0/4",
	"::1/128",
	"fe80::/10",
	"fc00::/7",
}

var localNets []*net.IPNet

func init() {
	for _, cidr := range localNetworks {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(err)
		}
		localNets = append(localNets, ipnet)
	}
}

func isLocalIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	for _, network := range localNets {
		if network.Contains(parsedIP) {
			return true
		}
	}
	return false
}
