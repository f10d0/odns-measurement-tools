package util

import (
	"encoding/binary"
	"net"
)

func ip42int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func int2ip4(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}
