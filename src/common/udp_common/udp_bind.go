package udp_common

import (
	"dns_tools/config"
	"dns_tools/logging"
	"net"
)

type Udp_binder struct {
	bound_sockets []*net.UDPConn
}

// binding all the sockets potentially in use by the scanner
// so no icmp port unreachable is sent and no other application
// may use these ports by chance
func (binder *Udp_binder) Bind_ports() {
	logging.Println(3, nil, "Binding ports")
	var port uint32
	for port = (uint32)(config.Cfg.Port_min); port <= (uint32)(config.Cfg.Port_max); port++ {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{
			IP:   net.ParseIP(config.Cfg.Iface_ip),
			Port: (int)(port),
		})
		if err != nil {
			logging.Println(2, nil, "Could not bind to UDP port", port)
			logging.Println(2, nil, "reason:", err)
			// TODO should then probably exclude these from the scan
		} else {
			binder.bound_sockets = append(binder.bound_sockets, conn)
		}
	}
}

func (binder *Udp_binder) Unbind_ports() {
	logging.Println(3, nil, "Unbinding ports")
	for _, sock := range binder.bound_sockets {
		sock.Close()
	}
}
