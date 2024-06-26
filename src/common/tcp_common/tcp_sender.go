package tcp_common

import (
	"dns_tools/common"
	"dns_tools/config"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Tcp_sender struct {
	L2_sender *common.RawL2
}

func (sender *Tcp_sender) Send_tcp_pkt(ip layers.IPv4, tcp layers.TCP, payload []byte) {
	tcp_buf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(tcp_buf, common.Opts, &ip, &tcp, gopacket.Payload(payload))
	if err != nil {
		panic(err)
	}

	sender.L2_sender.Send(tcp_buf.Bytes())
}

func (sender *Tcp_sender) Send_ack_pos_fin(dst_ip net.IP, src_port layers.TCPPort, seq_num uint32, ack_num uint32, fin bool) {
	// === build packet ===
	// Create ip layer
	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    net.ParseIP(config.Cfg.Iface_ip),
		DstIP:    dst_ip,
		Protocol: layers.IPProtocolTCP,
		Id:       1,
	}

	// Create tcp layer
	tcp := layers.TCP{
		SrcPort: src_port,
		DstPort: layers.TCPPort(config.Cfg.Dst_port),
		ACK:     true,
		FIN:     fin,
		Seq:     ack_num,
		Ack:     seq_num + 1,
		Window:  8192,
	}
	tcp.SetNetworkLayerForChecksum(&ip)
	sender.Send_tcp_pkt(ip, tcp, nil)
}
