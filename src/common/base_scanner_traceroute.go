package common

import (
	"dns_tools/config"
	"dns_tools/logging"
	"encoding/csv"
	"net"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"golang.org/x/net/ipv4"
	"golang.org/x/time/rate"
)

type stop struct{}

type IBase_methods interface {
	Handle_pkt(pkt gopacket.Packet)
}

type Scanner_traceroute struct {
	Wg               sync.WaitGroup
	Base_methods     IBase_methods
	Stop_chan        chan stop
	DNS_PAYLOAD_SIZE uint16
	Ip_chan          chan net.IP
	Waiting_to_end   bool
	Send_limiter     *rate.Limiter
	Raw_con          *ipv4.RawConn
	Writer           *csv.Writer
}

func (st *Scanner_traceroute) Base_init() {
	st.Stop_chan = make(chan stop) // (〃・ω・〃)
	st.Ip_chan = make(chan net.IP, 1024)
	st.Waiting_to_end = false
	st.Send_limiter = rate.NewLimiter(rate.Every(time.Duration(1000000/config.Cfg.Pkts_per_sec)*time.Microsecond), 1)
}

func (st *Scanner_traceroute) Packet_capture(handle *pcapgo.EthernetHandle) {
	defer st.Wg.Done()
	logging.Println(3, nil, "starting packet capture")
	pkt_src := gopacket.NewPacketSource(
		handle, layers.LinkTypeEthernet).Packets()
	for {
		select {
		case pkt := <-pkt_src:
			go st.Base_methods.Handle_pkt(pkt)
		case <-st.Stop_chan:
			logging.Println(3, nil, "stopping packet capture")
			return
		}
	}
}

// handle ctrl+c SIGINT
func (st *Scanner_traceroute) Handle_ctrl_c() {
	interrupt_chan := make(chan os.Signal, 1)
	signal.Notify(interrupt_chan, os.Interrupt)
	<-interrupt_chan
	if st.Waiting_to_end {
		logging.Println(3, nil, "already ending")
	} else {
		logging.Println(3, nil, "received SIGINT, ending")
		close(st.Stop_chan)
	}
}

func (st *Scanner_traceroute) Close_handle(handle *pcapgo.EthernetHandle) {
	defer st.Wg.Done()
	<-st.Stop_chan
	logging.Println(3, nil, "closing handle")
	handle.Close()
	logging.Println(3, nil, "handle closed")
}
