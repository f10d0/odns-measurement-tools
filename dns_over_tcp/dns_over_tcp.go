package dns_over_tcp

import (
	"compress/gzip"
	"encoding/csv"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"

	"golang.org/x/net/ipv4"

	"github.com/breml/bpfutils"
	"golang.org/x/time/rate"

	"dns_tools/common"
	"dns_tools/config"
	"dns_tools/generator"
	"dns_tools/logging"
)

var raw_con *ipv4.RawConn

var send_limiter *rate.Limiter

var DNS_PAYLOAD_SIZE uint16

/*	id:
*	(seq-num)		(Ports from 61440)   	(2048 byte padding)
*	2^32	*			2^11			/			 2^11		=2^32
*
*	increment: |y=11*x | z=21*x|
*	seq_num = z*2^11, max:2^32-2^11
*	port = y+15<<15 = y+61440
 */

// this struct contains all relevant data to track the tcp connection
type scan_data_item struct {
	id       uint32
	ts       time.Time
	ip       net.IP
	port     layers.TCPPort
	seq      uint32
	ack      uint32
	flags    TCP_flags
	dns_recs []net.IP
	Next     *scan_data_item
}

func (item *scan_data_item) last() *scan_data_item {
	var cur *scan_data_item = item
	for cur.Next != nil {
		cur = cur.Next
	}
	return cur
}

// key for the map below
type scan_item_key struct {
	port layers.TCPPort
	seq  uint32
}

// map to track tcp connections, key is a tuple of (port, seq)
type root_scan_data struct {
	mu    sync.Mutex
	items map[scan_item_key]*scan_data_item
}

var scan_data root_scan_data = root_scan_data{
	items: make(map[scan_item_key]*scan_data_item),
}

var write_chan = make(chan *scan_data_item, 4096)

func scan_item_to_strarr(scan_item *scan_data_item) []string {
	// transform scan_item into string array for csv writer
	var record []string
	record = append(record, strconv.Itoa(int(scan_item.id)))
	record = append(record, scan_item.ts.UTC().Format("2006-01-02 15:04:05.000000"))
	record = append(record, scan_item.ip.String())
	record = append(record, scan_item.port.String())
	record = append(record, strconv.Itoa(int(scan_item.seq)))
	record = append(record, strconv.Itoa(int(scan_item.ack)))
	var flags string
	if scan_item.flags.SYN {
		flags += "S"
	}
	if scan_item.flags.RST {
		flags += "R"
	}
	if scan_item.flags.FIN {
		flags += "F"
	}
	if scan_item.flags.PSH {
		flags += "P"
	}
	if scan_item.flags.ACK {
		flags += "A"
	}
	record = append(record, flags)
	dns_answers := ""
	for i, dns_ip := range scan_item.dns_recs {
		dns_answers += dns_ip.String()
		if i != len(scan_item.dns_recs)-1 {
			dns_answers += ","
		}
	}
	record = append(record, dns_answers)
	return record
}

func write_results() {
	defer common.Wg.Done()
	csvfile, err := os.Create("tcp_results.csv.gz")
	if err != nil {
		panic(err)
	}
	defer csvfile.Close()

	zip_writer := gzip.NewWriter(csvfile)
	defer zip_writer.Close()

	writer := csv.NewWriter(zip_writer)
	writer.Comma = ';'
	defer writer.Flush()

	for {
		select {
		case root_item := <-write_chan:
			scan_item := root_item
			for scan_item != nil {
				writer.Write(scan_item_to_strarr(scan_item))
				scan_item = scan_item.Next
			}
			// remove entry from map
			scan_data.mu.Lock()
			delete(scan_data.items, scan_item_key{root_item.port, root_item.seq})
			scan_data.mu.Unlock()
		case <-common.Stop_chan:
			return
		}
	}
}

// periodically remove keys (=connections) that get no response from map
func timeout() {
	defer common.Wg.Done()
	for {
		select {
		case <-time.After(10 * time.Second):
			//go through map's keyset
			scan_data.mu.Lock()
			for k, v := range scan_data.items {
				//remove each key where its timestamp is older than x seconds
				if time.Now().Unix()-v.ts.Unix() > 10 {
					delete(scan_data.items, k)
				}
			}
			scan_data.mu.Unlock()
		case <-common.Stop_chan:
			return
		}
	}
}

var opts gopacket.SerializeOptions = gopacket.SerializeOptions{
	ComputeChecksums: true,
	FixLengths:       true,
}

func send_tcp_pkt(ip layers.IPv4, tcp layers.TCP, payload []byte) {
	ip_head_buf := gopacket.NewSerializeBuffer()
	err := ip.SerializeTo(ip_head_buf, opts)
	if err != nil {
		panic(err)
	}
	ip_head, err := ipv4.ParseHeader(ip_head_buf.Bytes())
	if err != nil {
		panic(err)
	}

	tcp_buf := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(tcp_buf, opts, &tcp, gopacket.Payload(payload))
	if err != nil {
		panic(err)
	}

	if err = raw_con.WriteTo(ip_head, tcp_buf.Bytes(), nil); err != nil {
		panic(err)
	}
}

func build_ack_with_dns(dst_ip net.IP, src_port layers.TCPPort, seq_num uint32, ack_num uint32) (layers.IPv4, layers.TCP, []byte) {
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
		PSH:     true,
		Seq:     ack_num,
		Ack:     seq_num + 1,
		Window:  8192,
	}
	tcp.SetNetworkLayerForChecksum(&ip)

	// create dns layers
	qst := layers.DNSQuestion{
		Name:  []byte(config.Cfg.Dns_query),
		Type:  layers.DNSTypeA,
		Class: layers.DNSClassIN,
	}
	dns := layers.DNS{
		Questions: []layers.DNSQuestion{qst},
		RD:        true,
		QDCount:   1,
		OpCode:    layers.DNSOpCodeQuery,
		ID:        uint16(rand.Intn(65536)),
	}

	dns_buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(dns_buf, gopacket.SerializeOptions{}, &dns)
	// prepend dns payload with its size, as gopacket does not do this automatically
	dns_buf_bytes := dns_buf.Bytes()
	dns_corrected := make([]byte, len(dns_buf_bytes)+2)
	dns_corrected[0] = uint8(0)
	dns_corrected[1] = uint8(len(dns_buf_bytes))
	for i := 0; i < len(dns_buf_bytes); i++ {
		dns_corrected[i+2] = dns_buf_bytes[i]
	}
	return ip, tcp, dns_corrected
}

func send_ack_with_dns(dst_ip net.IP, src_port layers.TCPPort, seq_num uint32, ack_num uint32) {
	send_tcp_pkt(build_ack_with_dns(dst_ip, src_port, seq_num, ack_num))
}

func send_ack_pos_fin(dst_ip net.IP, src_port layers.TCPPort, seq_num uint32, ack_num uint32, fin bool) {
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
	send_tcp_pkt(ip, tcp, nil)
}

func handle_pkt(pkt gopacket.Packet) {
	ip_layer := pkt.Layer(layers.LayerTypeIPv4)
	if ip_layer == nil {
		return
	}
	ip, ok := ip_layer.(*layers.IPv4)
	if !ok {
		return
	}

	tcp_layer := pkt.Layer(layers.LayerTypeTCP)
	if tcp_layer == nil {
		return
	}
	tcp, ok := tcp_layer.(*layers.TCP)
	if !ok { // skip wrong packets
		return
	}
	tcpflags := TCP_flags{
		PSH: tcp.PSH,
		FIN: tcp.FIN,
		SYN: tcp.SYN,
		RST: tcp.RST,
		ACK: tcp.ACK,
	}
	if pkt.ApplicationLayer() == nil {
		// SYN-ACK
		if tcpflags.is_SYN_ACK() {
			logging.Println(5, nil, "received SYN-ACK")
			// check if item in map and assign value
			scan_data.mu.Lock()
			root_data_item, ok := scan_data.items[scan_item_key{tcp.DstPort, tcp.Ack - 1}]
			scan_data.mu.Unlock()
			if !ok {
				return
			}
			last_data_item := root_data_item.last()
			// this should not occur, this would be the case if a syn-ack is being received more than once
			if last_data_item != root_data_item {
				return
			}
			data := scan_data_item{
				id:   last_data_item.id,
				ts:   time.Now(),
				port: tcp.DstPort,
				seq:  tcp.Seq,
				ack:  tcp.Ack,
				ip:   ip.SrcIP,
				flags: TCP_flags{
					FIN: tcp.FIN,
					SYN: tcp.SYN,
					RST: tcp.RST,
					PSH: tcp.PSH,
					ACK: tcp.ACK,
				},
			}
			last_data_item.Next = &data
			send_ack_with_dns(root_data_item.ip, tcp.DstPort, tcp.Seq, tcp.Ack)
		} else
		// FIN-ACK
		if tcpflags.is_FIN_ACK() {
			logging.Println(5, nil, "received FIN-ACK")
			scan_data.mu.Lock()
			root_data_item, ok := scan_data.items[scan_item_key{tcp.DstPort, tcp.Ack - 2 - uint32(DNS_PAYLOAD_SIZE)}]
			scan_data.mu.Unlock()
			if !ok {
				return
			}

			last_data_item := root_data_item.last()
			if !(last_data_item.flags.is_PSH_ACK()) {
				logging.Println(5, nil, "missing PSH-ACK, dropping")
				send_ack_pos_fin(ip.SrcIP, tcp.DstPort, tcp.Seq, tcp.Ack, true)
				return
			}
			logging.Println(5, nil, "ACKing FIN-ACK")
			send_ack_pos_fin(root_data_item.ip, tcp.DstPort, tcp.Seq, tcp.Ack, false)
			write_chan <- root_data_item
		}
	} else
	// PSH-ACK || FIN-PSH-ACK == DNS Response
	if tcpflags.is_PSH_ACK() || tcpflags.is_FIN_PSH_ACK() {
		logging.Println(5, nil, "received PSH-ACK or FIN-PSH-ACK")
		// decode as DNS Packet
		dns := &layers.DNS{}
		// remove the first two bytes of the payload, i.e. size of the dns response
		// see build_ack_with_dns()
		if len(tcp.LayerPayload()) <= 2 {
			return
		}
		// validate payload size
		pld_size := int(tcp.LayerPayload()[0]) + int(tcp.LayerPayload()[1])<<8
		if pld_size == len(tcp.LayerPayload())-2 {
			return
		}
		pld := make([]byte, len(tcp.LayerPayload())-2)
		for i := 0; i < len(pld); i++ {
			pld[i] = tcp.LayerPayload()[i+2]
		}
		err := dns.DecodeFromBytes(pld, gopacket.NilDecodeFeedback)
		if err != nil {
			logging.Println(5, nil, "DNS not found")
			return
		}
		logging.Println(4, nil, "got DNS response")
		// check if item in map and assign value
		scan_data.mu.Lock()
		root_data_item, ok := scan_data.items[scan_item_key{tcp.DstPort, tcp.Ack - 1 - uint32(DNS_PAYLOAD_SIZE)}]
		scan_data.mu.Unlock()
		if !ok {
			return
		}
		last_data_item := root_data_item.last()
		// this should not occur, this would be the case if a psh-ack is being received more than once
		if last_data_item.flags.is_PSH_ACK() {
			logging.Println(5, nil, "already received PSH-ACK")
			return
		}
		if !(last_data_item.flags.is_SYN_ACK()) {
			logging.Println(5, nil, "missing SYN-ACK")
			return
		}
		answers := dns.Answers
		var answers_ip []net.IP
		for _, answer := range answers {
			if answer.IP != nil {
				answers_ip = append(answers_ip, answer.IP)
				logging.Println(6, nil, answer.IP)
			} else {
				logging.Println(5, nil, "non IP type found in answer")
				return
			}
		}
		data := scan_data_item{
			id:   last_data_item.id,
			ts:   time.Now(),
			port: tcp.DstPort,
			seq:  tcp.Seq,
			ack:  tcp.Ack,
			ip:   ip.SrcIP,
			flags: TCP_flags{
				FIN: tcp.FIN,
				SYN: tcp.SYN,
				RST: tcp.RST,
				PSH: tcp.PSH,
				ACK: tcp.ACK,
			},
			dns_recs: answers_ip,
		}
		last_data_item.Next = &data
		// send FIN-ACK to server
		send_ack_pos_fin(root_data_item.ip, tcp.DstPort, tcp.Seq, tcp.Ack, true)
		// if this pkt is fin-psh-ack we will remove it from the map at this point already
		// because we wont receive any further fin-ack from the server
		if tcpflags.is_FIN_PSH_ACK() {
			write_chan <- root_data_item
		}
	}
}

func packet_capture(handle *pcapgo.EthernetHandle) {
	defer common.Wg.Done()
	logging.Println(3, nil, "starting packet capture")
	pkt_src := gopacket.NewPacketSource(
		handle, layers.LinkTypeEthernet).Packets()
	for {
		select {
		case pkt := <-pkt_src:
			go handle_pkt(pkt)
		case <-common.Stop_chan:
			logging.Println(3, nil, "stopping packet capture")
			return
		}
	}
}

func send_syn(id uint32, dst_ip net.IP) {
	// generate sequence number based on the first 21 bits of the hash
	seq := (id & 0x1FFFFF) * 2048
	port := layers.TCPPort(((id & 0xFFE00000) >> 21) + 61440)
	logging.Println(6, nil, dst_ip, "seq_num=", seq)
	// check for sequence number collisions
	scan_data.mu.Lock()
	s_d_item := scan_data_item{
		id:   id,
		ts:   time.Now(),
		ip:   dst_ip,
		port: port,
		seq:  seq,
		ack:  0,
		flags: TCP_flags{
			FIN: false,
			ACK: false,
			RST: false,
			PSH: false,
			SYN: true,
		},
		dns_recs: nil,
		Next:     nil,
	}
	logging.Println(6, nil, "scan_data=", s_d_item)
	scan_data.items[scan_item_key{port, seq}] = &s_d_item
	scan_data.mu.Unlock()

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
		SrcPort: port,
		DstPort: 53,
		SYN:     true,
		Seq:     seq,
		Ack:     0,
	}
	tcp.SetNetworkLayerForChecksum(&ip)

	send_tcp_pkt(ip, tcp, nil)
}

type u32id struct {
	mu sync.Mutex
	id uint32
}

// id for saving to results file, synced between multiple init_tcp()
var ip_loop_id u32id = u32id{
	id: 0,
}

func get_next_id() uint32 {
	ip_loop_id.mu.Lock()
	defer ip_loop_id.mu.Unlock()
	ip_loop_id.id += 1
	return ip_loop_id.id
}

func init_tcp() {
	defer common.Wg.Done()
	for {
		select {
		case dst_ip := <-common.Ip_chan:
			// check if ip is excluded in the blocklist
			should_exclude := false
			for _, blocked_net := range common.Blocked_nets {
				if blocked_net.Contains(dst_ip) {
					should_exclude = true
					break
				}
			}
			if should_exclude {
				logging.Println(3, nil, "excluding ip:", dst_ip)
				continue
			}
			id := get_next_id()
			logging.Println(6, nil, "ip:", dst_ip, id)
			r := send_limiter.Reserve()
			if !r.OK() {
				logging.Println(4, nil, "Rate limit exceeded")
			}
			time.Sleep(r.Delay())
			send_syn(id, dst_ip)
		case <-common.Stop_chan:
			return
		}
	}
}

func close_handle(handle *pcapgo.EthernetHandle) {
	defer common.Wg.Done()
	<-common.Stop_chan
	logging.Println(3, nil, "closing handle")
	handle.Close()
	logging.Println(3, nil, "handle closed")
}

func Start_scan(config_path string, args []string) {
	// before running the script run below iptables command so that kernel doesn't send out RSTs
	// sudo iptables -C OUTPUT -p tcp --tcp-flags RST RST -j DROP > /dev/null || sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

	// write start ts to log
	logging.Write_to_runlog("START " + time.Now().UTC().String())
	// command line args
	if len(args) < 1 {
		logging.Write_to_runlog("END " + time.Now().UTC().String() + " arg not given")
		logging.Println(1, nil, "ERR need filename or net in CIDR notation")
		return
	}
	var fname string
	var netip net.IP
	var hostsize int
	fname, netip, hostsize = common.Get_cidr_filename(args[0])

	go common.Handle_ctrl_c()

	common.Exclude_ips()
	send_limiter = rate.NewLimiter(rate.Every(time.Duration(1000000/config.Cfg.Pkts_per_sec)*time.Microsecond), 1)
	// set the DNS_PAYLOAD_SIZE once as it is static
	_, _, dns_payload := build_ack_with_dns(net.ParseIP("0.0.0.0"), 0, 0, 0)
	DNS_PAYLOAD_SIZE = uint16(len(dns_payload))
	// start packet capture
	handle, err := pcapgo.NewEthernetHandle(config.Cfg.Iface_name)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	iface, err := net.InterfaceByName(config.Cfg.Iface_name)
	if err != nil {
		panic(err)
	}
	bpf_instr, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, iface.MTU, fmt.Sprint("tcp and ip dst ", config.Cfg.Iface_ip, " and src port 53"))
	if err != nil {
		panic(err)
	}
	bpf_raw := bpfutils.ToBpfRawInstructions(bpf_instr)
	if err := handle.SetBPF(bpf_raw); err != nil {
		panic(err)
	}
	// create raw l3 socket
	var pkt_con net.PacketConn
	pkt_con, err = net.ListenPacket("ip4:tcp", config.Cfg.Iface_ip)
	if err != nil {
		panic(err)
	}
	raw_con, err = ipv4.NewRawConn(pkt_con)
	if err != nil {
		panic(err)
	}

	// start packet capture as goroutine
	common.Wg.Add(5)
	go packet_capture(handle)
	go write_results()
	go timeout()
	if fname != "" {
		logging.Println(3, nil, "running in filename mode")
		go common.Read_ips_file(fname)
	} else {
		logging.Println(3, nil, "running in CIDR mode")
		go generator.Gen_ips(netip, hostsize)
	}
	for i := 0; i < 8; i++ {
		common.Wg.Add(1)
		go init_tcp()
	}
	go close_handle(handle)
	common.Wg.Wait()
	logging.Println(3, nil, "all routines finished")
	logging.Write_to_runlog("[TCP SCAN] END " + time.Now().UTC().String())
	logging.Println(3, nil, "program done")
}
