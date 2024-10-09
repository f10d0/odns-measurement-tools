package udpscanner

import (
	"dns_tools/common"
	"dns_tools/common/udp_common"
	"dns_tools/config"
	"dns_tools/generator"
	"dns_tools/logging"
	"dns_tools/scanner"
	"fmt"
	"log"
	"math"
	"math/rand"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/time/rate"
)

type Udp_scanner struct {
	scanner.Base_scanner
	udp_common.Udp_sender
	udp_common.Udp_binder
	// slice for sockets that will be bound on program start
	bound_sockets []*net.UDPConn
	ip_loop_id    synced_init
}

// lockable datastructure for the init phase
type synced_init struct {
	mu    sync.Mutex
	id    uint32
	port  uint16
	dnsid uint16
}

func (udps *Udp_scanner) update_sync_init() (uint32, uint16, uint16) {
	udps.ip_loop_id.mu.Lock()
	defer udps.ip_loop_id.mu.Unlock()
	udps.ip_loop_id.id += 1
	if (uint32)(udps.ip_loop_id.dnsid)+1 > 0xFFFF {
		udps.ip_loop_id.dnsid = 0
		// restart at the beginning of the port range
		if (uint32)(udps.ip_loop_id.port)+1 > (uint32)(config.Cfg.Port_max) {
			udps.ip_loop_id.port = config.Cfg.Port_min
		} else {
			udps.ip_loop_id.port += 1
		}
	} else {
		udps.ip_loop_id.dnsid += 1
	}
	return udps.ip_loop_id.id, udps.ip_loop_id.port, udps.ip_loop_id.dnsid
}

// this struct contains all relevant data to track the dns query & response
type Udp_scan_data_item struct {
	Id       uint32
	Ts       time.Time
	Ip       net.IP
	Answerip net.IP
	Port     layers.UDPPort
	Dnsid    uint16
	Dns_recs []net.IP
}

func (u *Udp_scan_data_item) Get_timestamp() time.Time {
	return u.Ts
}

func (u *Udp_scan_data_item) String() string {
	var dns_rec string = ""
	for _, rec := range u.Dns_recs {
		dns_rec += rec.String() + " "
	}
	return fmt.Sprintf("Item %d: Request-IP %s, Answer-IP %s, DNS-Recs %s", u.Id, u.Ip.String(), u.Answerip.String(), dns_rec)
}

// key for the map below
type udp_scan_item_key struct {
	port  layers.UDPPort
	dnsid uint16
}

func (udps *Udp_scanner) Write_item(scan_item *scanner.Scan_data_item) {
	udp_scan_item, ok := (*scan_item).(*Udp_scan_data_item)
	if !ok {
		return
	}
	udps.Writer.Write(scan_item_to_strarr(udp_scan_item))
	// remove entry from map
	udps.Scan_data.Mu.Lock()
	delete(udps.Scan_data.Items, udp_scan_item_key{udp_scan_item.Port, udp_scan_item.Dnsid})
	udps.Scan_data.Mu.Unlock()
}

func scan_item_to_strarr(scan_item *Udp_scan_data_item) []string {
	// csv format: id;target_ip;response_ip;arecords;timestamp;port;dnsid
	// transform scan_item into string array for csv writer
	var record []string
	record = append(record, strconv.Itoa(int(scan_item.Id)))
	record = append(record, scan_item.Ip.String())
	record = append(record, scan_item.Answerip.String())
	dns_answers := ""
	for i, dns_ip := range scan_item.Dns_recs {
		dns_answers += dns_ip.String()
		if i != len(scan_item.Dns_recs)-1 {
			dns_answers += ","
		}
	}
	record = append(record, dns_answers)
	record = append(record, scan_item.Ts.UTC().Format("2006-01-02 15:04:05.000000"))
	record = append(record, scan_item.Port.String())
	record = append(record, strconv.Itoa((int)(scan_item.Dnsid)))
	return record
}

func (udps *Udp_scanner) send_dns(id uint32, dst_ip net.IP, src_port layers.UDPPort, dnsid uint16) {
	// generate sequence number based on the first 21 bits of the hash
	logging.Println(6, nil, dst_ip, "port=", src_port, "dnsid=", dnsid)
	// check for sequence number collisions
	udps.Scan_data.Mu.Lock()
	s_d_item := Udp_scan_data_item{
		Id:       id,
		Ts:       time.Now(),
		Ip:       dst_ip,
		Port:     src_port,
		Dns_recs: nil,
		Dnsid:    dnsid,
	}
	logging.Println(6, nil, "scan_data=", s_d_item)
	udps.Scan_data.Items[udp_scan_item_key{src_port, dnsid}] = &s_d_item
	udps.Scan_data.Mu.Unlock()

	udps.Send_udp_pkt(udps.Build_dns(dst_ip, src_port, dnsid, config.Cfg.Dns_query))
}

func (udps *Udp_scanner) Handle_pkt(pkt gopacket.Packet) {
	ip_layer := pkt.Layer(layers.LayerTypeIPv4)
	if ip_layer == nil {
		return
	}
	ip, ok := ip_layer.(*layers.IPv4)
	if !ok {
		return
	}

	udp_layer := pkt.Layer(layers.LayerTypeUDP)
	if udp_layer == nil {
		return
	}
	udp, ok := udp_layer.(*layers.UDP)
	if !ok { // skip wrong packets
		return
	}
	// pkts w/o content will be dropped
	if pkt.ApplicationLayer() != nil {
		logging.Println(5, nil, "received data")
		// decode as DNS Packet
		dns := &layers.DNS{}
		pld := udp.LayerPayload()
		err := dns.DecodeFromBytes(pld, gopacket.NilDecodeFeedback)
		if err != nil {
			logging.Println(5, nil, "DNS not found")
			return
		}
		logging.Println(5, nil, "got DNS response from", ip.SrcIP.String(), "port", udp.DstPort, "id", dns.ID)
		// check if item in map and assign value
		udps.Scan_data.Mu.Lock()
		scan_item, ok := udps.Scan_data.Items[udp_scan_item_key{udp.DstPort, dns.ID}]
		udps.Scan_data.Mu.Unlock()
		if !ok {
			return
		}
		udp_scan_item, ok := scan_item.(*Udp_scan_data_item)
		if !ok {
			log.Fatal("cast failed, wrong type")
		}
		answers := dns.Answers
		var answers_ip []net.IP
		for _, answer := range answers {
			if answer.IP != nil {
				answers_ip = append(answers_ip, answer.IP)
				logging.Println(5, nil, "answer ip:", answer.IP)
			} else {
				logging.Println(5, nil, "non IP type found in answer")
				//return
			}
		}
		udp_scan_item.Answerip = ip.SrcIP
		udp_scan_item.Dns_recs = answers_ip
		// queue for writeout
		udps.Write_chan <- &scan_item
	}
}

func (udps *Udp_scanner) init_udp() {
	defer udps.Wg.Done()
	for {
		select {
		case dst_ip := <-udps.Ip_chan:
			// check if ip is excluded in the blocklist
			should_exclude := false
			for _, blocked_net := range udps.Blocked_nets {
				if blocked_net.Contains(dst_ip) {
					should_exclude = true
					break
				}
			}
			if should_exclude {
				logging.Println(4, nil, "excluding ip:", dst_ip)
				continue
			}
			id, src_port, dns_id := udps.update_sync_init()
			logging.Println(5, nil, "ip:", dst_ip, "id=", id, "port=", src_port, "dns_id=", dns_id)
			if config.Cfg.Pkts_per_sec > 0 {
				r := udps.Send_limiter.Reserve()
				if !r.OK() {
					log.Println("Rate limit exceeded")
				}
				time.Sleep(r.Delay())
			}
			udps.send_dns(id, dst_ip, layers.UDPPort(src_port), dns_id)
		case <-udps.Stop_chan:
			return
		}
	}
}

func (udps *Udp_scanner) gen_ips(netip net.IP, hostsize int) bool {
	netip_int := generator.Ip42uint32(netip)
	var lcg_ipv4 generator.Lcg
	lcg_ipv4.Init(int(math.Pow(2, float64(hostsize))))
	for lcg_ipv4.Has_next() {
		select {
		case <-udps.Stop_chan:
			return false
		default:
			val := lcg_ipv4.Next()
			udps.Ip_chan <- generator.Uint322ip(netip_int + uint32(val))
		}
	}
	return true
}

func (udps *Udp_scanner) gen_ips_nets(nets []net.IP, hostsize int) {
	defer udps.Wg.Done()
	rand.Shuffle(len(nets), func(i, j int) { nets[i], nets[j] = nets[j], nets[i] })
	// generate ips for all the given nets
	for _, ip := range nets {
		if !udps.gen_ips(ip, hostsize) {
			return
		}
	}
	var wait_time int = len(udps.Ip_chan)/config.Cfg.Pkts_per_sec + 10
	logging.Println(3, nil, "all ips generated, waiting", wait_time, "seconds to end")
	udps.Waiting_to_end = true
	// time to wait until end based on packet rate + channel size
	time.Sleep(time.Duration(wait_time) * time.Second)
	close(udps.Stop_chan)
}

func (udps *Udp_scanner) gen_ips_wait(netip net.IP, hostsize int) {
	defer udps.Wg.Done()
	udps.gen_ips(netip, hostsize)
	// wait some time to send out SYNs & handle the responses
	// of the IPs just generated before ending the program
	var wait_time int = len(udps.Ip_chan)/config.Cfg.Pkts_per_sec + 10
	logging.Println(3, nil, "all ips generated, waiting", wait_time, "seconds to end")
	udps.Waiting_to_end = true
	// time to wait until end based on packet rate + channel size
	time.Sleep(time.Duration(wait_time) * time.Second)
	close(udps.Stop_chan)
}

func (udps *Udp_scanner) Start_scan(args []string, outpath string) {
	udps.Scanner_init()
	udps.Sender_init()
	udps.L2_sender = &udps.L2
	udps.Scanner_methods = udps
	udps.Base_methods = udps
	udps.bound_sockets = []*net.UDPConn{}
	// synced between multiple init_udp()
	udps.ip_loop_id = synced_init{
		id:    0,
		port:  config.Cfg.Port_min,
		dnsid: 0,
	}

	// write start ts to log
	logging.Write_to_runlog("START " + time.Now().UTC().String())
	// command line args
	if len(os.Args) < 2 {
		logging.Write_to_runlog("END " + time.Now().UTC().String() + " arg not given")
		logging.Println(1, nil, "ERR need filename or net in CIDR notation")
		return
	}
	var fname string
	var netip net.IP
	var hostsize int
	fname, netip, hostsize = udps.Get_cidr_filename(args[0])

	udps.Bind_ports()
	// set the DNS_PAYLOAD_SIZE once as it is static
	_, _, dns_payload := udps.Build_dns(net.ParseIP("0.0.0.0"), 0, 0, config.Cfg.Dns_query)
	udps.DNS_PAYLOAD_SIZE = uint16(len(dns_payload))
	handle := common.Get_ether_handle("udp")
	// start packet capture as goroutine
	udps.Wg.Add(5)
	go udps.Packet_capture(handle)
	go udps.Write_results(outpath)
	go udps.Timeout()
	if fname != "" {
		logging.Println(3, nil, "running in filename mode")
		go udps.Read_ips_file(fname)
	} else {
		logging.Println(3, nil, "running in CIDR mode")
		go udps.gen_ips_wait(netip, hostsize)
	}
	for i := 0; i < int(config.Cfg.Number_routines); i++ {
		udps.Wg.Add(1)
		go udps.init_udp()
	}
	go udps.Close_handle(handle)
	udps.Wg.Wait()
	udps.Unbind_ports()
	logging.Println(3, nil, "all routines finished")
	logging.Write_to_runlog("END " + time.Now().UTC().String())
	logging.Println(3, nil, "program done")
}

func (udps *Udp_scanner) Start_internal(nets []net.IP, hostsize int) []scanner.Scan_data_item {
	udps.Scanner_init_internal()
	udps.Sender_init()
	udps.L2_sender = &udps.L2
	udps.Scanner_methods = udps
	udps.Base_methods = udps
	//udps.bound_sockets = []*net.UDPConn{}
	// synced between multiple init_udp()
	udps.ip_loop_id = synced_init{
		id:    0,
		port:  config.Cfg.Port_min,
		dnsid: 0,
	}
	udps.Send_limiter = rate.NewLimiter(rate.Every(time.Duration(1000000/config.Cfg.Pkts_per_sec)*time.Microsecond), 1)

	//udps.Bind_ports()
	// set the DNS_PAYLOAD_SIZE once as it is static
	_, _, dns_payload := udps.Build_dns(net.ParseIP("0.0.0.0"), 0, 0, config.Cfg.Dns_query)
	udps.DNS_PAYLOAD_SIZE = uint16(len(dns_payload))
	handle := common.Get_ether_handle("udp")
	// start packet capture as goroutine
	udps.Wg.Add(6)
	go udps.Packet_capture(handle)
	go udps.Store_internal()
	go udps.Timeout()
	go udps.gen_ips_nets(nets, hostsize)
	go udps.init_udp()
	go udps.Close_handle(handle)
	udps.Wg.Wait()
	//udps.Unbind_ports()
	logging.Println(3, nil, "internal scan done")
	return udps.Result_data_internal
}
