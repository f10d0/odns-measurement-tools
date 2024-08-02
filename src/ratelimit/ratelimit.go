package ratelimit

import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"dns_tools/common"
	"dns_tools/common/udp_common"
	"dns_tools/config"
	"dns_tools/logging"
	"encoding/binary"
	"encoding/hex"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/time/rate"
)

const (
	csv_target_ip     int = 1
	csv_response_ip   int = 2
	csv_response_type int = 4
)

type Resolver_entry struct {
	resolver_ip     net.IP
	tfwd_ips        []net.IP // ip pool
	tfwd_pool_pos   int
	rate_pos        int           // the current pos in the rate slice aka the current send rate
	rate_limiter    *rate.Limiter // current rate limiter
	answer_tss      []int64       // us, answer timestamps, log timestamp of every incoming packet
	moving_avg_rate float64
	outport         uint16
}

type Resolver_key struct {
	resolver_ip string
}

type Active_key struct {
	port uint16
}

type Rate_tester struct {
	common.Base
	udp_common.Udp_binder
	udp_common.Udp_sender
	resolver_data     map[Resolver_key]*Resolver_entry
	resolver_mu       sync.Mutex
	active_resolvers  map[Active_key]*Resolver_entry
	sender_wg         sync.WaitGroup
	increase_interval int // time delay between rate increases [ms]
	rate_curve        []int
	current_port      uint32
	resolver_counter  int
	rec_thres         float64
}

func (tester *Rate_tester) Read_forwarders(fname string) {
	logging.Println(3, nil, "reading forwarders from", fname)
	file, err := os.Open(fname)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	gzip_reader, err := gzip.NewReader(file)
	if err != nil {
		log.Fatal(err)
	}
	defer gzip_reader.Close()

	scanner := bufio.NewScanner(gzip_reader)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			logging.Println(6, nil, "line empty")
			continue
		}
		// split csv columns
		split := strings.Split(line, ";")
		if split[csv_response_type] != "Transparent Forwarder" {
			continue
		}
		logging.Println(6, nil, "target-ip:", split[csv_target_ip], "response-ip:", split[csv_response_ip])
		// add to resolver map
		key := Resolver_key{resolver_ip: split[csv_response_ip]}
		resolver_entry, ok := tester.resolver_data[key]
		if !ok {
			tester.resolver_data[key] = &Resolver_entry{
				resolver_ip:  net.ParseIP(split[csv_response_ip]),
				tfwd_ips:     make([]net.IP, 0),
				rate_pos:     0,
				rate_limiter: rate.NewLimiter(rate.Every(0*time.Microsecond), 1),
				answer_tss:   make([]int64, 0),
			}
			resolver_entry = tester.resolver_data[key]
		}
		resolver_entry.tfwd_ips = append(resolver_entry.tfwd_ips, net.ParseIP(split[csv_target_ip]))
	}

	logging.Println(6, nil, "read all lines")
	logging.Println(3, nil, "there are", len(tester.resolver_data), "resolvers")
}

func (tester *Rate_tester) rate_test_target(id int, entry *Resolver_entry) {
	// create a dns query
	for entry.moving_avg_rate == 0 || entry.moving_avg_rate > tester.rec_thres*float64(tester.rate_curve[entry.rate_pos]) {
		t_start := time.Now().UnixMicro()
		// send for increate_interval ms
		for time.Now().UnixMicro()-t_start > int64(tester.increase_interval)*1000 {
			hash := sha256.New()
			time_bytes := make([]byte, 8)
			binary.LittleEndian.PutUint64(time_bytes, (uint64)(time.Now().UnixMicro()))
			hash.Write(time_bytes)
			domain_prefix := hex.EncodeToString(hash.Sum(nil)[0:4])
			query_domain := domain_prefix + "." + config.Cfg.Dns_query
			logging.Println(4, "Sender "+strconv.Itoa(id), "using query domain:", query_domain)
			query_domain = config.Cfg.Dns_query //TODO remove this later
			var dnsid uint16 = 0
			tester.Send_udp_pkt(tester.Build_dns(entry.tfwd_ips[entry.tfwd_pool_pos], layers.UDPPort(entry.outport), dnsid, query_domain))
			entry.tfwd_pool_pos++
		}
		now := time.Now().UnixMicro()
		// calculate avg receive rate
		ans_len := len(entry.answer_tss)
		i := ans_len
		for ; i >= 0; i-- {
			if entry.answer_tss[i] < now-int64(tester.increase_interval)*1000 {
				break
			}
		}
		entry.moving_avg_rate = float64(ans_len-i) / float64(tester.increase_interval)
	}
	logging.Println(5, "Sender "+strconv.Itoa(id), "rate too small, quitting")
}

func (tester *Rate_tester) send_packets(id int) {
	defer tester.sender_wg.Done()
	for {
		tester.resolver_mu.Lock()
		if len(tester.resolver_data) == 0 {
			tester.resolver_mu.Unlock()
			logging.Println(4, "Sender "+strconv.Itoa(id), "List exhausted, returning")
			return
		}
		// retrieve the next resolver from the map
		var key Resolver_key
		for key = range tester.resolver_data { // pseudo-random key, TODO how random is this?
			break
		}
		entry := tester.resolver_data[key]
		delete(tester.resolver_data, key)
		outport := tester.current_port
		entry.outport = (uint16)(outport)
		tester.current_port++
		if tester.current_port > uint32(config.Cfg.Port_max) {
			tester.current_port = uint32(config.Cfg.Port_min)
		}
		tester.active_resolvers[Active_key{port: uint16(outport)}] = entry
		tester.resolver_counter++
		tester.resolver_mu.Unlock()
		logging.Println(4, "Sender "+strconv.Itoa(id), "rate limit testing resolver", tester.resolver_counter, entry.resolver_ip, "on port", outport)
		// === start the rate limit testing to that target ===
		tester.rate_test_target(id, entry)
		break
		time.Sleep(5 * time.Millisecond)
	}
}

func (tester *Rate_tester) Handle_pkt(pkt gopacket.Packet) {

}

func (tester *Rate_tester) Start_ratetest() {
	tester.increase_interval = 1000 // ms
	tester.resolver_data = make(map[Resolver_key]*Resolver_entry)
	tester.active_resolvers = make(map[Active_key]*Resolver_entry)
	tester.rate_curve = []int{50, 100, 150, 200} // the rate will increase over time up to a maximum value
	tester.current_port = uint32(config.Cfg.Port_min)
	tester.rec_thres = 0.75

	tester.Base_init()
	tester.Bind_ports()

	// TODO config variable
	fname := "intersect_out.csv.gz"
	tester.Read_forwarders(fname)

	// packet capture will call Handle_pkt
	handle := common.Get_ether_handle("udp")
	tester.Wg.Add(1)
	go tester.Packet_capture(handle)
	// start ratelimit senders
	// TODO config variable
	for i := 0; i < 1; i++ {
		tester.sender_wg.Add(1)
		go tester.send_packets(i)
	}
	tester.sender_wg.Wait()
	logging.Println(3, nil, "Sending completed")

	time.Sleep(5 * time.Second)
	close(tester.Stop_chan)

	tester.Wg.Wait()
	tester.Unbind_ports()
	logging.Println(3, nil, "all routines finished")
	logging.Write_to_runlog("END " + time.Now().UTC().String())
	logging.Println(3, nil, "program done")
}
