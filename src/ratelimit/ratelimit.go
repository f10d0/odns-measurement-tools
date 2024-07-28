package ratelimit

import (
	"bufio"
	"compress/gzip"
	"dns_tools/common"
	"dns_tools/common/udp_common"
	"dns_tools/logging"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"golang.org/x/time/rate"
)

const (
	csv_target_ip     int = 1
	csv_response_ip   int = 2
	csv_response_type int = 4
)

type Resolver_entry struct {
	resolver_ip     net.IP
	tfwd_ips        []net.IP      // ip pool
	rate_pos        int           // the rate will increase over time up to a maximum value
	rate_limiter    *rate.Limiter // current rate limiter
	answer_tss      []int64       // answer timestamps, we will log the timestamp of every incoming packet
	moving_avg_rate int
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
	sender_wg         sync.WaitGroup
	rate_limit_hard   int // maximum send rate to test [Pkts/s]
	increase_interval int // time delay between rate increases [ms]
	rate_curve        []int
	active_resolvers  map[Active_key]*Resolver_entry
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
}

func (tester *Rate_tester) send_packets() {
	defer tester.Wg.Done()
	tester.resolver_mu.Lock()
	if len(tester.resolver_data) == 0 {
		return
	}
	// retrieve the next resolver from the map
	var key Resolver_key
	for key = range tester.resolver_data { // pseudo-random key, TODO how random is this?
		break
	}
	entry := tester.resolver_data[key]
	delete(tester.resolver_data, key)
	tester.resolver_mu.Unlock()
	// start the rate limit testing to that target
	logging.Println(4, nil, "rate limit testing resolver", entry.resolver_ip)
}

func (tester *Rate_tester) Handle_pkt(pkt gopacket.Packet) {

}

func (tester *Rate_tester) Start_ratetest() {
	tester.rate_limit_hard = 5000
	tester.increase_interval = 1000
	tester.rate_curve = []int{50, 100, 200, 500}

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
	for i := 0; i < 10; i++ {
		tester.sender_wg.Add(1)
		go tester.send_packets()
	}
	tester.sender_wg.Wait()

	time.Sleep(5 * time.Second)
	<-tester.Stop_chan

	tester.Wg.Wait()
	tester.Unbind_ports()
	logging.Println(3, nil, "all routines finished")
	logging.Write_to_runlog("END " + time.Now().UTC().String())
	logging.Println(3, nil, "program done")
}
