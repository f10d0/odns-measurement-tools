package ratelimit

import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"dns_tools/common"
	"dns_tools/common/udp_common"
	"dns_tools/config"
	"dns_tools/generator"
	"dns_tools/logging"
	udpscanner "dns_tools/scanner/udp"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/time/rate"
)

type csv_pos_struct struct {
	target_ip     int
	response_ip   int
	response_type int
}

var csv_pos csv_pos_struct = csv_pos_struct{
	target_ip:     -1,
	response_ip:   -1,
	response_type: -1,
}

type Answer_entry struct {
	ts               int64
	dns_payload_size int
}

type rate_data_s struct {
	answer_data     []Answer_entry // us, answer timestamps, log timestamp of every incoming packet
	answer_mu       sync.Mutex
	moving_avg_rate float64
	max_rate        float64
	rate_limiter    *rate.Limiter // current rate limiter
}

type Resolver_entry struct {
	resolver_ip   net.IP
	tfwd_ips      []net.IP // ip pool
	tfwd_pool_pos int
	rate_pos      int // the current pos in the rate slice aka the current send rate
	rate_sync     sync.WaitGroup
	rate_mu       sync.Mutex
	outport       uint16
	rate_data     []rate_data_s
	acc_max_rate  int
	acc_avg_rate  int
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
	resolver_data      map[Resolver_key]*Resolver_entry
	resolver_mu        sync.Mutex
	active_resolvers   map[Active_key]*Resolver_entry
	finished_resolvers chan *Resolver_entry
	sender_wg          sync.WaitGroup
	rate_curve         []int
	current_port       uint32
	resolver_counter   int
	domains            []string
}

func (entry *rate_data_s) calc_last_second_rate() {
	now := time.Now().UnixMicro()
	// calculate avg receive rate
	ans_len := len(entry.answer_data) - 1
	i := ans_len
	for ; i >= 0; i-- {
		if entry.answer_data[i].ts < now-int64(config.Cfg.Rate_increase_interval)*1000 {
			break
		}
	}
	entry.moving_avg_rate = float64(ans_len-i) / float64(config.Cfg.Rate_increase_interval) * 1000
	entry.max_rate = common.Max(entry.max_rate, entry.moving_avg_rate)
}

func (tester *Rate_tester) write_results(out_path string) {
	formatted_ts := time.Now().UTC().Format("2006-01-02_15-04-05")
	out_path = path.Join(out_path, fmt.Sprintf("%s_rm-%s_dm-%s_incr-%s", formatted_ts, config.Cfg.Rate_mode, config.Cfg.Domain_mode, strconv.Itoa(config.Cfg.Rate_increase_interval)))
	// TODO output config as txt file in folder
	os.MkdirAll(out_path, os.ModePerm)
	for {
		select {
		case entry := <-tester.finished_resolvers:
			// TODO concurrent_pool
			csvfile, err := os.Create(path.Join(out_path, entry.resolver_ip.String()+".csv.gz"))
			if err != nil {
				panic(err)
			}
			zip_writer := gzip.NewWriter(csvfile)
			csv_writer := csv.NewWriter(zip_writer)
			csv_writer.Comma = ';'

			logging.Println(5, nil, "writing entry for resolver", entry.resolver_ip)
			var record []string
			// === csv format ===
			// line 1: resolver_ip, max_rate, avg_rate
			record = append(record, entry.resolver_ip.String())
			record = append(record, strconv.Itoa(int(entry.acc_max_rate)))
			record = append(record, strconv.Itoa(int(entry.acc_avg_rate)))
			csv_writer.Write(record)
			// line 2: ts 1?
			// line 3: ts 2
			// ...
			// line n: ts n
			/*for _, ans_entry := range entry.answer_data {
				record = make([]string, 2)
				record[0] = strconv.FormatInt(ans_entry.ts, 10)
				record[1] = strconv.Itoa(ans_entry.dns_payload_size)
				csv_writer.Write(record)
			}*/

			csv_writer.Flush()
			zip_writer.Close()
			csvfile.Close()
		case <-tester.Stop_chan:
			return
		}
	}
}

func (tester *Rate_tester) print_resolver_data() {
	for _, v := range tester.resolver_data {
		var fwd_strs []string
		for _, fwd := range v.tfwd_ips {
			fwd_strs = append(fwd_strs, fwd.String())
		}
		logging.Println(5, "Resolver Data", "Resolver-IP:", v.resolver_ip, "Fwds:", fwd_strs)
		//fmt.Println("Resolver Data", "Resolver-IP:", v.resolver_ip, "Fwds:", fwd_strs)
	}
}

func iparr_contains(s []net.IP, e net.IP) bool {
	for _, a := range s {
		if generator.Ip42uint32(a) == generator.Ip42uint32(e) {
			return true
		}
	}
	return false
}

func (tester *Rate_tester) find_active_fwds() {
	logging.Println(3, "Probing", "Probing for active forwarders")
	var mask uint32 = 0xffffff00
	var config_backup config.Cfg_db = config.Cfg
	//config.Cfg.Verbosity = 4
	config.Cfg.Pkts_per_sec = 20000

	// Find all the nets to scan
	var nets map[uint32]struct{} = make(map[uint32]struct{}, 0)
	for _, entry := range tester.resolver_data {
		for _, fwd_ip := range entry.tfwd_ips {
			var cur_net uint32 = generator.Ip42uint32(fwd_ip) & mask
			if _, ok := nets[cur_net]; !ok {
				nets[cur_net] = struct{}{}
			}
		}
		// Zero fwds from resolver_data
		entry.tfwd_ips = make([]net.IP, 0)
	}
	pass_on_nets := make([]net.IP, 0)
	for k := range nets {
		pass_on_nets = append(pass_on_nets, generator.Uint322ip(k))
		logging.Println(4, "Probing", "net:", generator.Uint322ip(k).String())
	}
	// Scan these nets with the UDP scanner
	var udp_scanner udpscanner.Udp_scanner
	var data_items = udp_scanner.Start_internal(pass_on_nets, 8)
	var udp_data_items []udpscanner.Udp_scan_data_item = make([]udpscanner.Udp_scan_data_item, 0)
	for _, item := range data_items {
		udp_item, ok := item.(*udpscanner.Udp_scan_data_item)
		if !ok {
			log.Fatal("error in converting data item to udp data item")
		}
		udp_data_items = append(udp_data_items, *udp_item)
		logging.Println(5, "Probing", udp_item.String())
	}
	config.Cfg = config_backup
	// Add detected fwds
	temp_resolver_data := tester.resolver_data
	for res_key, res_val := range temp_resolver_data {
		for _, udp_item := range udp_data_items {
			if len(udp_item.Dns_recs) == 0 || udp_item.Answerip == nil {
				continue
			}
			if generator.Ip42uint32(udp_item.Answerip) == generator.Ip42uint32(res_val.resolver_ip) {
				// check if ip already in list
				if !iparr_contains(res_val.tfwd_ips, udp_item.Ip) {
					res_val.tfwd_ips = append(res_val.tfwd_ips, udp_item.Ip)
				} else {
					logging.Println(5, nil, "ip already contained in array of resolver", res_val.resolver_ip.String(), "data item:", udp_item.String())
				}
			}
		}
		// no fwds found -> remove from map
		if len(res_val.tfwd_ips) == 0 {
			delete(tester.resolver_data, res_key)
		}
	}
	logging.Println(3, "Probing", "Probing done")
}

func (tester *Rate_tester) read_domain_list(max int) {
	logging.Println(3, nil, "reading domain list from", config.Cfg.Domain_list)
	file, err := os.Open(config.Cfg.Domain_list)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			logging.Println(6, nil, "line empty")
			continue
		}
		// split csv columns
		// domain file format: id,domain
		split := strings.Split(line, ",")
		tester.domains = append(tester.domains, split[1])
		if max != 0 && len(tester.domains)+1 > max {
			break
		}
	}
}

func (tester *Rate_tester) read_forwarders(fname string) bool {
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
	// read column headers
	if scanner.Scan() {
		line := scanner.Text()
		split := strings.Split(line, ";")
		for i, col := range split {
			switch col {
			case "ip_request":
				csv_pos.target_ip = i
			case "ip_response":
				csv_pos.response_ip = i
			case "response_type":
				csv_pos.response_type = i
			}
		}
		if csv_pos.response_ip == -1 || (!config.Cfg.Rate_response_ip_only && csv_pos.target_ip == -1) {
			log.Fatal("missing header of the csv file")
		}
	}
	if config.Cfg.Rate_response_ip_only {
		logging.Println(5, nil, "Rate limit testing response ip directly")
	} else {
		logging.Println(5, nil, "Rate limit testing via target ip")
	}
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			logging.Println(6, nil, "line empty")
			continue
		}
		// split csv columns
		split := strings.Split(line, ";")
		//if split[csv_pos.response_type] != "Transparent Forwarder" {
		//	continue
		//}
		// add to resolver map
		key := Resolver_key{resolver_ip: split[csv_pos.response_ip]}
		resolver_entry, ok := tester.resolver_data[key]
		if !ok {
			tester.resolver_data[key] = &Resolver_entry{
				resolver_ip: net.ParseIP(split[csv_pos.response_ip]),
				tfwd_ips:    make([]net.IP, 0),
				rate_pos:    0,
				rate_data:   make([]rate_data_s, 1),
			}
			resolver_entry = tester.resolver_data[key]
		}
		if config.Cfg.Rate_response_ip_only {
			if !iparr_contains(resolver_entry.tfwd_ips, net.ParseIP(split[csv_pos.response_ip])) {
				resolver_entry.tfwd_ips = append(resolver_entry.tfwd_ips, net.ParseIP(split[csv_pos.response_ip]))
			} else {
				logging.Println(6, "Reading Forwarder File", "ip already in list")
			}
		} else {
			if !iparr_contains(resolver_entry.tfwd_ips, net.ParseIP(split[csv_pos.target_ip])) {
				resolver_entry.tfwd_ips = append(resolver_entry.tfwd_ips, net.ParseIP(split[csv_pos.target_ip]))
			} else {
				logging.Println(6, "Reading Forwarder File", "ip already in list")
			}
		}
	}

	if config.Cfg.Rate_mode == "probe" {
		logging.Println(3, nil, "probe rate mode")
		tester.find_active_fwds()
		tester.print_resolver_data()
	} else if config.Cfg.Rate_mode == "direct" || config.Cfg.Rate_mode == "" {
		logging.Println(3, nil, "direct rate mode")
		tester.print_resolver_data()
	} else {
		logging.Println(1, nil, "the rate_mode", config.Cfg.Rate_mode, "does not exist")
		return false
	}

	logging.Println(6, nil, "read all lines")
	logging.Println(3, nil, "there are", len(tester.resolver_data), "resolvers")
	return true
}

func (tester *Rate_tester) rate_test_target_sub(id int, entry *Resolver_entry, subid int, wg *sync.WaitGroup) {
	defer wg.Done()
	var dnsid uint16 = 0 //TODO maybe make this id random
	for {
		entry.rate_sync.Add(1)
		t_start := time.Now().UnixMicro()
		// send for increase_interval ms
		for time.Now().UnixMicro()-t_start < int64(config.Cfg.Rate_increase_interval)*1000 {
			var query_domain string
			if config.Cfg.Domain_mode == "hash" {
				hash := sha256.New()
				time_bytes := make([]byte, 8)
				binary.LittleEndian.PutUint64(time_bytes, (uint64)(time.Now().UnixMicro()))
				hash.Write(time_bytes)
				domain_prefix := hex.EncodeToString(hash.Sum(nil)[0:4])
				query_domain = domain_prefix + "." + config.Cfg.Dns_query
				logging.Println(6, "Sender "+strconv.Itoa(id)+"-"+strconv.Itoa(subid), "using query domain:", query_domain)
			} else if config.Cfg.Domain_mode == "constant" {
				query_domain = config.Cfg.Dns_query
			} else if config.Cfg.Domain_mode == "list" || config.Cfg.Domain_mode == "inject" {
				query_domain = tester.domains[rand.Intn(len(tester.domains))]
			} else {
				log.Fatal("wrong domain mode")
			}
			//TODO check if ip on blocklist
			// entry.tfwd_ips[entry.tfwd_pool_pos]
			port := (int(entry.outport)-int(config.Cfg.Port_min)+subid)%int(config.Cfg.Port_max-config.Cfg.Port_min) + int(config.Cfg.Port_min)
			if config.Cfg.Rate_concurrent_pool {
				logging.Println(6, "Sender "+strconv.Itoa(id)+"-"+strconv.Itoa(subid), "sending dns to", entry.tfwd_ips[subid].String(), ",resolver", entry.resolver_ip.String())
				tester.Send_udp_pkt(tester.Build_dns(entry.tfwd_ips[subid], layers.UDPPort(port), dnsid, query_domain))
			} else {
				logging.Println(6, "Sender "+strconv.Itoa(id)+"-"+strconv.Itoa(subid), "sending dns to", entry.tfwd_ips[entry.tfwd_pool_pos].String(), ",resolver", entry.resolver_ip.String())
				tester.Send_udp_pkt(tester.Build_dns(entry.tfwd_ips[entry.tfwd_pool_pos], layers.UDPPort(port), dnsid, query_domain))
				entry.tfwd_pool_pos = (entry.tfwd_pool_pos + 1) % len(entry.tfwd_ips)
			}
			dnsid++
			r := entry.rate_data[subid].rate_limiter.Reserve()
			if !r.OK() {
				log.Println("Rate limit exceeded")
			}
			time.Sleep(r.Delay())
		}
		entry.rate_data[subid].calc_last_second_rate()
		logging.Println(5, "Sender "+strconv.Itoa(id)+"-"+strconv.Itoa(subid), "last calculated rate is", entry.rate_data[subid].moving_avg_rate)
		// set rate limiter to next value
		if entry.rate_pos == len(tester.rate_curve)-1 {
			logging.Println(5, "Sender "+strconv.Itoa(id)+"-"+strconv.Itoa(subid), "rate curve exhausted")
			break
		}
		// TODO remove threshold and instead just check if increasing the tx rate gives a certain increase in rx rate
		if entry.rate_data[subid].moving_avg_rate < config.Cfg.Rate_receive_threshold*float64(tester.rate_curve[entry.rate_pos]) {
			logging.Println(5, "Sender "+strconv.Itoa(id)+"-"+strconv.Itoa(subid), "receiving rate too small, quitting")
			break
		}
		var locked bool = entry.rate_mu.TryLock()
		entry.rate_sync.Done()
		entry.rate_sync.Wait()
		if locked {
			entry.rate_pos++
			entry.rate_mu.Unlock()
		}
		logging.Println(5, "Sender "+strconv.Itoa(id)+"-"+strconv.Itoa(subid), "rate up", tester.rate_curve[entry.rate_pos], "Pkts/s")
		entry.rate_data[subid].rate_limiter.SetLimit(rate.Every(time.Duration(1000000/tester.rate_curve[entry.rate_pos]) * time.Microsecond))
	}
	entry.rate_sync.Done()
}

func (tester *Rate_tester) rate_test_target(id int, entry *Resolver_entry) {
	var wg sync.WaitGroup
	if config.Cfg.Rate_concurrent_pool {
		for i := 0; i < len(entry.tfwd_ips); i++ {
			wg.Add(1)
			go tester.rate_test_target_sub(id, entry, i, &wg)
		}
		wg.Wait()
	} else {
		wg.Add(1)
		tester.rate_test_target_sub(id, entry, 0, &wg)
	}
	// calc final rate
	entry.acc_max_rate = 0
	entry.acc_avg_rate = 0
	for i := 0; i < len(entry.rate_data); i++ {
		entry.acc_max_rate += int(entry.rate_data[i].max_rate)
		entry.acc_avg_rate += int(entry.rate_data[i].moving_avg_rate)
	}
	logging.Println(4, "Sender "+strconv.Itoa(id), "final avg rate for ", entry.resolver_ip, "is", entry.acc_avg_rate, "Pkts/s")
	logging.Println(4, "Sender "+strconv.Itoa(id), "max rate for ", entry.resolver_ip, "is", entry.acc_max_rate, "Pkts/s")
	// TODO test stability at max rate, add config variable
}

func (tester *Rate_tester) send_packets(id int) {
	defer tester.sender_wg.Done()
	for {
		tester.resolver_mu.Lock()
		if len(tester.resolver_data) == 0 {
			tester.resolver_mu.Unlock()
			logging.Println(4, "Sender "+strconv.Itoa(id), "list exhausted, returning")
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
		if config.Cfg.Rate_concurrent_pool {
			tester.current_port += uint32(len(entry.tfwd_ips))
		} else {
			tester.current_port++
		}
		if tester.current_port > uint32(config.Cfg.Port_max) {
			tester.current_port -= uint32(config.Cfg.Port_max-config.Cfg.Port_min) + 1
		}
		if config.Cfg.Rate_concurrent_pool {
			entry.rate_data = make([]rate_data_s, len(entry.tfwd_ips))
			for i := 0; i < len(entry.tfwd_ips); i++ {
				entry.rate_data[i].rate_limiter = rate.NewLimiter(rate.Every(time.Duration(1000000/tester.rate_curve[0])*time.Microsecond), 1)
				act_key := Active_key{port: uint16(int(outport) + i)}
				tester.active_resolvers[act_key] = entry
			}
		} else {
			entry.rate_data[0].rate_limiter = rate.NewLimiter(rate.Every(time.Duration(1000000/tester.rate_curve[0])*time.Microsecond), 1)
			act_key := Active_key{port: uint16(outport)}
			tester.active_resolvers[act_key] = entry
		}
		tester.resolver_counter++
		tester.resolver_mu.Unlock()
		logging.Println(4, "Sender "+strconv.Itoa(id), "rate limit testing resolver", tester.resolver_counter, entry.resolver_ip, "on port", outport)
		// === start the rate limit testing to that target ===
		tester.rate_test_target(id, entry)
		tester.finished_resolvers <- entry
		tester.resolver_mu.Lock()
		if config.Cfg.Rate_concurrent_pool {
			for i := 0; i < len(entry.tfwd_ips); i++ {
				act_key := Active_key{port: uint16(int(outport) + i)}
				delete(tester.active_resolvers, act_key)
			}
		} else {
			act_key := Active_key{port: uint16(outport)}
			delete(tester.active_resolvers, act_key)
		}
		tester.resolver_mu.Unlock()
		time.Sleep(50 * time.Millisecond)
	}
}

func (tester *Rate_tester) Handle_pkt(pkt gopacket.Packet) {
	// TODO check public resolvers with tfwds and w/o
	rec_time := time.Now().UnixMicro()
	ip_layer := pkt.Layer(layers.LayerTypeIPv4)
	if ip_layer == nil {
		return
	}
	_, ok := ip_layer.(*layers.IPv4)
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
	if pkt.ApplicationLayer() == nil {
		return
	}

	logging.Println(6, nil, "received data")
	// decode as DNS Packet
	dns := &layers.DNS{}
	pld := udp.LayerPayload()
	err := dns.DecodeFromBytes(pld, gopacket.NilDecodeFeedback)
	if err != nil {
		logging.Println(5, nil, "DNS not found")
		return
	}
	logging.Println(6, nil, "got DNS response")
	// check if item in map and assign value
	tester.resolver_mu.Lock()
	rate_entry, ok := tester.active_resolvers[Active_key{port: uint16(udp.DstPort)}]
	subid := uint16(udp.DstPort) - rate_entry.outport
	tester.resolver_mu.Unlock()
	if !ok {
		logging.Println(6, nil, "got DNS but cant find related resolver")
		return
	}
	rate_entry.rate_data[subid].answer_mu.Lock()
	ans_entry := Answer_entry{
		ts:               rec_time,
		dns_payload_size: len(pld),
	}
	rate_entry.rate_data[subid].answer_data = append(rate_entry.rate_data[subid].answer_data, ans_entry)
	rate_entry.rate_data[subid].answer_mu.Unlock()
}

func (tester *Rate_tester) inject_cache() {
	logging.Println(3, "cache injection", "starting")
	// summon go routines
	for i := 0; i < int(config.Cfg.Rate_inject_routines); i++ {
		tester.sender_wg.Add(1)

		// iterate all resolvers
		// per resolver iterate all 1k domains
		// apply send limit of 100pps
		// ignore responses?
	}
	logging.Println(3, "cache injection", "done")
}

func (tester *Rate_tester) Start_ratetest(args []string, outpath string) {
	tester.resolver_data = make(map[Resolver_key]*Resolver_entry)
	tester.active_resolvers = make(map[Active_key]*Resolver_entry)
	// load rate curve from config
	// the rate will increase over time up to a maximum value
	var rate_values []string = strings.Split(config.Cfg.Rate_curve, ",")
	tester.rate_curve = make([]int, 0)
	for _, rate_value := range rate_values {
		rate_val_int, err := strconv.Atoi(strings.Trim(rate_value, " "))
		if err != nil {
			logging.Println(1, nil, "cannot convert value in rate curve to int")
			return
		}
		tester.rate_curve = append(tester.rate_curve, rate_val_int)
	}
	logging.Println(4, nil, "rate curve:", tester.rate_curve)
	tester.current_port = uint32(config.Cfg.Port_min)
	tester.L2_sender = &tester.L2
	tester.Base_methods = tester
	tester.finished_resolvers = make(chan *Resolver_entry, 128)
	tester.Sender_init()
	tester.Base_init()
	tester.Bind_ports()

	if len(args) < 1 {
		logging.Println(1, nil, "missing intersect input file")
		return
	}

	logging.Write_to_runlog("START " + time.Now().UTC().String())

	if !tester.read_forwarders(args[0]) {
		logging.Println(3, nil, "exiting with error")
		return
	}

	if config.Cfg.Domain_mode == "list" {
		logging.Println(3, nil, "using domain list")
		tester.read_domain_list(0)
	} else if config.Cfg.Domain_mode == "inject" {
		logging.Println(3, nil, "using domain list, inject mode")
		tester.read_domain_list(config.Cfg.Rate_inject_count)
		tester.inject_cache()
	}

	// packet capture will call Handle_pkt
	handle := common.Get_ether_handle("udp")
	tester.Wg.Add(1)
	go tester.Packet_capture(handle)

	// path to an output directory, each resolver will be written to its own file
	go tester.write_results(outpath)
	// start ratelimit senders
	for i := 0; i < int(config.Cfg.Number_routines); i++ {
		tester.sender_wg.Add(1)
		go tester.send_packets(i)
	}
	tester.sender_wg.Wait()
	logging.Println(3, nil, "Sending completed")

	time.Sleep(5 * time.Second)
	close(tester.Stop_chan)
	handle.Close()

	tester.Wg.Wait()
	tester.Unbind_ports()
	logging.Println(3, nil, "all routines finished")
	logging.Write_to_runlog("END " + time.Now().UTC().String())
	logging.Println(3, nil, "program done")
}
