package scanner

import (
	"bufio"
	"compress/gzip"
	"dns_tools/common"
	"dns_tools/config"
	"dns_tools/logging"
	"encoding/csv"
	"errors"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"golang.org/x/net/ipv4"
	"golang.org/x/time/rate"
)

type stop struct{}

type Scan_data_item interface {
	Get_timestamp() time.Time
}
type scan_item_key interface{}

// map to track tcp connections, key is a tuple of (port, seq)
type root_scan_data struct {
	Mu    sync.Mutex
	Items map[scan_item_key]Scan_data_item
}

type Methods interface {
	Write_item(scan_item Scan_data_item)
	Handle_pkt(pkt gopacket.Packet)
}

type Base_scanner struct {
	Stop_chan       chan stop
	Wg              sync.WaitGroup
	Ip_chan         chan net.IP
	Waiting_to_end  bool
	Blocked_nets    []*net.IPNet
	Write_chan      chan Scan_data_item
	Scan_data       root_scan_data
	Writer          *csv.Writer
	Scanner_methods Methods
	Send_limiter    *rate.Limiter
	Raw_con         *ipv4.RawConn
}

func (bs *Base_scanner) Init() {
	bs.Blocked_nets = []*net.IPNet{}
	bs.Stop_chan = make(chan stop) // (〃・ω・〃)
	bs.Ip_chan = make(chan net.IP, 1024)
	bs.Waiting_to_end = false
	bs.Write_chan = make(chan Scan_data_item, 4096)
	bs.Scan_data = root_scan_data{
		Items: make(map[scan_item_key]Scan_data_item),
	}
	bs.Send_limiter = rate.NewLimiter(rate.Every(time.Duration(1000000/config.Cfg.Pkts_per_sec)*time.Microsecond), 1)

	go bs.Handle_ctrl_c()
	bs.Exclude_ips()
}

func (bs *Base_scanner) Write_results(out_path string) {
	defer bs.Wg.Done()
	csvfile, err := os.Create(out_path) //"udp_results.csv.gz")
	if err != nil {
		panic(err)
	}
	defer csvfile.Close()

	zip_writer := gzip.NewWriter(csvfile)
	defer zip_writer.Close()

	bs.Writer = csv.NewWriter(zip_writer)
	bs.Writer.Comma = ';'
	defer bs.Writer.Flush()

	for {
		select {
		case scan_item := <-bs.Write_chan:
			//udp: writer.Write(scanner.scan_item_to_strarr(scan_item))
			bs.Scanner_methods.Write_item(scan_item)
		case <-bs.Stop_chan:
			return
		}
	}
}

// periodically remove keys (=connections) that get no response from map
func (bs *Base_scanner) Timeout() {
	defer bs.Wg.Done()
	for {
		select {
		case <-time.After(10 * time.Second):
			//go through map's keyset
			bs.Scan_data.Mu.Lock()
			for k, v := range bs.Scan_data.Items {
				//remove each key where its timestamp is older than x seconds
				if time.Now().Unix()-v.Get_timestamp().Unix() > 10 {
					delete(bs.Scan_data.Items, k)
				}
			}
			bs.Scan_data.Mu.Unlock()
		case <-bs.Stop_chan:
			return
		}
	}
}

func (bs *Base_scanner) Get_cidr_filename(cidr_filename string) (fname string, netip net.IP, hostsize int) {
	ip_or_file_split := strings.Split(cidr_filename, "/")
	if len(ip_or_file_split) == 1 {
		// using filename
		fname = ip_or_file_split[0]
	} else if len(ip_or_file_split) == 2 {
		// using CIDR net
		netip = net.ParseIP(ip_or_file_split[0])
		var err error
		hostsize, err = strconv.Atoi(ip_or_file_split[1])
		if err != nil {
			panic(err)
		}
		hostsize = 32 - hostsize
	} else {
		logging.Write_to_runlog("END " + time.Now().UTC().String() + " wrongly formatted input arg")
		logging.Println(1, nil, "ERR check your input arg (filename or CIDR notation)")
		os.Exit(int(common.WRONG_INPUT_ARGS))
	}
	return
}

func (bs *Base_scanner) Exclude_ips() {
	if _, err := os.Stat(config.Cfg.Excl_ips_fname); errors.Is(err, os.ErrNotExist) {
		logging.Println(2, nil, "ip exclusion list [", config.Cfg.Excl_ips_fname, "] not found, skipping")
		return
	}
	file, err := os.Open(config.Cfg.Excl_ips_fname)
	if err != nil {
		panic(err)
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		comment_pos := strings.IndexByte(line, '#')
		if comment_pos == -1 {
			comment_pos = len(line)
		}
		pos_net := line[:comment_pos]
		pos_net = strings.TrimSpace(pos_net)
		if pos_net == "" {
			continue
		}
		_, new_net, err := net.ParseCIDR(pos_net)
		if err != nil { // if there are errors try if the string maybe is a single ip
			toblock_ip := net.ParseIP(pos_net)
			if toblock_ip == nil {
				logging.Println(3, nil, "could not interpret line, skipping")
				continue
			}
			mask := net.CIDRMask(32, 32) // 32 bits for IPv4
			new_net = &net.IPNet{IP: toblock_ip, Mask: mask}
		}

		bs.Blocked_nets = append(bs.Blocked_nets, new_net)
		logging.Println(3, nil, "added blocked net:", new_net.String())
	}

	if err := scanner.Err(); err != nil {
		panic(err)
	}
}

// handle ctrl+c SIGINT
func (bs *Base_scanner) Handle_ctrl_c() {
	interrupt_chan := make(chan os.Signal, 1)
	signal.Notify(interrupt_chan, os.Interrupt)
	<-interrupt_chan
	if bs.Waiting_to_end {
		logging.Println(3, nil, "already ending")
	} else {
		logging.Println(3, nil, "received SIGINT, ending")
		close(bs.Stop_chan)
	}
}

func (bs *Base_scanner) Read_ips_file(fname string) {
	defer bs.Wg.Done()
	file, err := os.Open(fname)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if bs.Waiting_to_end {
			return
		}
		line := scanner.Text()
		if line == "" {
			continue
		}
		bs.Ip_chan <- net.ParseIP(line)
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	// wait some time to send out SYNs & handle the responses
	// of the IPs just read before ending the program
	logging.Println(3, nil, "read all ips, waiting to end ...")
	bs.Waiting_to_end = true
	time.Sleep(10 * time.Second)
	close(bs.Stop_chan)
}

func (bs *Base_scanner) Close_handle(handle *pcapgo.EthernetHandle) {
	defer bs.Wg.Done()
	<-bs.Stop_chan
	logging.Println(3, nil, "closing handle")
	handle.Close()
	logging.Println(3, nil, "handle closed")
}

func (bs *Base_scanner) Packet_capture(handle *pcapgo.EthernetHandle) {
	defer bs.Wg.Done()
	logging.Println(3, nil, "starting packet capture")
	pkt_src := gopacket.NewPacketSource(
		handle, layers.LinkTypeEthernet).Packets()
	for {
		select {
		case pkt := <-pkt_src:
			go bs.Scanner_methods.Handle_pkt(pkt)
		case <-bs.Stop_chan:
			logging.Println(3, nil, "stopping packet capture")
			return
		}
	}
}
