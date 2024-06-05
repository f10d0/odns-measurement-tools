package common

import (
	"bufio"
	"errors"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"dns_tools/config"
	"dns_tools/logging"
)

func Get_cidr_filename(cidr_filename string) (fname string, netip net.IP, hostsize int) {
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
		os.Exit(int(WRONG_INPUT_ARGS))
	}
	return
}

func Exclude_ips() {
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

		Blocked_nets = append(Blocked_nets, new_net)
		logging.Println(3, nil, "added blocked net:", new_net.String())
	}

	if err := scanner.Err(); err != nil {
		panic(err)
	}
}

// handle ctrl+c SIGINT
func Handle_ctrl_c() {
	interrupt_chan := make(chan os.Signal, 1)
	signal.Notify(interrupt_chan, os.Interrupt)
	<-interrupt_chan
	if Waiting_to_end {
		logging.Println(3, nil, "already ending")
	} else {
		logging.Println(3, nil, "received SIGINT, ending")
		close(Stop_chan)
	}
}

func Read_ips_file(fname string) {
	defer Wg.Done()
	file, err := os.Open(fname)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		Ip_chan <- net.ParseIP(line)
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	// wait some time to send out SYNs & handle the responses
	// of the IPs just read before ending the program
	logging.Println(3, nil, "read all ips, waiting to end ...")
	Waiting_to_end = true
	time.Sleep(10 * time.Second)
	close(Stop_chan)
}
