package generator

import (
	"dns_tools/common"
	"dns_tools/logging"
	"encoding/binary"
	"math"
	"math/rand"
	"net"
	"time"
)

// Linear Congruential Generator
// as described in https://stackoverflow.com/a/53551417
type lcg_state struct {
	value      int
	offset     int
	multiplier int
	modulus    int
	max        int
	found      int
}

var lcg_ipv4 lcg_state

func (lcg *lcg_state) init(stop int) {
	// Seed range with a random integer.
	lcg.value = rand.Intn(stop)
	lcg.offset = rand.Intn(stop)*2 + 1                                  // Pick a random odd-valued offset.
	lcg.multiplier = 4*(int(stop/4)) + 1                                // Pick a multiplier 1 greater than a multiple of 4
	lcg.modulus = int(math.Pow(2, math.Ceil(math.Log2(float64(stop))))) // Pick a modulus just big enough to generate all numbers (power of 2)
	lcg.found = 0                                                       // Track how many random numbers have been returned
	lcg.max = stop
}

func (lcg *lcg_state) next() int {
	for lcg.value >= lcg.max {
		lcg.value = (lcg.value*lcg.multiplier + lcg.offset) % lcg.modulus
	}
	lcg.found += 1
	value := lcg.value
	// Calculate the next value in the sequence.
	lcg.value = (lcg.value*lcg.multiplier + lcg.offset) % lcg.modulus
	return value
}

func (lcg *lcg_state) has_next() bool {
	return lcg.found < lcg.max
}

func ip42uint32(ip net.IP) uint32 {
	return binary.BigEndian.Uint32(ip.To4())
}

func uint322ip(ipint uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipint)
	return ip
}

func Gen_ips(netip net.IP, hostsize int) {
	defer common.Wg.Done()
	netip_int := ip42uint32(netip)
	lcg_ipv4.init(int(math.Pow(2, float64(hostsize))))
	for lcg_ipv4.has_next() {
		select {
		case <-common.Stop_chan:
			return
		default:
			val := lcg_ipv4.next()
			common.Ip_chan <- uint322ip(netip_int + uint32(val))
		}
	}
	// wait some time to send out SYNs & handle the responses
	// of the IPs just read before ending the program
	logging.Println(3, "all ips generated, waiting to end ...")
	common.Waiting_to_end = true
	time.Sleep(10 * time.Second)
	close(common.Stop_chan)
}
