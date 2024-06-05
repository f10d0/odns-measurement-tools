package common

import (
	"net"
	"sync"
)

var Blocked_nets []*net.IPNet = []*net.IPNet{}

type stop struct{}

var Stop_chan = make(chan stop) // (〃・ω・〃)

var Waiting_to_end bool = false

var Wg sync.WaitGroup
var Ip_chan = make(chan net.IP, 1024)
