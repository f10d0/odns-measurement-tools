package common

import (
	"strings"

	"github.com/google/gopacket"
)

var Opts gopacket.SerializeOptions = gopacket.SerializeOptions{
	ComputeChecksums: true,
	FixLengths:       true,
}

func To_csv_line(str_slice []string) string {
	return strings.Join(str_slice[:], ";") + "\n"
}
