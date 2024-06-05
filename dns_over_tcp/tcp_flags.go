package dns_over_tcp

// a simple struct for all the tcp flags needed
type TCP_flags struct {
	FIN, SYN, RST, PSH, ACK bool
}

func (flags TCP_flags) equals(tomatch TCP_flags) bool {
	return flags.FIN == tomatch.FIN &&
		flags.SYN == tomatch.SYN &&
		flags.RST == tomatch.RST &&
		flags.PSH == tomatch.PSH &&
		flags.ACK == tomatch.ACK
}

func (flags TCP_flags) is_PSH_ACK() bool {
	return flags.equals(TCP_flags{
		FIN: false,
		SYN: false,
		RST: false,
		PSH: true,
		ACK: true,
	})
}

func (flags TCP_flags) is_SYN_ACK() bool {
	return flags.equals(TCP_flags{
		FIN: false,
		SYN: true,
		RST: false,
		PSH: false,
		ACK: true,
	})
}

func (flags TCP_flags) is_FIN_ACK() bool {
	return flags.equals(TCP_flags{
		FIN: true,
		SYN: false,
		RST: false,
		PSH: false,
		ACK: true,
	})
}

func (flags TCP_flags) is_FIN_PSH_ACK() bool {
	return flags.equals(TCP_flags{
		FIN: true,
		SYN: false,
		RST: false,
		PSH: true,
		ACK: true,
	})
}
