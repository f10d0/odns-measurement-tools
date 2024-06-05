package main

import (
	"dns_tools/common"
	"dns_tools/config"
	"dns_tools/dns_over_tcp"
	"dns_tools/logging"
	"flag"
	"fmt"
	"os"
)

func main() {
	var (
		help_flag    = flag.Bool("help", false, "Display help")
		mode_flag    = flag.String("mode", "", "available modes: scan, traceroute")
		mode_alias   = flag.String("m", "", "alias for --mode")
		prot_flag    = flag.String("protocol", "", "available protocols: tcp, udp")
		prot_alias   = flag.String("p", "", "alias for --protocol")
		config_path  = flag.String("config", "", "Path to configuration file")
		config_alias = flag.String("c", "", "alias for --config")
		debug_level  = flag.Int("verbose", -1, "overwrites the debug level set in the config")
		debug_alias  = flag.Int("v", -1, "alias for --verbose")
	)

	flag.Parse()
	fmt.Println("Remaining args:", flag.Args())

	if *help_flag {
		flag.Usage()
		return
	}

	if *mode_alias != "" {
		mode_flag = mode_alias
	}
	if *prot_alias != "" {
		prot_flag = prot_alias
	}
	if *config_alias != "" {
		config_path = config_alias
	}
	if *debug_alias > -1 {
		debug_level = debug_alias
	}

	if *config_path != "" {
		fmt.Println("using config", *config_path)
		config.Load_config(*config_path)
	} else {
		fmt.Println("missing config path")
		os.Exit(int(common.WRONG_INPUT_ARGS))
	}

	if *mode_flag != "" {
		if *debug_level > -1 {
			fmt.Println("verbosity level set to", *debug_level)
			config.Cfg.Verbosity = *debug_level
		}
		switch *mode_flag {
		case "scan":
			if *prot_flag == "" {
				fmt.Println("missing protocol")
				os.Exit(int(common.WRONG_INPUT_ARGS))
			}
			switch *prot_flag {
			case "tcp":
				fmt.Println("starting tcp scan")
				logging.Runlog_prefix = "TCP-SCAN"
				dns_over_tcp.Start_scan(*config_path, flag.Args())
			case "udp":
				fmt.Println("starting udp scan")
			default:
				fmt.Println("wrong protocol")
				os.Exit(int(common.WRONG_INPUT_ARGS))
			}
		case "traceroute":
			fmt.Println("starting traceroute")
		default:
			fmt.Println("wrong mode")
			os.Exit(int(common.WRONG_INPUT_ARGS))
		}
	} else {
		fmt.Println("missing mode (--mode)")
		os.Exit(int(common.WRONG_INPUT_ARGS))
	}
}
