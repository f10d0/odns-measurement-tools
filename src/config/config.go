package config

import (
	"fmt"

	"github.com/ilyakaznacheev/cleanenv"
)

// config
type Cfg_db struct {
	Iface_name     string `yaml:"iface_name"`
	Iface_ip       string `yaml:"iface_ip"`
	Dst_port       uint16 `yaml:"dst_port"`
	Dns_query      string `yaml:"dns_query"`
	Excl_ips_fname string `yaml:"exclude_ips_fname"`
	Pkts_per_sec   int    `yaml:"pkts_per_sec"`
	Verbosity      int    `yaml:"verbosity" env-default:"3"`
	// traceroute
	Port_min           uint16 `yaml:"port_min"`
	Port_max           uint16 `yaml:"port_max"`
	Port_reuse_timeout int    `yaml:"port_reuse_timeout"`
	Number_routines    uint16 `yaml:"no_of_routines"`
	Craft_ethernet     bool   `yaml:"craft_ethernet"`
	Domain_mode        string `yaml:"domain_mode"`
	Domain_list        string `yaml:"domain_list"`
	Rate_curve         string `yaml:"rate_curve"`
	// rate modes may be: < probe | direct >
	//  - probe will check the entire /24 net of the transparent fwds from the intersect file for (further) active fwds
	//  - direct will only use the specified addresses
	Rate_mode string `yaml:"rate_mode"`
}

var Cfg Cfg_db

func Load_config(config_path string) {
	err := cleanenv.ReadConfig(config_path, &Cfg)
	if err != nil {
		panic(err)
	}
	fmt.Println("config:", Cfg)
}
