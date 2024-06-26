# Collection of ODNS Measurement Tools

An implementation to measure the open DNS infrastructure using various Protocols over IPv4 (for now DNS-over-TCP & DNS-over-UDP).
It comprises all ODNS components: 
- Recursive resolvers
- Recursive forwarders
- Transparent forwarders

Regular scan results are published under http://odns.secnow.net

# Usage
```
  -help
    	Display help
  -c, --config [string]
    	Path to configuration file
  -m, --mode [string]
    	available modes: (s)scan, (t)trace,traceroute
  -p, --protocol [string]
    	available protocols: tcp, udp
  -v, --verbose [int]
    	overwrites the debug level set in the config (default -1)
```

## DNS over TCP

### Usage
**Setup:**
Modify the config accordingly (set your interface name and IP-address).

The template is located at ` src/scanner/tcp/config.yml.template`

Ensure kernel reset packets are disabled before running the scan:

```
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
```

**Run the scan:**
```
sudo go run dns_tool.go --mode scan --protocol tcp --config src/scanner/tcp/config.yml <net-to-scan-in-CIDR|filename-of-ip-list>
```

Results are written to `tcp_results.csv.gz`

**Postprocessing:**

Transform the data into a format useful for postprocessing:
```
python3 src/postprocessing/postproc_data_tcp_pure.py <input_file> <output_file>
```

## DNS over UDP

### Usage
**Setup:**
Modify the config accordingly (set your interface name and IP-address).

The template is located at ` src/scanner/udp/config.yml.template`

The port range can also be specified in the config. By default the range lies outside the Linux ephemeral port range (random port range) used by normal applications.

**Run the scan:**
```
sudo go run dns_tool.go --mode scan --protocol udp --config src/scanner/udp/config.yml [net-to-scan-in-CIDR|filename-of-ip-list]
```

Results are written to `udp_results.csv.gz` and are in a similiar format as the `tcp_results.csv.gz`.


## DNS Traceroute Tools
These tools measure the path to and beyond transparent DNS forwarders. 
### DNS over TCP Traceroute
Sends out SYN packets with increasing IP TTL values.
As soon as a SYN/ACK arrives, the tool starts to send DNS requests over TCP with increasing IP TTL to explore the path between scanner over target to DNS resolver.

**Usage**
```
sudo go run dns_tool.go --mode traceroute --protocol tcp [target-ip|path-to-list-of-ips]
```
