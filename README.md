# http-redirect
This tool is used for a NAT(Network Address Translator) router 
to redirect the connections from its LAN(Local Area Network) to 
its management page.

The router will block the connection with pre-defined keywords 
by iptables drop or connection reset. Later, the connection will 
be redirected to a warning page (default: http://gateway-ip/block.html)  

### Prerequisites
 - `raw socket` library in you Linux
 - `iptables` with string match module (Need to check your kernel options)

### Setup
 - `git clone` this project
 - `make` to compile 
 - `./conn_redirect -url` 
 
 
