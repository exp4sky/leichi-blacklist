/log info "Import leichi ipv4 cidr list..."
/ip firewall address-list remove [/ip firewall address-list find list=cn_ip_cidr]
/ip firewall address-list
:do {add address=1.1.8.0/24 list=leichi_blacklist_cidr} on-error={}
:do {add address=1.2.4.0/24 list=leichi_blacklist_cidr} on-error={}
