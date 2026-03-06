#!/bin/bash

upgrade (){
        echo "[*] Checking if anything requires updates, this may take a few minutes...."
	arr=('nmap' 'nikto' 'wafw00f' 'odat' 'oscanner' 'dnsenum' 'dnsrecon' 'fierce' 'onesixtyone' 'whatweb' 'rpcbind' 'gem')
	for tool in "${arr[@]}"; do
		sudo apt-get install -y "$tool" >/dev/null 2>&1 &
	done
		gem install wpscan >/dev/null 2>&1 &
	wait
        echo "[*] Done!"
}
