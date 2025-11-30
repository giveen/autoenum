#!/bin/bash
dir=$(dirname $(readlink -f $0))

source $dir/functions/banner.sh
source $dir/functions/check_deps.sh
source $dir/functions/upgrade.sh
source $dir/functions/scans.sh
source $dir/functions/enum.sh
source $dir/functions/help_general.sh
source $dir/functions/menu.sh


if [[ $1 == '-nr' ]];then nr=1;fi
clear
banner
if [ $nr ];then tput setaf 2;echo -en "\n[*] autoenum set to noresolve mode";tput sgr0;sleep 0.5;fi
get_ip
halp_meh
menu

