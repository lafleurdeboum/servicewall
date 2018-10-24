#!/usr/bin/env bash

function bailout {
  echo -e "$1"
  exit 1
}

# Bash 4 dictionaries - list of services to enable locally
declare -A local_services
local_services=(
  ["http"]="80/tcp"
  ["ssh"]="22/tcp"
  ["Bonjour"]="5353/udp 5298"
  ["Transmission"]="51413/tcp"
  ["upnp"]="80 5431 1900/udp 49152"
  ["Skype"]="443/tcp"
  ["avahi"]="38400/udp"
  ["netbios"]="137/udp 138/udp 139/tcp"
)

authorized_services="WWW Bonjour Transmission"
# Deluge Dropbox KTorrent NFS LPD SSH
# still to be found cups netbios
option=$1
logfile=/tmp/dynfw.log
#while getopts "start:stop:" option; do
case $option in
  start)
    date >> $logfile
    echo "arguments : $@" >> $logfile

    # Determine subnet
    # at home, is 192.168.0.0/16 (or 192.168.1.0/24 ?)
    subnet=$(ip address show wlan0 | grep inet | awk '{ print $2 }')
    subnet=$(echo $subnet | awk '{ print $1 }')
    echo -n 'loading services for subnet' $subnet ':'

    # iterate over the keys of the dict :
    for service in "${!local_services[@]}"; do
      #proto=$(ufw app info $service | tail -n 1)
      echo -n " $service"
      dests=${local_services[$service]}
      for dest in $dests; do
        port=$(echo $dest | awk -F/ '{print $1}')
        proto=$(echo $dest | awk -F/ '{print $2}')
        if test -n $proto; then
          ufw allow from $subnet to any port $port comment $service > /dev/null 2>&1
        else
          ufw allow proto $proto from $subnet to any port $port comment $service > /dev/null 2>&1
        fi
      done
    done
    ufw reload > /dev/null 2>&1
    echo # a newline
    ;;
  stop)
    echo -n 'unloading services for subnet' $subnet ':'
    # Let's pray the subnet hasn't changed - but if it had, we would have been
    # called at that moment, right ?
    subnet=$(ip address show wlan0 | grep inet | awk '{ print $2 }')
    subnet=$(echo $subnet | awk '{ print $1 }')
    for service in "${!local_services[@]}"; do
      #proto=$(ufw app info $service | tail -n 1)
      echo -n " $service"
      dests=${local_services[$service]}
      for dest in $dests; do
        port=$(echo $dest | awk -F/ '{print $1}')
        proto=$(echo $dest | awk -F/ '{print $2}')
        if test -n $proto; then
          ufw delete allow from $subnet to any port $port > /dev/null 2>&1
        else
          ufw delete allow proto $proto from $subnet to any port $port > /dev/null 2>&1
        fi
      done
    done
    ufw reload > /dev/null 2>&1
    echo # a newline
    ;;
  *)
    bailout "\nusage : $0 start||stop"
    ;;
esac
