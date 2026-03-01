#!/bin/bash

# Define the bridge name (you can change this or pass as $1)
NET_NAME="xdp-test-net"

# 1. Get the Network ID of the bridge
NET_ID=$(docker network inspect -f '{{.Id}}' "$NET_NAME" 2>/dev/null)

if [ -z "$NET_ID" ]; then
    echo "Error: Network '$NET_NAME' not found."
    exit 1
fi

echo -e "CONTAINER ID\tCONTAINER NAME\tVETH INTERFACE\tIFLINK INDEX"
echo -e "----------------------------------------------------------"

# 2. Get all running container IDs
docker ps --format '{{.ID}}' | while read -r cid; do

    # 3. Check if this container is connected to our target network
    # We use grep -q (quiet) to check the exit status
    if docker inspect -f '{{range .NetworkSettings.Networks}}{{.NetworkID}}{{end}}' "$cid" | grep -q "$NET_ID"; then

        raw_name=$(docker inspect -f '{{.Name}}' "$cid")
        name=${raw_name#/} # Bash Parameter Expansion: deletes '/' from start of string

        # 4. Get the peer index (iflink) from INSIDE the container
        # We redirect stderr to /dev/null in case eth0 isn't the interface name
        iflink=$(docker exec "$cid" cat /sys/class/net/eth0/iflink 2>/dev/null)

        if [ -n "$iflink" ]; then
            # 5. Search the HOST /sys/class/net/ for a matching ifindex
            for veth_path in /sys/class/net/veth*; do
                host_idx=$(cat "$veth_path/ifindex")

                if [ "$host_idx" -eq "$iflink" ]; then
                    veth_name=$(basename "$veth_path")
                    echo -e "$cid\t$name\t$veth_name\t$iflink"
                    break # Optimization: Found the match, stop looking for this container
                fi
            done
        fi
    fi
done
