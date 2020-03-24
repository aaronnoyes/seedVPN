#! /bin/bash

#connect to client using simpletun
#server IP supplied in command line arg
sudo ./simpletun -i tun0 -c $1 -d &

#configure tun0
#IP assigned from second command line arg
sudo ip addr add $2/24 dev tun0
sudo ifconfig tun0 up

#route traffic to server through tun0
route add -net 10.0.5.0 netmask 255.255.255.0 dev tun0