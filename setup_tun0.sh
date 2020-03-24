#! /bin/bash


#configure tun0
#IP assigned from second command line arg
sudo ip addr add $1/24 dev tun0
sudo ifconfig tun0 up

#route traffic to server through tun0
route add -net $2 netmask 255.255.255.0 dev tun0