#! /bin/bash

#route traffic to server through tun0
route add -net $1 netmask 255.255.255.0 dev tun0