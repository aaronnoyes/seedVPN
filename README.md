# seedVPN

A Linux-based VPN written according to [this SEED lab](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Networking/VPN/).

## About

The report associated with this is in `paper.pdf`. The report concerns implementation decisions. This document is intented to explain how to run the project and demonstrate it. 

## Quick Start

The quickest way to get everything up and running is to tun `start-serv.sh` and `start-cli.sh` on the respective machines, then commands can be tried to see functionality. Using this method, run `ping 10.0.5.1` from the client in a second terminal tab or window to see the server respond. Debug output is availible by default.

## VM Setup
MISSING DOWNLOAD INSTRUCTIONS

Unzip the VM bundle and `cd` into it. From here run `./setup.sh` which will import the client and server VMs and configure them on a new NATNetwork. Both VMs will also be launched. This ensures that the VirtualBox DHCP service assigns consistent IP addresses to the client and server machines, making the program easier to demonstrate. Both VMs are already configured to start `qterminal` on boot and `cd` into the project folder.

One VM is named client, and the other is named server, but the program runs exactly the same way.

For ease of use, both VMs use the password `4580`.

## Building
As noted above, once the VMs launch they will already have an open terminal in the project folder.

A makefile is supplied to build all the needed files. Simply running `make` in the `seedVPN` folder will build all necessary object files and executables. The `client` and `server` executables are the final builds of the VPN.

The makefile is setup to compile with the flag `-DDANGEROUSDEBUG` which allows a function to be created that is dangerous but helps with demo purposes. Compiling with this flag means that the client and server will both print hex representions of important data like the session key, IV, and HMACs. This is supplied to demonstrate the utility of the program, but makes the output long and ugly and can be removed by removing `-DDANGEROUSDEBUG` from the makefile's `CFLAGS` variable near the top of the file.

## Running
Once built, the server and the client can be run manually, or using the `start-serv.sh` and `start-cli.sh` scripts which remove the need to type in any command line arguments. Root privileges are required to create the virtual TUN devices, so sudo is need. As noted above, both machines use the password `4580`. The server should be started first as it wauts for client connections.

#### Options
* -t <vpnIP> is required and chooses what IP the device should use in the VPN
* -d is optional and allows for debug output to be printed
* -s <serverIP> is required ONLY BY THE CLIENT and specifies the IP address of the server

#### Example
The following are example configurations used in the automated scripts:
* `sudo ./server -t 10.0.5.1 -d`
* `sudo ./client -s 10.0.10.4 -t 10.0.4.1 -d`

These commands start the client and server in debug mode. Since the `-DDANGEROUSDEBUG` flag is set, this debug info will include the printing of keys, etc. The client in this case has the IP address of 10.0.4.1 within the VPN.

## Commands
The VPN server and client each have 4 runtime commands implemented for dynamic reconfiguration. The first 3 are run by typing the command into `stdin` on the client or server. Implementation details can be found in the report.
* key <key> - change the session key (32 bytes)
* iv <iv> - change the session IV (16 bytes)
* hmac <key> - change the session's HMAC key (32 bytes)
* quit - this is done by exiting the process, which closes the TCP pipe and tells the peer the session is done. To do this, use `ctrl-c` or kill the program.

#### Example
`hmac 01234567890123456789012345678901` will change the HMAC key used by both the client and server.

`hmac 01278901` will fail to update the HMAC key because the length is too short

`iv 0123456789012345` will update the IV used by AES encryption

## Demonstration
Once the client and server are connected either manually or via the automated scripts, commands listed above can be entered at will. Debug output written to `stdin` will show the effect and success status of a change. Debug output also shows the key exchange at the beginning of the program which sets up the secure channel.

Example commands are given above.

The best way to see the VPN tunnel in action is to ping the `vpnIP` (ie `ping 10.0.5.1` from the client to ping the server via its internal IP. Do this in a second terminal window/tab. By default, any packets sent between the client and server will output all releveant information like the encrypted data received, the decrypted version, and the value of the HMAC. 

As explained in the paper and discussed over WebEx, the decision was made not to demonstrate a network with 2 gateways and a host connected to each. In short, all that adds is some routing information and does not show anything about the implementation.