[![CMake](https://github.com/payano/network_diagnostics/actions/workflows/cmake.yml/badge.svg)](https://github.com/payano/network_diagnostics/actions/workflows/cmake.yml)

# network_diagnostics
A tool to diagnoze network, test if firewalls, vlan, latency is in order.

## Usage
<pre>
Usage network_tester:
  -c       Mode client   (sends data to server)
  -r       Mode receiver (receives data from client)
  -l       Mode listener (listens to data from client)
  -i       Network interface to use
  -d       Destination address to send data (used with -c)
  -p       port number
  -s       Source address to send data (used with -r)
  -t       ethernet protocol (tcp or udp)
  -v       vlan id
</pre>

## Supported platforms
* Asus rt-ac66u
* Linux
* Armbian
* Raspberry Pi
* Odroid N2
* And more...

## Why use this application?
If you have two network looking like this:
<pre>
<-ComputerA-> <-LAN_A-> <-Firewall_A-> <----INTERNET----> <-Firewall_B-> <-LAN_B-> <-ServerB->
</pre>
And you are sitting on ComputerA and want to reach ServerB, but the connection via TCP or UDP fails and you want to diagnose it.
We need to assume that the "INTERNET" connection is working good. To be able to diagnose the problem further one way could be to use this application.
You install the start the application in Client mode on ComputerA, on Firewall_A and Firewall_B you start the application in Listener mode and
on ServerB you start the application in Receiever mode. When ComputerA sends the packet towards ServerB, Firewall_A should be able to see the ingress packet,
Firewall_B should also be able to read the packet, if it's not blocked by the Firewall_B firewall rules. If you setup the Listener on Firewall_B WAN port,
you should be able to see the incoming packet. Then you could assume that there is something wrong with Firewall_B. 

## How it works
First you setup one or more servers, and then you launch the client to access the endpoint server.
The main goal with this application is to use these listeners which you can start on almost every device.
And run them on the network equipment along the way to be able to follow the path of the packet going from Endpoind to Workstation.

For example:<br/>
<pre>
|----------|                    |-----------------|                    |-------------|
| Endpoint | <--- ETHERNET ---> | Router/Firewall | <--- ETHERNET ---> | Workstation |
|----------|                    |-----------------|                    |-------------|

     ^                                  ^                                     ^
     |                                  |                                     |
     |                                  |                                     |
|----------|                       |----------|                           |--------|
| Receiver |                       | Listener |                           | Client |
|----------|                       |----------|                           |--------|
</pre>

All the intermediate servers will be able to capture the sent packet from the client and can show, if the packet was successfully recieved or not. It can also print out timestamps to show how the latency looks between different endpoints. <br/>

One thing to notice, is that the application can print out when the packet was received or sent, but in order for the timestamps to make sense, the clocks needs to be synchronized with a common source, perhaps a NTP server on the internet.<br/>

Then we can see the delays between different nodes on the network, to be able to pinpoint delay issues.<br/>

## Supported features will be:
* vlan [ if requested ]
* network latency
* multiple servers to capture the packet along the way to the endpoint node
* Suggestions?

## How to build:
If you want to cross compile to a router and don't know how to do it, create a issue and I can build the binary for you<br/>
Otherwise, checkout this repository:<br/>
git clone https://github.com/payano/network_diagnostics.git<br/>
cd network_diagnostics<br/>
mkdir build<br/>
cmake ..<br/>
make<br/>

