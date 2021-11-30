# network_diagnostics
A tool to diagnoze network, test if firewalls, vlan, latency is in order.

## How to build:
This is a eclipse project for now, but later I will add a cmake configure file in order to build the binary. </br>
This application uses libpcap, which will be downloaded with cmake and linked statically in to the binar. </br>
Why? I want this tool to be highly portable, so you can build it and load it into your firewall/wireless router</br>
Or a Linux machine.

## How it works
First you setup one or more servers, and then you launch the client to access the endpoint server.</br>
For example:</br>
<pre>
|----------|                    |-----------------|                    |-------------|
| Endpoint | <--- ETHERNET ---> | Router/Firewall | <--- ETHERNET ---> | Workstation |
|----------|                    |-----------------|                    |-------------|

     ^                                  ^                                     ^
     |                                  |                                     |
     |                                  |                                     |
 |--------|                         |--------|                           |--------|
 | Server |                         | Server |                           | Client |
 |--------|                         |--------|                           |--------|
</pre>

All the intermediate servers will be able to capture the sent packet from the client and can show, if the packet was successfully recieved or not. It can also print out timestamps to show how the latency looks between different endpoints. 

## Supported features will be:
* vlan
* network latency
* multiple servers to capture the packet along the way to the endpoint node
* Suggestions?
