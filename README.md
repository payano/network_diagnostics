# network_diagnostics
A tool to diagnoze network, test if firewalls, vlan, latency is in order.

## How to build:
This is a eclipse project for now, but later I will add a cmake configure file in order to build the binary. </br>
This application uses libpcap, which will be downloaded with cmake and linked statically in to the binar. </br>
Why? I want this tool to be highly portable, so you can build it and load it into your firewall/wireless router</br>
Or a Linux machine.
