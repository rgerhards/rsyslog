# Impcap input plugin
This plugin adds monitoring of network interfaces to Rsyslog module, by capturing and parsing network packets.
The result is messages sent to the Rsyslog core, containing parsed information about the packet (ethernet and ip addresses, ports, flags...).

#Dependencies
This plugin depends on _libpcap_, and shouldn't need anything more (except the dependencies listed by Rsyslog already).
You can find information and source code of libpcap on the [tcpdump](http://www.tcpdump.org/) web page.

#Features
This is a plugin developed by a small team, so its support and features are still growing,
but the plugin already includes the following:
- capture on EthernetII-type interfaces
- capture on multiple interfaces
- per-interface filters (using libpcap filtering)
- promiscuous mode enable/disable
- metadata filtering
- data extraction (experimental)
- reading from file capture (experimental)

this plugin doesn't:
- capture data on interfaces with other datalinks (Ethernet II is the only format supported)
- support every protocol
- give you the answer to the Ultimate Question of Life, the Universe, and Everything

#How to build
Impcap is integrated into Rsyslog, but won't be compiled with it by default.
To allow Impcap to be compiled along Rsyslog, specify "--enable-impcap" option during the ./configure step (refer to [rsyslog documentation](https://www.rsyslog.com/doc/build_from_repo.html) for compilation and installation) then build rsyslog normally.

#How to use
Impcap accepts a number of parameters, either for the whole module or for each instance. Those parameters are specified in the .conf configuration file used by or given to rsyslog.
The main usage of this module is to provide an interface to listen to, then specify optional parameters, such as promiscuity, buffering, filters...
Please see below for more information.

##Module parameters
The module parameters are the following:
- **snap_length** [int/default=65535] defines the number of bytes to take from the packet. This can help when looking for increased performance, as it will only copy this much data to buffer, but beware that this might also cut desired data.
- **metadata_only** [bool/default=off] setting to take metadata only from packets. Sets snap_length to 100.

##instance parameters
The instances parameters are the following:
- **interface** [string/default=none] the name of the interface to monitor. This parameter must be specified for each input if the **file** parameter is not.
- **file** [string/default=none] the complete path to the capture file to read. This file must have the [pcap-savefile](http://www.tcpdump.org/manpages/pcap-savefile.5.html) format (.pcap and most .pcapng are compatible). This parameter must be specified if the **interface** is not.
- **promiscuous** [bool/default=off] defines if the interface must be put into [promiscuous mode](https://en.wikipedia.org/wiki/Promiscuous_mode). Beware that this might break your local network policy, and that rsyslog and affiliates will hold no responsibility for consequences.
- **filter** [string/default=none] sets the filter to apply to the libpcap capture, as defined by their [manpage](https://www.tcpdump.org/manpages/pcap-filter.7.html).
- **no_buffer** [bool/default=off] tells the capture session to work in immediate mode, meaning every packet will be delivered as soon as it is received. This option cancels the setting of **bufer_size**, **buffer_timeout**, and **packet_count**. This will decrease delay between reception and logging of packet, but this will also decrease performance.
- **buffer_size** [int/default=15360] sets the size of the pcap buffer (in kiB) to hold packets during buffering. This applies only when **no_buffer** is *off* and should be modified only for a very good reason, unless having packets dropped.
- **buffer_timeout** [int/default=10] sets the maximum timeout (in ms) between each packet buffering. Buffer will be processed if either this or **packet_count** is reached. This applies only when **no_buffer** is *off*.
- **packet_count** [int/default=5] sets the number of packets to wait for during buffering. Buffer will be processed if either this or **buffer_timeout** is reached. This applies only when **no_buffer** is *off*.
- **tag** [string/default=none] sets a specific tag to apply to messages, for rsyslog filtering.

##Getting parsed metadata
The metadata created by impcap is added to rsyslog messages adding a custom json field.
This json can be accessed in configuration using the "$!impcap" keyword.
Every subfield inside can also be accessed adding "!" and the keyword to "$!impcap", as the json object is flat every field is accessed from "$!impcap".
The (non-exhaustive) list of fields that can be accessed is :
- net_src_ip
- net_dst_ip
- net_src_port
- net_dst_port
- net_proto
- net_icmp_code
- net_icmp_type
- net_ttl
- net_bytes_total
- net_bytes_data
- net_flags

#Contribute
This plugin is open to contributions, and follows the [rules](../../CONTRIBUTING.md) defined by the Rsyslog development community.

#Credits
This plugin was created using [libpcap](https://github.com/the-tcpdump-group/libpcap), and was inspired by code made by [The Tcpdump Group](https://github.com/the-tcpdump-group), and by extension code made by the *Lawrence Berkeley National Laboratory Network Research Group*.
