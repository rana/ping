# Ping

A simple ICMP Echo implementation in Rust.

Based on a [Firezone](https://www.firezone.dev/) interview [challenge](https://gist.github.com/jamilbk/487bee1d3e8088c55252cf1d2b538839). 

## Intent

Create a solution that knocks it out of the park. 

Implement a high quality solution that includes the more challenging optional bonus, all the requirements, and documentation.

## Solution

![Screencast](./screencast.mp4)

- Completed optional bonus.
- Handled ICMP packet IO asynchronously with non-blocking `socket2` raw socket.
- Created an async-friendly ICMP tokio socket `IcmpSocketTokio`.
- Five second ping roundtrip timeouts.
- Input parameter bounds checks.
- Code documention.
- Code comments.
  
## Requirements

Some notes on the requirements.

* Use Linux or Docker. 
  - `Linux selected.` 
    - Having an Ubuntu Linux [desktop](https://www.intel.com/content/www/us/en/products/sku/190108/intel-nuc-9-pro-kit-nuc9vxqnx/specifications.html) makes the choice simple.
* Specify parameters:
  - IPv4.
  - ping count (min 1, max 10).
  - ping interval in milliseconds (min 1, max 1000). Requests should be sent at this interval.
* Set ICMP Echo timout at 5 seconds.
* Exit after all sent and all received, or timed out.
* Use an async runtime.
  - Don't block the executor. 
  - tokio runtime recommended.
  - Send, receive, and timeout are concurrent.
  - Choose how to coordinate concurrent commuication.
- Bonus (optional)
  - > Handle the packet IO asynchronously using the runtime without blocking calls, only waking the executor when the socket is ready. This will likely involve creating an async-friendly ICMP socket similar to [tokio::net::UdpSocket](https://docs.rs/tokio/latest/tokio/net/struct.UdpSocket.html) on top of [socket2](https://docs.rs/socket2/latest/socket2/) sockets.
* Choose a crate for sending packets.
  - Understand the tradeoffs of crate selection.
      - GitHub repo [rust-lang/socket2](https://github.com/rust-lang/socket2)
      - socket2 has 49x more downloads than pnet.
      - socket2 is also cross-platform.
    - [pnet](https://crates.io/crates/pnet) is a popular choice for parsing and forming packets.
      > Cross-platform, low level networking using the Rust programming language.

      > 1,678,261 crate downloads

      > 3rd party Rust crate

      > GitHub: 1.9k stars

      > Code changed 3 months ago

      > Cross-platform

      > High-level functions with convenience. Has nice Rust lanague constructs making it faster to develop with.

      > Thread-safe

      > Provides a cross-platform API for low level networking using Rust.
    - [socket2](https://crates.io/crates/socket2) enables raw ICMP socket sending and recieving.
      > Utilities for handling networking sockets with a maximal amount of configuration possible intended.

      > 82,798,377 crate downloads

      > Official Rust crate

      > GitHub: 519 stars

      > Code changed last week

      > Cross-platform: Linux, macOS, Windows

      > Low-level functions; less convenience than pnet; more configurability than pnet.

      > Possibly more perfofrmance than pnet? Due to low-level functions?

      > [Not thread-safe.](https://docs.rs/socket2/latest/socket2/struct.Socket.html#notes)

      > It is up to the user to know how to use sockets when using this crate. *If you don't know how to create a socket using libc/system calls then this crate is not for you.* Most, if not all, functions directly relate to the equivalent system call with no error handling applied, so no handling errors such as EINTR. As a result using this crate can be a little wordy, but it should *give you maximal flexibility over configuration of sockets.*

### Input

Input is passed to the first argument in a comma-delimited format:
```sh
# IPv4, request_count, interval_in_milliseconds
./ping "1.1.1.1,3,1000"
```

### Output

Output is printed to STDOUT in a comma-delimited format:
```sh
# IPv4, icmp_sequence_number, elapsed_time_in_microseconds
1.1.1.1,0,7189
```

### Example

```sh
$ echo "1.1.1.1,3,1000" | ping
1.1.1.1,0,7189
1.1.1.1,1,7750
1.1.1.1,2,6674
```

## Research

Some resarch notes.

 * [ICMP](https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol) - Internet Control Message Protocol. OSI layer 3
   > ICMP uses the basic support of IP as if it were a higher-level protocol, however, ICMP is actually an integral part of IP. Although ICMP messages are contained within standard IP packets, ICMP messages are usually processed as a special case, distinguished from normal IP processing.

 * ICMP [RFC 792](https://datatracker.ietf.org/doc/html/rfc792).
```
Summary of Message Types
    0  Echo Reply
    3  Destination Unreachable
    4  Source Quench
    5  Redirect
    8  Echo
   11  Time Exceeded
   12  Parameter Problem
   13  Timestamp
   14  Timestamp Reply
   15  Information Request
   16  Information Reply
```
 * [UDP](https://en.wikipedia.org/wiki/User_Datagram_Protocol) - User Datagram Protocol. OSI layer 4
 * [Internet layer](https://en.wikipedia.org/wiki/Internet_layer) - OSI layer 3
 * [Transport layer](https://en.wikipedia.org/wiki/Transport_layer) - OSI layer 4
 * Cloudflare article "[What is the Internet Control Message Protocol (ICMP)?](https://www.cloudflare.com/learning/ddos/glossary/internet-control-message-protocol-icmp/)".
   > ICMP is not associated with a transport layer protocol such as TCP or UDP. This makes ICMP a connectionless protocol: one device does not need to open a connection with another device before sending an ICMP message.
 * GitHub repo [fastping-rs](https://github.com/bparli/fastping-rs)
   - Uses pnet
     - `pnet::packet::icmp`
 * Library documentation "[pnet::packet::icmp](https://docs.rs/pnet/latest/pnet/packet/icmp/)".
 * GitHub repo "[libpnet](https://github.com/libpnet/libpnet)"
 * pnet: [Ethernet echo server](https://docs.rs/pnet/latest/pnet/index.html#ethernet-echo-server)
 * tokio: [crate](https://crates.io/crates/tokio), [website](https://tokio.rs/), [tutorial](https://tokio.rs/tokio/tutorial), [api](https://docs.rs/tokio/latest/tokio/)
   > Tokio is designed for IO-bound applications where each individual task spends most of its time waiting for IO.

   > Tokio has a lot of functionality (TCP, UDP, Unix sockets, timers, sync utilities, multiple scheduler types, etc).

   > The [current_thread](https://docs.rs/tokio/1.28.0/tokio/runtime/struct.Builder.html#method.new_current_thread) runtime flavor is a lightweight, single-threaded runtime. It is a good choice when only spawning a few tasks and opening a handful of sockets. For example, this option works well when providing a synchronous API bridge on top of an asynchronous client library.

* [tokio::io::Stdout](https://docs.rs/tokio/1.28.0/tokio/io/struct.Stdout.html)

* [tokio::net](https://docs.rs/tokio/latest/tokio/net/index.html)

* Example Linux ping output.
```sh
> ping 8.8.8.8
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=118 time=16.1 ms
64 bytes from 8.8.8.8: icmp_seq=2 ttl=118 time=14.7 ms
64 bytes from 8.8.8.8: icmp_seq=3 ttl=118 time=14.4 ms
```

* [tokio Echo server](https://tokio.rs/tokio/tutorial/io)

* [tokio-rs/mio](https://github.com/tokio-rs/mio)
  - Mio – Metal I/O
  > Mio is a fast, low-level I/O library for Rust focusing on non-blocking APIs and event notification for building high performance I/O apps with as little overhead as possible over the OS abstractions.
  - Non-blocking TCP, UDP
  - I/O event queue backed by epoll, kqueue, and IOCP
  - Zero allocations at runtime
  - Platform specific extensions
  - Platforms: Android (API level 21), DragonFly BSD, FreeBSD, Linux, NetBSD, OpenBSD, Windows, iOS, macOS
  - [API docs](https://docs.rs/mio/0.8.6/mio/)
  - [mio::net::UdpSocket](https://docs.rs/mio/0.8.6/mio/net/struct.UdpSocket.html) - UDP Echo example program
  - Linux man page: [ip - Linux IPv4 protocol implementation](https://man7.org/linux/man-pages/man7/ip.7.html)
    - Searching for ICMP usage
  - Linux man page: [icmp - Linux IPv4 ICMP kernel module.](https://man7.org/linux/man-pages/man7/icmp.7.html)
    > This kernel protocol module implements the Internet Control Message Protocol defined in RFC 792.  It is used to signal error conditions and for diagnosis.  The user doesn't interact directly with this module; instead it communicates with the other protocols in the kernel and these pass the ICMP errors to the application layers.  The kernel ICMP module also answers ICMP requests.

    > A user protocol may receive ICMP packets for all local sockets by opening a raw socket with the protocol IPPROTO_ICMP.  See raw(7) for more information.  The types of ICMP packets passed to the socket can be filtered using the ICMP_FILTER socket option.  ICMP packets are always processed by the kernel too, even when passed to a user socket.

* [zaphar/icmp-socket](https://github.com/zaphar/icmp-socket), [api docs](https://docs.rs/icmp-socket/latest/icmp_socket/)
  - ICMP Sockets for both IPv4 and IPv6
  - Uses socket2.
  - fn [set_timeout](https://docs.rs/icmp-socket/latest/icmp_socket/socket/trait.IcmpSocket.html#tymethod.set_timeout)
  - [icmp_socket::packet Echo request example](https://docs.rs/icmp-socket/latest/icmp_socket/packet/index.html#examples)

* [lib.rs: #icmp](https://lib.rs/keywords/icmp)
  - Many search results
  - [tokio-icmp-echo](https://lib.rs/crates/tokio-icmp-echo), [api docs](https://docs.rs/tokio-icmp-echo/latest/tokio_icmp_echo/), 
  - [surge-ping](https://lib.rs/crates/surge-ping), [api docs](https://docs.rs/surge-ping/latest/surge_ping/), [repo](https://github.com/kolapapa/surge-ping)
    - tokio + socket2 + pnet_packet.

* [tokio::select](https://docs.rs/tokio/latest/tokio/macro.select.html)

* Article "[Implementing ICMP in Rust](https://dev.to/xphoniex/i-implementing-icmp-in-rust-296o)"

* sys/socket.h "[api docs](https://pubs.opengroup.org/onlinepubs/7908799/xns/syssocket.h.html)", [src](https://github.com/torvalds/linux/blob/master/include/linux/socket.h).
  - `AF` = [address family](https://github.com/torvalds/linux/blob/master/include/linux/socket.h#L187)
```c
#define AF_INET		2	/* Internet IP Protocol 	*/
```

* [SOCK_SEQPACKET](https://man7.org/linux/man-pages/man7/unix.7.html), for a sequenced-packet socket that is connection-oriented, preserves message boundaries, and delivers messages in the order that they were sent.
  - ICMP is not connection-oriented. Do not use SOCK_SEQPACKET for ICMP.

* [SOCK_SEQPACKET](https://man7.org/linux/man-pages/man2/socket.2.html) - Provides a sequenced, reliable, two-way connection-based data transmission path for datagrams of fixed maximum length; a consumer is required to read an entire packet with each input system call.

* [SOCK_RAW](https://man7.org/linux/man-pages/man2/socket.2.html) - Provides raw network protocol access.

* Linux manual "[socket - create an endpoint for communication](https://man7.org/linux/man-pages/man2/socket.2.html)".

* Linux manual "[protocols - protocols definition file](https://man7.org/linux/man-pages/man5/protocols.5.html)".

* Linux manual "[icmp - Linux IPv4 ICMP kernel module](https://man7.org/linux/man-pages/man7/icmp.7.html)".
  > A user protocol may receive ICMP packets for all local sockets by opening a raw socket with the protocol IPPROTO_ICMP.

* Linux manual "[raw - Linux IPv4 raw sockets](https://man7.org/linux/man-pages/man7/raw.7.html)".
  > raw sockets are usually needed only for new protocols or protocols with no user interface (like ICMP).

  > For sending and receiving datagrams (sendto(2), recvfrom(2), and similar), raw sockets use the standard sockaddr_in address structure defined in ip(7).

  > Errors originating from the network are passed to the user only when the socket is connected or the IP_RECVERR flag is enabled.

  > If you want to receive all ICMP packets for a datagram socket, it is often better to use IP_RECVERR on that particular socket; see ip(7).

* Linux manual "[ip - Linux IPv4 protocol implementation](https://man7.org/linux/man-pages/man7/ip.7.html)".
  > IP_HDRINCL - If enabled, the user supplies an IP header in front of the user data.  Valid only for SOCK_RAW sockets

* Linux manual "[send, sendto, sendmsg - send a message on a socket](https://man7.org/linux/man-pages/man2/sendto.2.html)".

* Linux header "[linux/icmp.h](https://github.com/torvalds/linux/blob/master/include/linux/icmp.h)".

* Linux manual "[recv, recvfrom, recvmsg - receive a message from a socket](https://man7.org/linux/man-pages/man2/recv.2.html)".
  > If no messages are available at the socket, the receive calls wait for a message to arrive, unless the socket is nonblocking (see fcntl(2)), in which case the value -1 is returned and errno is set to EAGAIN or EWOULDBLOCK.  The receive calls normally return any data available, up to the requested amount, rather than waiting for receipt of the full amount requested.

  > An application can use select(2), poll(2), or epoll(7) to determine when more data arrives on a socket.

* Linux manual "[select, pselect, FD_CLR, FD_ISSET, FD_SET, FD_ZERO - synchronous I/O multiplexing](https://man7.org/linux/man-pages/man2/select.2.html)"
  > All modern applications should instead use poll(2) or epoll(7), which do not suffer this limitation.

* Linux manual "[poll, ppoll - wait for some event on a file descriptor](https://man7.org/linux/man-pages/man2/poll.2.html)".
  > poll() performs a similar task to select(2): it waits for one of a set of file descriptors to become ready to perform I/O.  The Linux-specific epoll(7) API performs a similar task, but offers features beyond those found in poll().

* Linux manual "[epoll - I/O event notification facility](https://man7.org/linux/man-pages/man7/epoll.7.html)".
  > The epoll API performs a similar task to poll(2): monitoring multiple file descriptors to see if I/O is possible on any of them.  The epoll API can be used either as an edge-triggered or a level-triggered interface and scales well to large numbers of watched file descriptors.

  > The central concept of the epoll API is the epoll instance, an in-kernel data structure which, from a user-space perspective, can be considered as a container for two lists:

  > • The interest list (sometimes also called the epoll set): the set of file descriptors that the process has registered an interest in monitoring.

  > • The ready list: the set of file descriptors that are "ready" for I/O. The ready list is a subset of (or, more precisely, a set of references to) the file descriptors in the interest list.  The ready list is dynamically populated by the kernel as a result of I/O activity on those file descriptors.

* Module [mio::guide](https://docs.rs/mio/0.8.6/mio/guide/index.html)
  - Getting started guide.
  - Uses with `socket2`, OS file descriptors

* Struct [mio::net::UdpSocket](https://docs.rs/mio/0.8.6/mio/net/struct.UdpSocket.html)
  - Example of UDP echo send/recv with mio polling.

* Article "[An introduction to using tcpdump at the Linux command line](https://opensource.com/article/18/10/introduction-tcpdump)".

* Linux manual "[tcpdump - dump traffic on a network](https://man7.org/linux/man-pages/man1/tcpdump.1.html)".

```sh
> tcpdump --list-interfaces
1.wlp3s0 [Up, Running, Wireless, Associated]
2.any (Pseudo-device that captures on all interfaces) [Up, Running]
3.lo [Up, Running, Loopback]
4.enp112s0 [Up, Disconnected]
5.eno1 [Up, Disconnected]
6.bluetooth0 (Bluetooth adapter number 0) [Wireless, Association status unknown]
7.bluetooth-monitor (Bluetooth Linux Monitor) [Wireless]
8.nflog (Linux netfilter log (NFLOG) interface) [none]
9.nfqueue (Linux netfilter queue (NFQUEUE) interface) [none]
10.dbus-system (D-Bus system bus) [none]
11.dbus-session (D-Bus session bus) [none]
```
```sh
# sudo required
> sudo tcpdump --interface wlp3s0
14:42:51.534190 ARP, Request who-has wiz_71b920.lan tell wiz_71b920.lan, length 28
14:42:51.638107 IP aum.lan.54962 > _gateway.domain: 31829+ [1au] PTR? 24.86.168.192.in-addr.arpa. (55)
14:42:51.642568 IP _gateway.domain > aum.lan.54962: 31829* 1/0/1 PTR wiz_71b920.lan. (83)

^C
64 packets captured
64 packets received by filter
0 packets dropped by kernel
```

```sh
> ping 1.1.1.1
PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.
64 bytes from 1.1.1.1: icmp_seq=1 ttl=58 time=14.7 ms
64 bytes from 1.1.1.1: icmp_seq=2 ttl=58 time=14.6 ms
64 bytes from 1.1.1.1: icmp_seq=3 ttl=58 time=14.9 ms
^C
--- 1.1.1.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2004ms
rtt min/avg/max/mdev = 14.648/14.766/14.905/0.105 ms

> sudo tcpdump --interface wlp3s0 -c5 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on wlp3s0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
14:50:42.961326 IP aum.lan > one.one.one.one: ICMP echo request, id 1, seq 1, length 64
14:50:42.976064 IP one.one.one.one > aum.lan: ICMP echo reply, id 1, seq 1, length 64
14:50:43.963206 IP aum.lan > one.one.one.one: ICMP echo request, id 1, seq 2, length 64
14:50:43.977841 IP one.one.one.one > aum.lan: ICMP echo reply, id 1, seq 2, length 64
14:50:44.965062 IP aum.lan > one.one.one.one: ICMP echo request, id 1, seq 3, length 64
5 packets captured
6 packets received by filter
0 packets dropped by kernel
>
```