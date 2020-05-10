# wiretime

![Build](https://github.com/claymation/wiretime/workflows/Build/badge.svg)

This program transmits small UDP packets and measures the time it takes
the packet to traverse the network protocol stack, the queue discipline
layer, and the driver queue before being emitted on the wire. It relies
on the network device timestamping the packet in hardware and providing
that timestamp to the caller via the socket's error queue.

The min, median, and max latencies are recored, as well as a histogram
of the latency distribution. Packets exceeding a configurable latency
threshold can trigger a tracing snapshot, if the tracefs is mounted at
the usual place (/sys/kernel/tracing).

Copyright (c) 2020 Clay McClure
