It’s there to keep the test realistic and prevent the binary‑search throughput routine from producing meaningless or misleading results when packet sizes are extremely small (64‑byte frames).

Why a 300 Mbps ceiling exists for 64‑byte packets
1. Small packets stress the CPU, not the NIC
64‑byte packets represent the worst‑case scenario for packet‑per‑second (pps) load.
Even a modest bit‑rate produces a very high pps rate:
300\mathrm{\  Mbps}\div (64\mathrm{\  B}\times 8)\approx 585,000\  \mathrm{pps}
That is already enough to saturate many software datapaths, especially in virtualized or containerized environments.
If the binary search were allowed to go higher, it would quickly hit CPU bottlenecks rather than measuring the actual forwarding performance you care about.
