# Zeek Suspicious Beaconing Investigation

## Overview

This lab demonstrates how to investigate periodic network communication using Zeek and an offline packet capture. The investigation focuses on connection timing, repeated HTTP requests, connection metadata, and the limitations of interpreting beacon-like patterns without sufficient context.

The supplied PCAP contains eight HTTP connections to a local service at `127.0.0.1:8765`. The connections occur at approximately five-second intervals and contain repeated requests to `/check`. The HTTP responses and user-agent identify the traffic as a controlled lab simulation.

The objective is to learn how to identify and measure periodic communication without automatically classifying it as malicious command-and-control activity.

## Objectives

- Analyze an offline PCAP using Zeek.
- Examine connection metadata in `conn.log`.
- Identify repeated connections to the same destination and service port.
- Calculate connection intervals and measure their consistency.
- Analyze HTTP requests and responses using `http.log`.
- Correlate connection records with HTTP transactions using Zeek connection UIDs.
- Investigate checksum-related warnings and compare Zeek analysis results.
- Distinguish observed periodic communication from confirmed malicious activity.
- Document findings, troubleshooting steps, and evidence limitations.

## Lab Environment

| Component | Details |
|---|---|
| Operating environment | Ubuntu 24.04 on WSL |
| Zeek version | 8.0.10 |
| Analysis method | Offline PCAP analysis |
| Capture file | `beaconing-investigation.pcap` |
| Destination IP | `127.0.0.1` |
| Destination port | `8765/TCP` |
| Primary log | `conn.log` |
| Supporting log | `http.log` |

## Investigation Workflow

1. Validate the PCAP file and inspect traffic associated with TCP port `8765`.
2. Run Zeek against the capture and review its warnings and generated logs.
3. Reprocess the capture with checksum validation disabled using the `-C` option.
4. Analyze `conn.log` to identify the eight client-side connections.
5. Calculate the time between consecutive connection starts.
6. Examine `http.log` for request methods, URIs, response codes, and user-agent values.
7. Correlate the network and HTTP records using connection UIDs.
8. Assess whether the observed behavior supports a beaconing hypothesis and document the limitations.

## Key Findings

- Eight client-side TCP connections were identified to `127.0.0.1:8765`.
- The average interval between connection starts was approximately `5.003018` seconds.
- The minimum observed interval was `5.001179` seconds.
- The maximum observed interval was `5.004739` seconds.
- All eight HTTP transactions used `GET` to request `/check`.
- All eight requests received `200 OK` responses.
- The observed user-agent was `Zeek-Lab05-Controlled-Test`.
- The packet payload identified the activity as a controlled lab test.
- The initial Zeek run reported checksum-related warnings and did not reconstruct the HTTP activity as expected. Reprocessing with `-C` produced usable connection and HTTP records.

## Conclusion

The capture demonstrates highly regular, repeated HTTP communication over a short observation window. Zeek connection metadata and HTTP logs provide sufficient evidence to measure the timing pattern and characterize the application-layer activity.

However, the destination is localhost, and the captured HTTP content explicitly identifies a controlled lab test. The investigation therefore demonstrates beaconing analysis techniques rather than detecting confirmed malicious command-and-control activity.

## Evidence and Limitations

- The capture contains controlled local traffic, not evidence of communication with an external C2 server.
- Periodic timing alone is not sufficient to establish malicious intent.
- The observation window is limited to eight connections.
- The `-C` option ignores checksum validation; it does not repair the PCAP or establish that all packets are valid.
- Findings are limited to the supplied capture and the Zeek records successfully generated from it.

## Tools Used

- Zeek
- `zeek-cut`
- `tcpdump`
- Ubuntu 24.04 on WSL

