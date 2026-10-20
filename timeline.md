# Timeline — Zeek Suspicious Beaconing Investigation

## 1. Timeline Overview

This timeline summarizes the eight client-side TCP connections observed in `beaconing-investigation.pcap`.

The connection timestamps are taken from Zeek's `conn.log`. Intervals are calculated as the difference between consecutive connection start times.

All timestamps below are from the captured activity on 20 October 2026, around 00:30:36–00:31:11 UTC as represented by the packet timestamps and HTTP `Date` header. The connection timestamps are expressed in Unix epoch seconds in Zeek output.

## 2. Connection Timeline

| Connection | Zeek start timestamp | Approximate capture time | Interval from previous connection |
|---:|---:|---|---:|
| 1 | `1792456236.173319` | 00:30:36.173319 | — |
| 2 | `1792456241.177993` | 00:30:41.177993 | 5.004674 seconds |
| 3 | `1792456246.182732` | 00:30:46.182732 | 5.004739 seconds |
| 4 | `1792456251.187124` | 00:30:51.187124 | 5.004392 seconds |
| 5 | `1792456256.188880` | 00:30:56.188880 | 5.001756 seconds |
| 6 | `1792456261.190142` | 00:31:01.190142 | 5.001262 seconds |
| 7 | `1792456266.191321` | 00:31:06.191321 | 5.001179 seconds |
| 8 | `1792456271.194443` | 00:31:11.194443 | 5.003122 seconds |

## 3. Timing Statistics

| Metric | Value |
|---|---:|
| Client-side connections | 8 |
| Intervals calculated | 7 |
| Average interval | 5.003018 seconds |
| Minimum interval | 5.001179 seconds |
| Maximum interval | 5.004739 seconds |
| Maximum-to-minimum spread | 0.003560 seconds |
| Elapsed time from first to last connection start | Approximately 35.021124 seconds |

The connection starts are separated by intervals clustered closely around five seconds. This supports the observation of highly regular periodic communication during the capture.

## 4. HTTP Activity

All eight connection records were correlated with HTTP transactions in `http.log`.

| Attribute | Observed value |
|---|---|
| Source IP | `127.0.0.1` |
| Destination IP | `127.0.0.1` |
| Destination port | `8765/TCP` |
| Method | `GET` |
| URI | `/check` |
| HTTP response | `200 OK` |
| User-agent | `Zeek-Lab05-Controlled-Test` |

The HTTP payload included the response body:

`Controlled Zeek beaconing lab test`

The application-layer evidence identifies the activity as a controlled lab simulation.

## 5. Analysis Events

1. **PCAP validation:** Confirmed the capture file was present and recognized as an Ethernet PCAP.
2. **Initial Zeek analysis:** Produced checksum-related and possible filtered-trace warnings; the expected HTTP records were not available in that output.
3. **Checksum-tolerant reprocessing:** Ran Zeek with `-C` and generated usable connection and HTTP records.
4. **Connection review:** Identified eight client-side TCP connections to `127.0.0.1:8765`.
5. **Interval calculation:** Measured seven intervals with an average of `5.003018` seconds.
6. **HTTP analysis:** Confirmed repeated `GET /check` requests, `200 OK` responses, and a consistent lab-specific user-agent.
7. **Evidence assessment:** Classified the traffic as a controlled periodic-communication simulation, not confirmed malicious beaconing.

## 6. Timeline Assessment

The capture demonstrates repeated HTTP communication at highly consistent intervals. Connection metadata establishes the timing pattern, and HTTP records provide the application-layer context.

The local endpoints and lab-identifying HTTP content indicate that the traffic was generated for testing. The timeline does not establish external command-and-control communication, malicious intent, or data exfiltration.
