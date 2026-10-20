# Investigation Notes
## 1. Evidence Reviewed

- PCAP: `beaconing-investigation.pcap`
- Zeek connection log: `conn.log`
- Zeek HTTP log: `http.log`
- Initial Zeek warnings and generated logs
- TCP packet inspection using `tcpdump`
- Calculated intervals between consecutive connection start times

## 2. Network Context

| Field | Observation |
|---|---|
| Source IP | `127.0.0.1` |
| Destination IP | `127.0.0.1` |
| Destination port | `8765/TCP` |
| Protocol | TCP |
| Zeek service | HTTP |
| Client-side connections | 8 |
| Connection state | `SF` for all eight records |
| Connection duration | Approximately 0.000658–0.001476 seconds |
| Original-direction bytes | 131 per connection |
| Responder-direction bytes | 173 per connection |

The `SF` connection state is consistent with connections that were established and finished. All eight records contain the same source and destination IP, with different client-side source ports.

The byte counts are the values recorded in the generated Zeek connection log. They describe the capture's reconstructed connection metadata and should not be treated as proof of the nature or intent of the traffic by themselves.

## 3. Periodicity Analysis

Connection intervals were calculated by subtracting each connection's start timestamp from the preceding connection's start timestamp.

| Metric | Result |
|---|---:|
| Connections analyzed | 8 |
| Intervals calculated | 7 |
| Average interval | 5.003018 seconds |
| Minimum interval | 5.001179 seconds |
| Maximum interval | 5.004739 seconds |
| Difference between maximum and minimum | 0.003560 seconds |

The seven measured intervals are tightly grouped around five seconds. This is strong evidence of regular timing within the observed capture.

A periodic pattern can be relevant during a C2 investigation, but it is not sufficient to identify the process responsible, determine intent, or classify traffic as malicious. The endpoint context and application-layer content must also be considered.

## 4. HTTP Analysis

The HTTP log contained eight transactions with the following consistent attributes:

| Field | Observed value |
|---|---|
| Method | `GET` |
| Host | `127.0.0.1:8765` |
| URI | `/check` |
| Response code | `200` |
| Response message | `OK` |
| User-agent | `Zeek-Lab05-Controlled-Test` |

Packet inspection also revealed the response body:

`Controlled Zeek beaconing lab test`

The HTTP method, URI, response code, and user-agent remained consistent across the eight requests. The request and response content explicitly identify the activity as a controlled test.

## 5. Connection Correlation

The connection UIDs in `conn.log` match the UIDs in `http.log`. This allows each HTTP transaction to be associated with its corresponding TCP connection.

The connection start timestamps and HTTP request timestamps differ slightly because they describe different events within each session. This is expected: a connection begins before the HTTP request is transmitted.

Correlation confirms that the periodic connection pattern corresponds to repeated HTTP requests rather than an unexplained series of connection timestamps.

## 6. Checksum and Capture Analysis

The initial Zeek run reported a warning indicating that the trace likely contained invalid TCP checksums. Zeek's default checksum validation can cause affected packets to be discarded, limiting protocol reconstruction.

The initial run also reported that the trace appeared to contain only TCP control packets, potentially indicating a pre-filtered capture. The initial output did not include the expected `http.log`.

The capture was then reprocessed with:

`/opt/zeek/bin/zeek -C -r ../beaconing-investigation.pcap`

This run generated `http.log` and produced connection records with HTTP service identification, connection durations, byte counts, and `SF` states.

The `-C` option allows Zeek to analyze packets without rejecting them based on checksum validation. It does not modify or repair the underlying capture. The difference between the two runs demonstrates why analysts should investigate parsing warnings before drawing conclusions from missing telemetry.

## 7. Findings

### Confirmed

- Eight client-side TCP connections were observed to `127.0.0.1:8765`.
- The connection starts were separated by intervals averaging approximately five seconds.
- All eight connections had corresponding HTTP transactions.
- Each transaction requested `/check` using `GET`.
- Every observed HTTP response returned `200 OK`.
- The user-agent and response body identify the activity as a controlled lab test.
- The initial Zeek run produced checksum-related warnings; the `-C` run enabled useful HTTP and connection analysis.

### Assessment

The capture demonstrates a highly regular periodic communication pattern. Its repeated timing and consistent HTTP behavior are characteristics an analyst could investigate when assessing suspected beaconing in an unknown environment.

In this capture, however, the localhost endpoints and explicit lab-identifying content establish a controlled simulation. The evidence does not demonstrate external command-and-control communication, malware execution, or data exfiltration.

### Unresolved in a Real-World Investigation

If similar timing appeared in an unknown environment, additional evidence would be needed, including:

- The originating process and executable path.
- Host telemetry around the connection timestamps.
- Destination ownership and reputation where applicable.
- The purpose of the service receiving the requests.
- Broader network history and a longer observation window.
- Relevant endpoint, DNS, and security alerts.

