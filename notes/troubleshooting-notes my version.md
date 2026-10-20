# Troubleshooting Notes

## 1. PCAP Validation

Before running Zeek, confirm that the capture exists and is recognized as a valid packet-capture file.

```bash
cd ~/zeek-labs/lab05

ls -lh beaconing-investigation.pcap
file beaconing-investigation.pcap
```

Observed result:

- File: `beaconing-investigation.pcap`
- Size: approximately 11 KB
- Format: PCAP version 2.4
- Link type: Ethernet
- Timestamp precision: microseconds

These checks confirm that the file is present and recognized as a PCAP. They do not independently establish that the capture contains complete or valid application-layer traffic.

## 2. Checksum Warning During the Initial Zeek Run

### Observed issue

Running Zeek normally produced a warning similar to:

`Your trace file likely has invalid TCP checksums, most likely from NIC checksum offloading.`

Zeek also reported that the trace appeared to contain only TCP control packets and might have been pre-filtered.

### Why it matters

Zeek validates packet checksums by default. Packets that fail validation may be discarded, preventing Zeek from reconstructing TCP sessions or identifying application protocols.

The warning about a potentially filtered trace is a separate diagnostic. It indicates that the packet sequence available to Zeek may be incomplete; it does not prove how or why the trace was filtered.

### Resolution used

The capture was reprocessed in a separate output directory:

```bash
cd ~/zeek-labs/lab05

mkdir -p zeek-output-checksum-ignored
cd zeek-output-checksum-ignored

/opt/zeek/bin/zeek -C -r ../beaconing-investigation.pcap
```

The `-C` option disables checksum validation during analysis. The resulting logs included `conn.log`, `http.log`, `files.log`, and `packet_filter.log`.

### Important limitation

The `-C` option does not repair packet checksums or restore missing packets. It permits Zeek to continue analyzing packets despite checksum-validation failures. Analysts should document this choice and avoid treating the resulting analysis as proof that the capture is complete.

## 3. Missing HTTP Log in the Initial Output

### Observed issue

The initial run generated `conn.log`, `packet_filter.log`, `reporter.log`, and `weird.log`, but did not generate the expected `http.log`.

### Investigation

The initial warnings indicated checksum problems and possible packet filtering. The absence of `http.log` was therefore treated as an analysis limitation rather than evidence that HTTP traffic did not exist.

### Resolution

After rerunning Zeek with `-C`, `http.log` was generated. It contained eight HTTP transactions, each requesting `/check` and receiving `200 OK`.

This comparison shows why analysts should investigate parser warnings and inspect the original packets before concluding that a protocol is absent.

## 4. Incorrect AWK Field Used for Destination Port

### Observed issue

An earlier interval calculation used:

```awk
$4 == 8765
```

However, the selected fields were:

```text
ts id.orig_h id.orig_p id.resp_h id.resp_p
```

Field `$4` is the destination IP address, not the destination port. As a result, the filter did not select the intended connections.

### Resolution

The correct destination-port field is `$5`. The corrected filter was:

```awk
$5 == 8765 && $2 == "127.0.0.1"
```

The full interval calculation then returned eight connections and seven intervals.

## 5. Verify Connection and HTTP Records

Use `zeek-cut` to inspect the connection metadata:

```bash
/opt/zeek/bin/zeek-cut \
  ts uid id.orig_h id.orig_p id.resp_h id.resp_p \
  proto service duration orig_bytes resp_bytes conn_state \
  < conn.log
```

Inspect HTTP transactions separately:

```bash
/opt/zeek/bin/zeek-cut \
  ts uid id.orig_h id.orig_p id.resp_h id.resp_p \
  method host uri status_code status_msg user_agent \
  < http.log
```

Compare the UIDs between the two logs to correlate each HTTP transaction with its TCP connection.

The connection timestamp records the start of a connection, while the HTTP timestamp records an application-layer event. Small timestamp differences between corresponding records are expected.

## 6. Inspect the Original Packet Payload

To inspect readable TCP payloads associated with port `8765`, use:

```bash
tcpdump -nn -A -r ../beaconing-investigation.pcap \
  'tcp port 8765' | head -60
```

The observed payload included an HTTP request for `/check` and the response body:

`Controlled Zeek beaconing lab test`

This payload provided additional context for interpreting the periodic traffic as a controlled simulation.

## 7. Avoid Misinterpreting Periodicity

### Potential mistake

Classifying repeated connections at fixed intervals as malicious C2 solely because the timing is regular.

### Correct approach

- Measure the intervals and report the observed consistency.
- Identify the destination and application protocol.
- Inspect requests, responses, and available payloads.
- Correlate network records with endpoint telemetry where available.
- Document what is confirmed, what is suspected, and what remains unknown.

In this lab, periodic communication is confirmed, but malicious intent is not. The traffic is directed to localhost and explicitly identifies itself as a lab test.

