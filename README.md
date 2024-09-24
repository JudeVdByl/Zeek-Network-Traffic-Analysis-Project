# Zeek Network Traffic Analysis Project

## Objective
This project aimed to leverage **Zeek** for analyzing network traffic captured in various PCAP files. The goal was to extract meaningful data, detect potential security threats, and uncover insights into network behaviors. Using a combination of Zeek logs, custom scripts, and command-line tools, I processed different traffic logs to identify patterns such as brute-force attacks, DNS queries, and potential password leakage.

## Skills Learned
- Network security analysis with Zeek
- Log parsing and data extraction
- Detecting network anomalies (e.g., brute-force attacks)
- Writing custom Zeek signatures
- Efficient use of Linux-based text processing tools
- Understanding network protocols and packet flows

## Tools Used
- **Zeek**: A powerful network monitoring and security tool.
- **Wireshark**: For visualizing PCAP files (although not directly used in this instance, it's relevant in similar contexts).
- **Custom Zeek scripts**: Tailored for specific use cases (e.g., password detection, FTP brute force detection).
- **Linux command-line tools**: Including `grep`, `sort`, `uniq`, `wc`, `strings`, and others to filter and analyze log data.

## Steps

### 1. Initial Log Extraction
I started by processing several `.pcap` files using Zeek. The `-C` flag was used to ignore checksum errors, and the `-r` flag to read from the provided PCAP files. 

**Example commands**:
```
zeek -C -r sample.pcap
zeek -C -r ftp.pcap
zeek -C -r smallFlows.pcap
```

Zeek automatically generated several logs (e.g., `conn.log`, `http.log`, `dns.log`, `dhcp.log`). These logs were essential for the deeper analysis performed in the following steps.

- **Image 1**:
  



### 2. DHCP and DNS Log Analysis
**Objective**: Parse logs to identify patterns in DNS queries and DHCP hostnames.

- Extracted queries from DNS logs:
```
cat dns.log | zeek-cut query | sort | uniq | wc -l
```
- Analyzed hostnames from DHCP logs:
```
cat dhcp.log | zeek-cut host_name domain | sort -r
```
  
- **Image 2**: 
 ![image](https://github.com/user-attachments/assets/9345e92c-ef2d-44ea-9be1-d868db49b371)


I also worked with larger flow datasets to study the distribution of hostnames:
```
cat dhcp.log | zeek-cut host_name | sort -nr | uniq | wc-l
```

### 3. Connection and HTTP Log Analysis
**Objective**: Parse `conn.log` and `http.log` to derive insights into HTTP requests and connection details.

- For the HTTP log, I extracted important fields such as HTTP methods and hosts:
```
cat http.log | zeek-cut uid id.orig_p id.orig_h method host | sort
```
  
- For the connection log, I analyzed the number of packets sent and received:
```
cat conn.log | zeek-cut uid orig_pkts resp_pkts id.orig_p | sort
```

These logs were essential for identifying normal traffic patterns and pinpointing anomalies such as long connection durations or suspicious HTTP methods.

- **Image 3**: 
 ![image](https://github.com/user-attachments/assets/643846f9-d519-4070-9ae4-c6a66d4de590)



### 4. Identifying Cleartext Passwords
I wrote a custom Zeek signature to identify cleartext passwords in HTTP traffic. This signature specifically looked for password-related keywords in unencrypted (HTTP) connections.

**Custom Signature**:
```
signature http-password {
    ip-proto == tcp
    dst-port == 80
    payload /.*password.*/
    event "Cleartext Password Found!"
}
```

This was particularly useful for detecting unsecured password transmissions in the network, which is a common vulnerability.

- **Image 4**:
  ![image](https://github.com/user-attachments/assets/3006df3f-1d7f-49ba-86a0-16f8c4eeb690)



### 5. Detecting FTP Brute-Force Attacks
Brute-force attacks are common against FTP servers. I employed Zeek scripts to detect this by analyzing connection patterns in the `ftp.pcap` file. The following command helped identify repeated login attempts (indicative of brute force):

```
cat notice.log | grep "FTP Brute" | wc -l
```

Additionally, I applied custom signatures and parsing tools to identify brute-force activity:
```
zeek -C -r ftp.pcap -s ftp-admin.sig
cat notice.log | grep -i "brute" | wc -l
```

- **Image 5**:
  ![image](https://github.com/user-attachments/assets/b370ab14-5c55-4d2d-b9c1-1088b75d9248)


### 6. Advanced Log Parsing and GeoIP Analysis
To gain insights into geographical patterns in network traffic, I used Zeek to analyze connections by city and IP address:

- Extracted city-level data from connection logs:
```
cat conn.log | zeek-cut geo.resp.city | sort -nr | uniq
```

- Combined city and host information for detailed analysis:
```
cat conn.log | zeek-cut geo.resp.city id.resp_h | sort -nr | uniq
```

- **Image 6**:
  ![image](https://github.com/user-attachments/assets/d9409db1-5262-499f-b4fd-683071fd2618)


### 7. Custom Zeek Scripts for Specific Case Analysis
I used several Zeek scripts tailored to different datasets and attack patterns. For example, I used the `dhcp-hostname.zeek` script for analyzing DHCP traffic:

```
zeek -C -r smallFlows.pcap dhcp-hostname.zeek
```

Similarly, I employed the `detect-bruteforcing.zeek` script to detect brute-force login attempts in the FTP logs:
```
zeek -C -r ftp-brute.pcap /opt/zeek/share/zeek/policy/protocols/ftp/detect-bruteforcing.zeek
```

### 8. Threat Intelligence and File Hashing
To incorporate threat intelligence, I analyzed files and executables within the HTTP logs and calculated hashes for malware detection. This helped in identifying potential threats, such as executables being downloaded through HTTP.

**Commands used**:
```
strings http.log | grep -i "exe"
zeek -Cr case1.pcap hash-demo.zeek
```

This combination of log analysis and hashing ensured that I could detect suspicious files being transferred over the network.

- **Image 7**:
  ![image](https://github.com/user-attachments/assets/61c6179e-bf63-4074-ba09-30f2a704a0ad)


## Results

The analysis of the PCAP files using Zeek provided critical insights into network behavior and potential security threats:

1. **DNS and DHCP Traffic**: By analyzing the DNS and DHCP logs, I identified unique hostnames and queries, which helped in mapping the devices and services active within the network. This step also provided clues to understanding the flow of communication between internal and external domains.

2. **HTTP Traffic**: Parsing the `http.log` helped uncover the use of various HTTP methods and identified potential cleartext password transmissions. This highlighted a critical vulnerability in the network's HTTP traffic, suggesting the need for encryption (e.g., HTTPS).

3. **Brute-Force Attack Detection**: The detection of brute-force attempts against FTP servers showed a potential security issue with login mechanisms. By monitoring repeated failed login attempts, Zeek effectively flagged this type of attack, showcasing its utility in real-time threat detection.

4. **GeoIP Analysis**: The GeoIP data provided insights into the geographic origin of connections. This analysis revealed potential anomalies, such as unusual foreign IP addresses interacting with the network, which could indicate unauthorized access attempts or data exfiltration.

5. **Threat Intelligence**: The integration of custom Zeek scripts allowed for the detection of specific malicious patterns, such as executables being transmitted over HTTP and possible malware infections. The calculated hashes from file extractions reinforced the ability to detect known threats using hash-based signatures.

### Conclusion
Through the use of Zeek, this project successfully demonstrated the effectiveness of network traffic analysis in detecting vulnerabilities and security threats. By systematically parsing various logs and applying custom threat detection signatures, I was able to uncover critical insights about the network's activity, such as potential password leaks, brute-force attacks, and unauthorized foreign access attempts. 

The visual representations and geographic analysis enhanced the understanding of these threats, and the integration of file hashing and threat intelligence further strengthened the analysis, making it possible to detect known malware and anomalies effectively. 

This project underscores the importance of continuous monitoring, the use of encryption, and proactive threat detection mechanisms to secure modern networks.

