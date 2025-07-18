# Week 1: Research & Planning Sprint - Research Notes

## AI for Intrusion Detection





### A comprehensive review of AI based intrusion detection system

**Abstract:** In today's digital world, the tremendous amount of data poses a significant challenge to cyber security. The complexity of cyber-attacks makes it difficult to develop efficient tools to detect them. Signature-based intrusion detection has been the common method used for detecting attacks and providing security. However, with the emergence of Artificial Intelligence (AI), particularly Machine Learning (ML), Deep Learning (DL) and ensemble learning, promising results have been shown in detecting attacks more efficiently. This review discusses how AI-based mechanisms are being used to detect attacks effectively based on relevant research. To provide a broader view, the study presents taxonomy of the existing literature on Machine Learning (ML), Deep learning (DL), and ensemble learning. The analysis includes 72 research papers and considers factors such as the algorithm and performance metrics used for detection. The The study reveals that AI-based intrusion detection methods improve accuracy, but researchers have primarily focused on improving performance for detecting attacks rather than individual attack classification. The main objective of the study is to provide an overview of different AI-based mechanisms in intrusion detection and offer deeper insights for future researchers to better understand the challenges of multi-classification of attacks.

**Keywords:** Intrusion detection system, Machine learning, Deep learning, Artificial intelligence, Ensemble learning

**Key Takeaways:**
*   AI-based IDS improve accuracy in detecting cyber-attacks.
*   Focus has been on overall performance rather than multi-classification.
*   Challenges include handling large, noisy datasets and considering time/CPU utilization.
*   The paper reviews ML, DL, and ensemble learning approaches for IDS.

**Source:** [A comprehensive review of AI based intrusion detection system](https://www.sciencedirect.com/science/article/pii/S2665917423001630)





## Analysis of Existing Tools

### Zeek
Zeek (formerly Bro) is a powerful open-source network analysis framework that functions as a Network Security Monitor (NSM). Unlike traditional signature-based Intrusion Detection Systems (IDS), Zeek focuses on comprehensive network visibility and deep protocol analysis. It captures high-fidelity transaction logs, file contents, and customizable data outputs, making it ideal for forensic investigations and threat hunting. Zeek can detect suspicious signatures and anomalies, track various network activities (DNS, HTTP, FTP), and supports real-time alerts with automatic program execution for detected anomalies. Its strength lies in its ability to provide rich, detailed logs and its highly extensible scripting language, allowing for customized analysis and detection logic.

**Key Features:**
*   Passive network traffic analysis.
*   Generates detailed transaction logs and extracts file contents.
*   Deep protocol analysis for various application-layer protocols.
*   Customizable scripting for flexible detection and analysis.
*   Supports real-time alerting and automated responses.
*   Focuses on network security monitoring and post-incident investigation.

**Source:** [About Zeek — Book of Zeek](https://docs.zeek.org/en/master/about.html), [The Zeek Network Security Monitor](https://zeek.org/), [Deep Dive into Zeek](https://medium.com/@ashutoshthakurofficial/deep-dive-into-zeek-a-powerful-network-security-monitoring-tool-f52ff3485035)

### Snort
Snort is a widely-used open-source Network Intrusion Detection System (NIDS) and Intrusion Prevention System (IPS). It is known for its lightweight nature and ability to perform real-time traffic analysis. Snort primarily relies on signature-based detection, where it compares network packets against a set of predefined rules to identify known attack patterns. It can operate in three main modes: sniffer (packet capture), packet logger (logs packets to disk), and network intrusion detection (analyzes traffic against rules). Snort's features include real-time traffic monitoring, packet logging, protocol analysis, content matching, OS fingerprinting, and the ability to create custom rules for specific threats. It is a versatile tool for securing networks by detecting and optionally blocking malicious activities.

**Key Features:**
*   Real-time network traffic analysis.
*   Signature-based detection using a comprehensive rule set.
*   Operates as a sniffer, packet logger, or NIDS/IPS.
*   Supports custom rule creation for tailored threat detection.
*   Performs protocol analysis, content matching, and OS fingerprinting.
*   Provides alerting and logging capabilities.

**Source:** [Snort - Network Intrusion Detection & Prevention System](https://www.snort.org/), [SNORT—Network Intrusion Detection and Prevention System](https://www.fortinet.com/resources/cyberglossary/snort), [Snort IDS/IPS Explained](https://www.zenarmor.com/docs/network-security-tutorials/what-is-snort)

### Wazuh
Wazuh is a free and open-source security platform that unifies Extended Detection and Response (XDR) and Security Information and Event Management (SIEM) capabilities. It provides comprehensive security visibility for endpoints and cloud workloads. Wazuh's core functionalities include security log analysis, intrusion detection, file integrity monitoring, vulnerability detection, security configuration assessment, and regulatory compliance. It uses a multi-platform agent that runs on monitored systems to collect security data, which is then analyzed by the Wazuh server. The platform offers real-time monitoring, in-depth log analysis, threat hunting, behavioral analysis, and automated response capabilities. Wazuh integrates with various security tools and provides a centralized dashboard for alerts and reporting.

**Key Features:**
*   Unified XDR and SIEM platform.
*   Security log analysis and aggregation.
*   Intrusion detection (host-based and network-based).
*   File integrity monitoring (FIM).
*   Vulnerability detection and security configuration assessment.
*   Automated response to security incidents.
*   Threat hunting and behavioral analysis.
*   Cloud workload protection.
*   Regulatory compliance reporting.

**Source:** [Overview | Wazuh](https://wazuh.com/platform/overview/), [Capabilities - User manual - Wazuh documentation](https://documentation.wazuh.com/current/user-manual/capabilities/index.html), [Wazuh - Open Source XDR. Open Source SIEM.](https://wazuh.com/)





## Features for Intrusion Detection

Intrusion Detection Systems (IDS) analyze various features to identify suspicious or malicious activities. These features can be broadly categorized into network-based and host-based (log-based) features.

**Common Network-Based Features:**
*   **Packet Rate:** The number of packets per unit of time. Anomalies in packet rates can indicate Denial of Service (DoS) attacks or unusual traffic patterns.
*   **Port Frequency:** The frequency of connections to specific ports. Unusual port activity (e.g., frequent connections to unusual ports or a high number of connections to a single port) can indicate port scanning or service exploitation attempts.
*   **Protocol Usage:** The types and distribution of protocols used in network traffic (e.g., TCP, UDP, ICMP). Deviations from normal protocol usage can signal tunneling, protocol abuse, or specific attack types.
*   **Packet Size:** The size of individual packets. Unusual packet sizes can be indicative of malformed packets or specific attack payloads.
*   **Timestamps:** The time at which packets are sent or received. Analyzing timestamps can help detect synchronized attacks or unusual communication patterns.
*   **IP Addresses:** Source and destination IP addresses. Monitoring these can help identify communication with known malicious IPs or unusual internal-to-internal or internal-to-external communication patterns.
*   **Connection Duration:** The length of time a connection remains active. Abnormally long or short connections can be suspicious.
*   **Number of Bytes Transferred:** The volume of data exchanged. High volumes can indicate data exfiltration, while low volumes might suggest reconnaissance.
*   **Flags (TCP flags):** Analysis of TCP flags (SYN, ACK, FIN, RST, PSH, URG) can reveal connection attempts, terminations, or abnormal behavior like SYN floods.

**Common Log-Based Features (Host-Based):**
*   **Login Attempts:** Number of successful/failed login attempts. High failed attempts can indicate brute-force attacks.
*   **User Activity:** Unusual commands executed, file access patterns, or privilege escalation attempts.
*   **System Calls:** Monitoring system calls can reveal malicious processes or unauthorized actions.
*   **Process Information:** New processes, unusual process behavior, or processes running with elevated privileges.
*   **File Access:** Unauthorized access, modification, or deletion of critical system files.
*   **Error Logs:** Unusual error messages or a high frequency of errors can indicate system compromise or misconfiguration being exploited.
*   **Security Event IDs:** Specific event IDs in system logs (e.g., Windows Event IDs) that indicate security-related events like account lockouts, security policy changes, or audit failures.

**Source:** [Top Features of Intrusion Detection Systems for Network Security](https://www.linkedin.com/advice/1/what-key-features-look-when-selecting-intrusion-eckpf), [What is an Intrusion Detection System?](https://www.paloaltonetworks.com/cyberpedia/what-is-an-intrusion-detection-system-ids), [Analyzing IDS Logs](https://info-savvy.com/analyzing-ids-logs/)





## Proposed Architecture Sketch (Network-based IDS)

Based on the decision to focus on network-based detection for the Minimum Viable Product (MVP), the architecture of the Multi-Agent Intelligent System for Real-Time Cyber Threat Detection and Response will consist of three main components:

1.  **Agent Listener (Network Packet Capture & Feature Extraction):**
    *   **Purpose:** This component will be responsible for passively capturing network traffic and extracting relevant features in real-time. It will act as the 'eyes and ears' of the system on the network.
    *   **Tools/Technologies:** Scapy or tshark can be used for packet capture and initial parsing. Python scripts will be developed to extract the defined network-based features (e.g., packet rate, port frequency, protocol usage, packet size, timestamps, IP addresses, connection duration, TCP flags).
    *   **Data Flow:** Raw network packets -> Packet parsing and feature extraction -> Structured feature data (e.g., CSV, JSON, or in-memory data structures) for the Analyzer.

2.  **Analyzer (Machine Learning Model for Anomaly Detection):**
    *   **Purpose:** This component will receive the extracted network features and apply a machine learning model to identify anomalous or suspicious patterns indicative of cyber threats.
    *   **Tools/Technologies:** Python with scikit-learn or TensorFlow (for more complex models if needed) will be used to implement and train the anomaly detection model (e.g., Isolation Forest, SVM, or Random Forest). The model will be trained on a dataset containing both normal and malicious network traffic patterns.
    *   **Data Flow:** Structured feature data from Agent Listener -> ML model inference -> Detection results (e.g., 'normal', 'anomaly', 'attack_type') and confidence scores.

3.  **Response Engine:**
    *   **Purpose:** This component will take action based on the detection results from the Analyzer. For the MVP, basic actions like logging and alerting will be prioritized, with optional auto-blocking.
    *   **Tools/Technologies:** Python scripts will handle the logic for different response actions. For logging, simple file writing or integration with a logging system can be used. For alerting, mechanisms like email notifications, Telegram alerts, or integration with a SIEM system can be explored. For auto-blocking, interaction with firewall rules (e.g., `iptables` on Linux) would be required.
    *   **Data Flow:** Detection results from Analyzer -> Decision logic -> Execution of response actions (logging, alerting, blocking).

**Overall System Flow:**
Network Traffic -> [Agent Listener] -> Extracted Features -> [Analyzer (ML Model)] -> Detection Results -> [Response Engine] -> Actions (Log, Alert, Block)

This modular design allows for independent development and future expansion of each component.



