
//QUIZ
const quizzes = {
  // --- Unit 1: Foundational Concepts (OSI, Zero Trust, PKI) Questions ---
  unit1: [
    {
      question: 'Which OSI Model layer is responsible for the logical process-to-process communication using port numbers?',
      options: [
        'a) Network Layer (L3)',
        'b) Transport Layer (L4)',
        'c) Session Layer (L5)',
        'd) Application Layer (L7)',
      ],
      answer: 'b) Transport Layer (L4)',
      rationale: 'The Transport Layer, using protocols like TCP and UDP, uses port numbers for process-to-process communication.',
    },
    {
      question: 'The TCP/IP Model\'s Network Access layer combines the functions of which two OSI layers?',
      options: [
        'a) Transport and Network',
        'b) Session and Presentation',
        'c) Physical and Data Link',
        'd) Network and Data Link',
      ],
      answer: 'c) Physical and Data Link',
      rationale: 'The Network Access layer is responsible for defining how data is sent and received over the physical medium.',
    },
    {
      question: 'What is the core security tenet of the Zero Trust Model?',
      options: [
        'a) Once inside the network, all authenticated users are trusted.',
        'b) Focus security primarily on the network perimeter.',
        'c) Never trust, always verify.',
        'd) Rely solely on strong multifactor authentication (MFA).',
      ],
      answer: 'c) Never trust, always verify.',
      rationale: 'Zero Trust requires continuous verification and assumes no implicit trust, regardless of location.',
    },
    {
      question: 'In LAN Management, what is the primary purpose of creating a VLAN?',
      options: [
        'a) To increase the network\'s total throughput speed.',
        'b) To replace physical cabling with wireless connections.',
        'c) To dynamically assign IP addresses to devices.',
        'd) To logically segment a single broadcast domain.',
      ],
      answer: 'd) To logically segment a single broadcast domain.',
      rationale: 'VLANs create smaller, manageable broadcast domains, improving security and reducing congestion.',
    },
    {
      question: 'A digital signature uses the sender\'s private key to provide which two cryptographic assurances?',
      options: [
        'a) Confidentiality and Encryption',
        'b) Non-repudiation and Integrity',
        'c) Availability and Authorization',
        'd) Access Control and Auditing',
      ],
      answer: 'b) Non-repudiation and Integrity',
      rationale: 'The private key proves the sender\'s identity (Non-repudiation), and the hash confirms the message hasn\'t changed (Integrity).',
    },
    {
      question: 'Which web security consideration best mitigates a SQL Injection attack?',
      options: [
        'a) Implementing HSTS.',
        'b) Escaping all HTML output.',
        'c) Using parameterized queries (prepared statements).',
        'd) Enforcing strong user passwords.',
      ],
      answer: 'c) Using parameterized queries (prepared statements).',
      rationale: 'Prepared statements separate the SQL command from the user data, preventing the data from being executed as code.',
    },
    {
      question: 'A Digital Certificate primarily serves to bind a public key to which element?',
      options: [
        'a) The private key storage device.',
        'b) The symmetric session key.',
        'c) A verified identity (person, server, or device).',
        'd) The Certificate Revocation List (CRL).',
      ],
      answer: 'c) A verified identity (person, server, or device).',
      rationale: 'The main goal of a certificate is to assure users that a specific public key belongs to the claimed identity.',
    },
    {
      question: 'In a PKI environment, what is the role of the Certificate Authority (CA)?',
      options: [
        'a) To manage network firewalls and access controls.',
        'b) To encrypt bulk data traffic between endpoints.',
        'c) To issue, manage, and revoke digital certificates.',
        'd) To resolve domain names to IP addresses.',
      ],
      answer: 'c) To issue, manage, and revoke digital certificates.',
      rationale: 'The CA is the trusted third party that validates identities and issues certificates.',
    },
    {
      question: 'The Kerberos protocol uses a unique three-part system for authentication. Which component issues the Service Ticket (ST)?',
      options: [
        'a) The Client Workstation',
        'b) The Application Server',
        'c) The Ticket Granting Service (TGS)',
        'd) The Certificate Authority (CA)',
      ],
      answer: 'c) The Ticket Granting Service (TGS)',
      rationale: 'The TGS issues the ST, which is needed to access a specific network service.',
    },
    {
      question: 'What is the main security advantage of using SSL/TLS when accessing a website (HTTPS)?',
      options: [
        'a) It prevents the server from ever crashing.',
        'b) It guarantees the client\'s IP address remains hidden.',
        'c) It encrypts data in transit to provide confidentiality and integrity.',
        'd) It speeds up file downloads by using compression.',
      ],
      answer: 'c) It encrypts data in transit to provide confidentiality and integrity.',
      rationale: 'TLS/SSL secures the communication channel against eavesdropping and tampering.',
    },
    {
      question: 'Which OSI Model layer handles data formatting, character code conversion, and data compression/decompression?',
      options: [
        'a) Session Layer (L5)',
        'b) Presentation Layer (L6)',
        'c) Application Layer (L7)',
        'd) Transport Layer (L4)',
      ],
      answer: 'b) Presentation Layer (L6)',
      rationale: 'The Presentation Layer is responsible for translating data into a format that the Application Layer can understand.',
    },
    {
      question: 'The TCP/IP Model\'s Application Layer corresponds conceptually to which three layers of the OSI Model?',
      options: [
        'a) Network, Transport, and Session',
        'b) Data Link, Network, and Transport',
        'c) Application, Presentation, and Session',
        'd) Physical, Data Link, and Network',
      ],
      answer: 'c) Application, Presentation, and Session',
      rationale: 'The TCP/IP Application layer handles the functions of the top three OSI layers.',
    },
    {
      question: 'To prevent lateral movement of threats within a network, the Zero Trust Model heavily relies on the concept of:',
      options: [
        'a) Strong physical security.',
        'b) Micro-segmentation.',
        'c) Centralized password management.',
        'd) Quarterly penetration testing.',
      ],
      answer: 'b) Micro-segmentation.',
      rationale: 'Micro-segmentation divides the network into small, secure zones, limiting a threat\'s ability to move laterally.',
    },
    {
      question: 'Which LAN Management protocol is used to dynamically assign IP addresses, subnet masks, and default gateways to client devices?',
      options: [
        'a) ARP (Address Resolution Protocol)',
        'b) DHCP (Dynamic Host Configuration Protocol)',
        'c) DNS (Domain Name System)',
        'd) ICMP (Internet Control Message Protocol)',
      ],
      answer: 'b) DHCP (Dynamic Host Configuration Protocol)',
      rationale: 'DHCP automates the assignment of necessary network configuration parameters.',
    },
    {
      question: 'When a recipient verifies a digital signature, what specific process confirms the document has not been altered since it was signed?',
      options: [
        'a) Decrypting the original message with the private key.',
        'b) Checking the Certificate Revocation List.',
        'c) Comparing a newly generated hash of the document with the hash embedded in the signature.',
        'd) Checking the sender\'s firewall logs.',
      ],
      answer: 'c) Comparing a newly generated hash of the document with the hash embedded in the signature.',
      rationale: 'If the hashes match, the integrity is confirmed; if they don\'t, the document was altered.',
    },
    {
      question: 'Cross-Site Scripting (XSS) is a major web security consideration. Which key defense strategy mitigates this?',
      options: [
        'a) Implementing a strong WAF (Web Application Firewall).',
        'b) Using anti-CSRF tokens.',
        'c) Input sanitization and output encoding (escaping).',
        'd) Using the TLS protocol.',
      ],
      answer: 'c) Input sanitization and output encoding (escaping).',
      rationale: 'Encoding user-supplied output prevents the browser from executing it as code.',
    },
    {
      question: 'If a server\'s Digital Certificate is compromised (its private key is leaked), which mechanism must be used to alert relying parties that the certificate is no longer valid before its expiration date?',
      options: [
        'a) Certificate Revocation List (CRL) or Online Certificate Status Protocol (OCSP)',
        'b) Domain Name System (DNS) update',
        'c) A new Kerberos TGT',
        'd) The Network Time Protocol (NTP)',
      ],
      answer: 'a) Certificate Revocation List (CRL) or Online Certificate Status Protocol (OCSP)',
      rationale: 'CRL and OCSP are the mechanisms PKI uses to revoke trust in compromised certificates.',
    },
    {
      question: 'What entity within a PKI is responsible for verifying the identity of an applicant and approving a certificate request before the CA issues it?',
      options: [
        'a) Registration Authority (RA)',
        'b) Certificate Repository (CR)',
        'c) Key Distribution Center (KDC)',
        'd) Certification Practice Statement (CPS)',
      ],
      answer: 'a) Registration Authority (RA)',
      rationale: 'The RA handles the administrative task of vetting the identity of the certificate applicant.',
    },
    {
      question: 'A Kerberos client uses the Ticket Granting Ticket (TGT) to request a Service Ticket (ST). What key is used to encrypt the Service Ticket delivered to the client?',
      options: [
        'a) The client\'s public key.',
        'b) The TGS\'s private key.',
        'c) The shared secret key between the KDC and the target Application Server.',
        'd) The client\'s original login password.',
      ],
      answer: 'c) The shared secret key between the KDC and the target Application Server.',
      rationale: 'This ensures only the legitimate application server and the client can decrypt and use the Service Ticket.',
    },
    {
      question: 'What is the function of the ServerHello message during the initial SSL/TLS handshake?',
      options: [
        'a) It sends the server\'s private key to the client.',
        'b) It proves the client\'s identity to the server.',
        'c) It confirms the agreed-upon cipher suite and the TLS version.',
        'd) It initiates the transfer of bulk encrypted data.',
      ],
      answer: 'c) It confirms the agreed-upon cipher suite and the TLS version.',
      rationale: 'ServerHello responds to ClientHello, agreeing on the encryption methods and protocol version to be used.',
    },
    {
      question: 'A router operates primarily at which layer of the OSI model?',
      options: [
        'a) Data Link Layer (L2)',
        'b) Network Layer (L3)',
        'c) Transport Layer (L4)',
        'd) Physical Layer (L1)',
      ],
      answer: 'b) Network Layer (L3)',
      rationale: 'Routers use IP addresses for routing decisions, which is the function of the Network Layer.',
    },
    {
      question: 'The TCP/IP Model\'s Transport layer is responsible for choosing between connection-oriented and connectionless service. Which two protocols fulfill these roles, respectively?',
      options: [
        'a) IP and ICMP',
        'b) ARP and RARP',
        'c) TCP and UDP',
        'd) HTTP and FTP',
      ],
      answer: 'c) TCP and UDP',
      rationale: 'TCP is connection-oriented; UDP is connectionless. Both are Transport Layer protocols.',
    },
    {
      question: 'Which action aligns most closely with the Zero Trust Model principle of "Assume Breach"?',
      options: [
        'a) Investing all security funds into the external firewall.',
        'b) Never updating user passwords.',
        'c) Designing internal network controls (like micro-segmentation) to contain an inevitable breach.',
        'd) Disabling all internal logging to save storage space.',
      ],
      answer: 'c) Designing internal network controls (like micro-segmentation) to contain an inevitable breach.',
      rationale: 'Assuming a breach means designing defenses to limit damage *after* a penetration occurs.',
    },
    {
      question: 'A crucial web security consideration is the use of anti-CSRF tokens. What type of attack are these tokens designed to prevent?',
      options: [
        'a) Cross-Site Scripting (XSS)',
        'b) Cross-Site Request Forgery (CSRF)',
        'c) Denial of Service (DoS)',
        'd) SQL Injection',
      ],
      answer: 'b) Cross-Site Request Forgery (CSRF)',
      rationale: 'Anti-CSRF tokens ensure the request originated from the legitimate web application.',
    },
    {
      question: 'In the context of PKI and Digital Certificates, what key is contained within a server\'s certificate and is used by clients to initiate key exchange?',
      options: [
        'a) The Certificate Authority\'s Private Key',
        'b) The server\'s Private Key',
        'c) The server\'s Public Key',
        'd) The symmetric session key',
      ],
      answer: 'c) The server\'s Public Key',
      rationale: 'The Public Key is shared to allow others to encrypt data or verify signatures from the server.',
    },
  ],

  // --- Unit 2: Security Services and Technologies (Firewalls, IDS, VPN) Questions ---
  unit2: [
    {
      question: 'Which of the following describes the function of a Firewall?',
      options: [
        'a) Automatically encrypting all internal network traffic.',
        'b) Providing strong authentication for all user logins.',
        'c) Controlling network traffic based on a set of predetermined security rules.',
        'd) Monitoring network traffic for signs of intrusion and immediately stopping it.',
      ],
      answer: 'c) Controlling network traffic based on a set of predetermined security rules.',
      rationale: 'The fundamental role of a firewall is to enforce an access policy by filtering traffic.',
    },
    {
      question: 'A Stateful Firewall is considered more secure and efficient than a stateless firewall primarily because it:',
      options: [
        'a) Uses deep packet inspection to analyze application content.',
        'b) Tracks the active connections and allows return traffic associated with those connections without re-evaluating rules.',
        'c) Requires a digital certificate for all incoming connections.',
        'd) Operates solely at the Application Layer (Layer 7).',
      ],
      answer: 'b) Tracks the active connections and allows return traffic associated with those connections without re-evaluating rules.',
      rationale: 'Stateful inspection maintains a connection table to distinguish legitimate responses from unsolicited traffic.',
    },
    {
      question: 'What is the main drawback of using a Proxy Firewall?',
      options: [
        'a) It is highly vulnerable to distributed denial-of-service (DDoS) attacks.',
        'b) It introduces latency (delay) because it breaks the connection and inspects the traffic at the Application Layer.',
        'c) It cannot perform Network Address Translation (NAT).',
        'd) It can only block traffic based on IP address and port number.',
      ],
      answer: 'b) It introduces latency (delay) because it breaks the connection and inspects the traffic at the Application Layer.',
      rationale: 'The deep inspection and session termination inherent to proxying adds processing time and latency.',
    },
    {
      question: 'Which Intrusion Detection System (IDS) type monitors the traffic flowing across an entire network segment for suspicious activity?',
      options: [
        'a) Host-based IDS (HIDS)',
        'b) Network-based IDS (NIDS)',
        'c) Application-based IDS (AIDS)',
        'd) Zero-day IDS (ZIDS)',
      ],
      answer: 'b) Network-based IDS (NIDS)',
      rationale: 'NIDS sensors are placed at strategic points to monitor all traffic passing through that segment.',
    },
    {
      question: 'What is the key difference between an IDS (Intrusion Detection System) and an IPS (Intrusion Prevention System)?',
      options: [
        'a) IDS only uses signature detection, while IPS only uses anomaly detection.',
        'b) IDS alerts and logs the event; IPS actively blocks or drops the malicious traffic.',
        'c) IDS is host-based; IPS is always network-based.',
        'd) IDS only protects internal networks; IPS only protects perimeter networks.',
      ],
      answer: 'b) IDS alerts and logs the event; IPS actively blocks or drops the malicious traffic.',
      rationale: 'The core difference is the *Prevention* capability—actively stopping the intrusion, not just logging it.',
    },
    {
      question: 'An IDS/IPS that uses a database of known attack patterns operates on which detection method?',
      options: [
        'a) Signature-based detection',
        'b) Anomaly-based detection',
        'c) Heuristic-based detection',
        'd) Protocol-based detection',
      ],
      answer: 'a) Signature-based detection',
      rationale: 'Signatures are predefined patterns matching known malicious activity.',
    },
    {
      question: 'The detection method that creates a baseline of normal network activity and alerts administrators when traffic deviates significantly from this baseline is known as:',
      options: [
        'a) Signature-based detection',
        'b) Anomaly-based detection',
        'c) Rule-based detection',
        'd) Correlation-based detection',
      ],
      answer: 'b) Anomaly-based detection',
      rationale: 'Anomaly detection flags anything that deviates from the established norm.',
    },
    {
      question: 'Which type of security tool is installed on individual workstations or servers and monitors local activity, such as file system changes and system calls?',
      options: [
        'a) Host-based Security System (HIDS/HIPS)',
        'b) Network-based Security System (NIDS/NIPS)',
        'c) Perimeter Firewall',
        'd) Application Gateway',
      ],
      answer: 'a) Host-based Security System (HIDS/HIPS)',
      rationale: 'Host-based systems monitor the activity on the local machine itself.',
    },
    {
      question: 'A Virtual Private Network (VPN) provides which three fundamental security services?',
      options: [
        'a) Availability, Authentication, and Non-repudiation.',
        'b) Confidentiality, Integrity, and Authentication.',
        'c) Access Control, Auditing, and Logging.',
        'd) Firewalling, NAT, and Load Balancing.',
      ],
      answer: 'b) Confidentiality, Integrity, and Authentication.',
      rationale: 'Confidentiality (encryption), Integrity (tamper detection), and Authentication (user/device identity) are core to a secure VPN tunnel.',
    },
    {
      question: 'What type of VPN configuration is used to connect two separate office networks securely over the internet?',
      options: [
        'a) Remote Access VPN',
        'b) Client-to-Site VPN',
        'c) Site-to-Site VPN',
        'd) Personal VPN',
      ],
      answer: 'c) Site-to-Site VPN',
      rationale: 'Site-to-Site connects entire LANs to each other.',
    },
    {
      question: 'What is the standard port used by the IPsec suite for negotiating security associations and exchanging keys?',
      options: [
        'a) TCP 443',
        'b) UDP 500',
        'c) UDP 500 (for IKE - Internet Key Exchange)',
        'd) TCP 1723',
      ],
      answer: 'c) UDP 500 (for IKE - Internet Key Exchange)',
      rationale: 'IKE, which handles the key exchange, uses UDP port 500.',
    },
    {
      question: 'IPsec operates at which layer of the TCP/IP or OSI model?',
      options: [
        'a) Transport Layer (L4)',
        'b) Internet/Network Layer (L3)',
        'c) Data Link Layer (L2)',
        'd) Application Layer (L7)',
      ],
      answer: 'b) Internet/Network Layer (L3)',
      rationale: 'IPsec operates at the Network layer, protecting IP packets.',
    },
    {
      question: 'What is the IPsec protocol that provides Confidentiality (encryption) and limited Authentication?',
      options: [
        'a) Authentication Header (AH)',
        'b) Encapsulating Security Payload (ESP)',
        'c) Internet Key Exchange (IKE)',
        'd) Transport Layer Security (TLS)',
      ],
      answer: 'b) Encapsulating Security Payload (ESP)',
      rationale: 'ESP provides both encryption (Confidentiality) and integrity/authentication (limited Authentication).',
    },
    {
      question: 'What is the primary function of the Authentication Header (AH) protocol in the IPsec suite?',
      options: [
        'a) To encrypt the payload of the IP packet.',
        'b) To negotiate the encryption key securely.',
        'c) To provide integrity and authentication for the IP packet header and payload.',
        'd) To manage dynamic firewall rules.',
      ],
      answer: 'c) To provide integrity and authentication for the IP packet header and payload.',
      rationale: 'AH ensures the data and the critical parts of the header have not been tampered with in transit.',
    },
    {
      question: 'What are the two main modes in which IPsec can operate?',
      options: [
        'a) Server Mode and Client Mode',
        'b) Transport Mode and Tunnel Mode',
        'c) AH Mode and ESP Mode',
        'd) Stateful Mode and Stateless Mode',
      ],
      answer: 'b) Transport Mode and Tunnel Mode',
      rationale: 'These describe how the IP packet is protected: just the payload (Transport) or the whole packet (Tunnel).',
    },
    {
      question: 'In IPsec Tunnel Mode, where is the security applied?',
      options: [
        'a) Only to the payload (data).',
        'b) To the original IP header and the payload.',
        'c) To the entire original IP packet, which is then encapsulated with a new, temporary IP header.',
        'd) Only to the cryptographic key exchange process.',
      ],
      answer: 'c) To the entire original IP packet, which is then encapsulated with a new, temporary IP header.',
      rationale: 'Tunnel mode hides the original sender and recipient behind a new IP header, which is essential for Site-to-Site VPNs.',
    },
    {
      question: 'Which protocol is primarily used for the control and establishment of tunnels in a Site-to-Site VPN but does not provide the actual data security?',
      options: [
        'a) IPsec ESP',
        'b) IKE (Internet Key Exchange)',
        'c) SSH',
        'd) SNMP',
      ],
      answer: 'b) IKE (Internet Key Exchange)',
      rationale: 'IKE negotiates the Security Association (SA) and the keys, but ESP/AH handle the data protection.',
    },
    {
      question: 'What is the primary risk associated with Anomaly-based detection in an IDS/IPS?',
      options: [
        'a) It is too slow to detect known, common attacks.',
        'b) It requires manual updates of known attack signatures.',
        'c) It often produces a high rate of false positives (alerting on legitimate, but unusual, traffic).',
        'd) It cannot detect encrypted traffic.',
      ],
      answer: 'c) It often produces a high rate of false positives (alerting on legitimate, but unusual, traffic).',
      rationale: 'Since "normal" traffic can change, anomaly detection can mistakenly flag legitimate, rare events as attacks.',
    },
    {
      question: 'Which of the following is an example of an attack that a signature-based IDS/IPS is least likely to detect?',
      options: [
        'a) A well-known virus whose signature has been published.',
        'b) A common SQL injection attempt.',
        'c) A zero-day attack using never-before-seen malicious code.',
        'd) An internal user attempting a dictionary attack on an internal server.',
      ],
      answer: 'c) A zero-day attack using never-before-seen malicious code.',
      rationale: 'Signature-based systems rely on known patterns, which a zero-day attack, by definition, lacks.',
    },
    {
      question: 'What Firewall type uses filtering rules that inspect traffic only up to the Transport Layer (L4) and does not examine the content of the packet?',
      options: [
        'a) Proxy Firewall',
        'b) Application Gateway Firewall',
        'c) Packet Filtering Firewall (Stateless)',
        'd) Next-Generation Firewall',
      ],
      answer: 'c) Packet Filtering Firewall (Stateless)',
      rationale: 'Basic packet filters look only at the network and transport headers (IP address, port number, protocol).',
    },
    {
      question: 'A Next-Generation Firewall (NGFW) includes which capability beyond traditional stateful inspection?',
      options: [
        'a) Integrated Intrusion Prevention (IPS) and Deep Packet Inspection (DPI) for application awareness.',
        'b) Only Layer 1 and Layer 2 filtering.',
        'c) Only basic Network Address Translation (NAT).',
        'd) Exclusively anomaly-based detection.',
      ],
      answer: 'a) Integrated Intrusion Prevention (IPS) and Deep Packet Inspection (DPI) for application awareness.',
      rationale: 'NGFWs integrate multiple security features (IPS, DPI, application control) into a single platform.',
    },
    {
      question: 'What is the main security advantage of a Host-based IDS (HIDS) over a Network-based IDS (NIDS)?',
      options: [
        'a) It is simpler to deploy across a large network.',
        'b) It can detect attacks that originate from encrypted external traffic.',
        'c) It can detect internal system events, like file modifications or unauthorized privilege escalation, that NIDS cannot see.',
        'd) It is unaffected by high network traffic volume.',
      ],
      answer: 'c) It can detect internal system events, like file modifications or unauthorized privilege escalation, that NIDS cannot see.',
      rationale: 'HIDS has visibility into local OS activity that is invisible to a network monitor.',
    },
    {
      question: 'Which common VPN protocol is most closely associated with the Remote Access VPN type, often used by individual users, and is easily supported by web browsers?',
      options: [
        'a) L2TP (Layer Two Tunneling Protocol)',
        'b) SSL/TLS (Secure Sockets Layer/Transport Layer Security)',
        'c) PPTP (Point-to-Point Tunneling Protocol)',
        'd) IPsec AH',
      ],
      answer: 'b) SSL/TLS (Secure Sockets Layer/Transport Layer Security)',
      rationale: 'SSL/TLS VPNs are popular for remote access because they use ubiquitous web browser technology (port 443).',
    },
    {
      question: 'The concept of Split Tunneling in a VPN refers to:',
      options: [
        'a) Using two different encryption protocols simultaneously.',
        'b) Encrypting traffic destined for the internet, but leaving internal traffic unencrypted.',
        'c) Sending corporate-bound traffic through the VPN tunnel, while routing personal internet traffic directly over the user\'s local connection.',
        'd) Using separate keys for encryption and authentication.',
      ],
      answer: 'c) Sending corporate-bound traffic through the VPN tunnel, while routing personal internet traffic directly over the user\'s local connection.',
      rationale: 'Split tunneling directs only necessary traffic through the secure tunnel, saving bandwidth, though it introduces some security risks.',
    },
    {
      question: 'The security association (SA) in IPsec is a fundamental concept. What does the Security Association define?',
      options: [
        'a) The IP addresses of the two endpoints.',
        'b) The specific protocols (AH or ESP), keys, algorithms, and security parameters agreed upon for a single direction of communication.',
        'c) The amount of data that can be encrypted per session.',
        'd) The overall network topology of the VPN.',
      ],
      answer: 'b) The specific protocols (AH or ESP), keys, algorithms, and security parameters agreed upon for a single direction of communication.',
      rationale: 'The SA is a one-way logical connection that bundles all the security parameters needed for IPsec processing.',
    },
  ],

  // --- Unit 3: Wireless Security and Protection (802.11, WPA, WIDS/WIPS) Questions ---
  unit3: [
    {
      question: 'What is the main purpose of the IEEE 802.11 standard?',
      options: [
        'a) Defining protocols for wired Ethernet local area networks (LANs).',
        'b) Specifying the rules for wide area network (WAN) connectivity.',
        'c) Defining the technical standards for wireless local area networks (WLANs).',
        'd) Standardizing network routing and IP addressing.',
      ],
      answer: 'c) Defining the technical standards for wireless local area networks (WLANs).',
      rationale: '802.11 is the family of standards defining Wi-Fi technology.',
    },
    {
      question: 'In an 802.11 WLAN, what term is used for the centralized device that connects wireless clients to the wired network?',
      options: [
        'a) Router',
        'b) Switch',
        'c) Access Point (AP)',
        'd) Repeater',
      ],
      answer: 'c) Access Point (AP)',
      rationale: 'The AP is the bridge between the wireless and wired network segments.',
    },
    {
      question: 'The basic unit of an 802.11 wireless network, which consists of a single Access Point and all associated wireless clients, is called a:',
      options: [
        'a) Extended Service Set (ESS)',
        'b) Independent Basic Service Set (IBSS)',
        'c) Basic Service Set (BSS)',
        'd) Distribution System (DS)',
      ],
      answer: 'c) Basic Service Set (BSS)',
      rationale: 'The BSS is the fundamental building block of an 802.11 network.',
    },
    {
      question: 'Which WPA version introduced AES (Advanced Encryption Standard) encryption combined with the CCMP (Counter Mode with Cipher Block Chaining Message Authentication Code Protocol)?',
      options: [
        'a) WPA',
        'b) WPA2',
        'c) WPA3',
        'd) WEP',
      ],
      answer: 'b) WPA2',
      rationale: 'WPA2 made AES/CCMP mandatory, replacing the less secure TKIP.',
    },
    {
      question: 'What key vulnerability of the original WEP (Wired Equivalent Privacy) protocol led to its replacement by WPA?',
      options: [
        'a) Poor coverage range.',
        'b) Inability to support modern devices.',
        'c) Weak initialization vectors (IVs) and a susceptible RC4 stream cipher, making encryption easily crackable.',
        'd) High latency for real-time applications.',
      ],
      answer: 'c) Weak initialization vectors (IVs) and a susceptible RC4 stream cipher, making encryption easily crackable.',
      rationale: 'The small IV size made it easy to collect enough traffic to crack the key.',
    },
    {
      question: 'The original WPA (Wi-Fi Protected Access) was introduced as an interim solution. What encryption protocol did it use while retaining compatibility with WEP hardware?',
      options: [
        'a) AES-CCMP',
        'b) TKIP (Temporal Key Integrity Protocol)',
        'c) EAP-TLS',
        'd) PSK-SHA',
      ],
      answer: 'b) TKIP (Temporal Key Integrity Protocol)',
      rationale: 'TKIP provided per-packet key mixing to fix the WEP IV issue while running on existing hardware.',
    },
    {
      question: 'Which key security feature introduced in WPA3 is designed to protect users even if the network password is weak or compromised, particularly in open public Wi-Fi networks?',
      options: [
        'a) TKIP',
        'b) Simultaneous Authentication of Equals (SAE)',
        'c) Pre-Shared Key (PSK)',
        'd) CCMP',
      ],
      answer: 'b) Simultaneous Authentication of Equals (SAE)',
      rationale: 'SAE (or WPA3-Personal) provides forward secrecy, which is the key enhancement over WPA2-PSK.',
    },
    {
      question: 'The WPA3 feature SAE (Simultaneous Authentication of Equals) is a modern replacement for the WPA2 PSK (Pre-Shared Key) mode. What cryptographic defense does SAE provide against offline password-guessing attacks?',
      options: [
        'a) It increases the key size to 512 bits.',
        'b) It mandates the use of digital certificates.',
        'c) It provides forward secrecy, preventing password cracking even if a passive sniffer captures the full handshake.',
        'd) It blocks all traffic based on MAC addresses.',
      ],
      answer: 'c) It provides forward secrecy, preventing password cracking even if a passive sniffer captures the full handshake.',
      rationale: 'Forward secrecy means a compromise of the key (or password) at one point does not compromise past session traffic.',
    },
    {
      question: 'What is the primary function of a Wireless Intrusion Detection System (WIDS)?',
      options: [
        'a) To automatically block unauthorized access points.',
        'b) To enforce strong password policies on wireless devices.',
        'c) To passively monitor the wireless spectrum for rogue devices, denial-of-service attacks, and known security policy violations.',
        'd) To generate new encryption keys every hour.',
      ],
      answer: 'c) To passively monitor the wireless spectrum for rogue devices, denial-of-service attacks, and known security policy violations.',
      rationale: 'WIDS detects threats; WIPS prevents them.',
    },
    {
      question: 'A Wireless Intrusion Prevention System (WIPS) is an active security measure. What specific capability does a WIPS have that a WIDS typically lacks?',
      options: [
        'a) Encrypting all wireless data.',
        'b) Automatically issuing countermeasures, such as sending de-authentication frames to disconnect malicious clients or rogue APs.',
        'c) Detecting unauthorized physical access to the network cabinet.',
        'd) Logging system events to a central server.',
      ],
      answer: 'b) Automatically issuing countermeasures, such as sending de-authentication frames to disconnect malicious clients or rogue APs.',
      rationale: 'The "Prevention" part involves actively neutralizing the threat.',
    },
    {
      question: 'Which type of attack is specifically targeted by WIDS/WIPS that involves repeatedly sending fake de-authentication or disassociation frames to disrupt client connections?',
      options: [
        'a) Evil Twin Attack',
        'b) Krack Attack',
        'c) Wireless Denial-of-Service (DoS) Attack',
        'd) Bluejacking',
      ],
      answer: 'c) Wireless Denial-of-Service (DoS) Attack',
      rationale: 'De-authentication flooding is a common way to achieve a wireless DoS.',
    },
    {
      question: 'The Evil Twin attack is a major threat to WLAN security. What defines an Evil Twin attack?',
      options: [
        'a) An attacker steals the private key of the legitimate AP.',
        'b) An attacker floods the network with too much traffic.',
        'c) An attacker sets up a rogue AP with the same SSID as a legitimate network to trick users into connecting.',
        'd) An attacker uses brute force to guess the WPA2 password.',
      ],
      answer: 'c) An attacker sets up a rogue AP with the same SSID as a legitimate network to trick users into connecting.',
      rationale: 'Users are tricked into connecting to the malicious AP, which then captures their credentials or traffic.',
    },
    {
      question: 'What is the difference between a Network-based WIDS/WIPS and a Host-based WIDS/WIPS?',
      options: [
        'a) Network-based monitors encrypted traffic only; Host-based monitors unencrypted traffic.',
        'b) Network-based uses dedicated sensor hardware to monitor the air; Host-based runs on the client device or AP itself.',
        'c) Network-based is effective for zero-day attacks; Host-based is only effective for signature-based attacks.',
        'd) Network-based operates at Layer 7; Host-based operates at Layer 2.',
      ],
      answer: 'b) Network-based uses dedicated sensor hardware to monitor the air; Host-based runs on the client device or AP itself.',
      rationale: 'Network-based systems rely on separate hardware to scan the radio frequency (RF) environment.',
    },
    {
      question: 'What does the term Rogue Access Point (Rogue AP) refer to in a corporate WLAN environment?',
      options: [
        'a) A legitimate AP that is malfunctioning.',
        'b) An AP that has been successfully updated to WPA3.',
        'c) An unauthorized AP installed on the network by an employee or intruder, bypassing security controls.',
        'd) A wireless AP configured without any password.',
      ],
      answer: 'c) An unauthorized AP installed on the network by an employee or intruder, bypassing security controls.',
      rationale: 'Rogue APs provide a backdoor to the network and are a major WIPS target.',
    },
    {
      question: 'What security mode uses a shared password for all users on the network and is typically used in home or small office environments (e.g., WPA2-PSK or WPA3-SAE)?',
      options: [
        'a) Enterprise Mode',
        'b) 802.1X Mode',
        'c) Personal Mode',
        'd) Radius Mode',
      ],
      answer: 'c) Personal Mode',
      rationale: 'Personal mode uses a single Pre-Shared Key (PSK) for all users.',
    },
    {
      question: 'What security mode requires users to authenticate using credentials (username/password or certificate) verified against an external authentication server, such as a RADIUS server (e.g., WPA2-Enterprise)?',
      options: [
        'a) Personal Mode',
        'b) PSK Mode',
        'c) Enterprise Mode (802.1X)',
        'd) Open Mode',
      ],
      answer: 'c) Enterprise Mode (802.1X)',
      rationale: 'Enterprise mode provides unique keys per user and stronger, centralized authentication.',
    },
    {
      question: 'Which protocol is primarily used by WPA2-Enterprise and WPA3-Enterprise for centralized authentication to the RADIUS server?',
      options: [
        'a) IPsec',
        'b) LDAP',
        'c) EAP (Extensible Authentication Protocol)',
        'd) TKIP',
      ],
      answer: 'c) EAP (Extensible Authentication Protocol)',
      rationale: 'EAP is a framework that handles the exchange of authentication data between the supplicant and the authentication server.',
    },
    {
      question: 'What is the fundamental security mechanism that WPA2 and WPA3 rely on to ensure data confidentiality during transit?',
      options: [
        'a) Regular changing of the SSID.',
        'b) Hiding the service set identifier (SSID).',
        'c) Strong symmetric encryption (AES-CCMP).',
        'd) Relying on physical barriers to block signals.',
      ],
      answer: 'c) Strong symmetric encryption (AES-CCMP).',
      rationale: 'AES is the mandatory encryption standard for WPA2/WPA3 (excluding legacy WPA2/TKIP).',
    },
    {
      question: 'The WPA3-Enterprise mode offers an enhancement called Optional 192-bit Security Mode. What is the primary benefit of this mode?',
      options: [
        'a) It allows for faster connection speeds.',
        'b) It supports older legacy devices that use WEP.',
        'c) It mandates the use of specific high-grade cryptography (CNSA Suite) to align with government and high-security requirements.',
        'd) It automatically segments the network for every user.',
      ],
      answer: 'c) It mandates the use of specific high-grade cryptography (CNSA Suite) to align with government and high-security requirements.',
      rationale: 'The 192-bit mode enforces top-tier cryptographic algorithms for enhanced protection.',
    },
    {
      question: 'In the context of 802.11, what does the term SSID stand for?',
      options: [
        'a) System Service Identifier',
        'b) Secure Session Indicator',
        'c) Service Set Identifier',
        'd) Standard Security Interconnect',
      ],
      answer: 'c) Service Set Identifier',
      rationale: 'The SSID is the name of the wireless network.',
    },
    {
      question: 'The process where a wireless client actively seeks out and establishes a connection with an Access Point is called:',
      options: [
        'a) Roaming',
        'b) Bridging',
        'c) Association',
        'd) Synchronization',
      ],
      answer: 'c) Association',
      rationale: 'Association is the process of a client formally joining the BSS of an AP.',
    },
    {
      question: 'A WIPS identifies a new client attempting to associate with an unauthorized neighboring AP, believing this is part of a potential attack. This is an example of which WIPS capability?',
      options: [
        'a) Rogue AP Detection',
        'b) Cryptographic Analysis',
        'c) Protocol Tunneling',
        'd) Physical Layer Filtering',
      ],
      answer: 'a) Rogue AP Detection',
      rationale: 'A WIPS constantly scans for unauthorized APs and devices trying to connect to them.',
    },
    {
      question: 'A wireless attack where the attacker collects a sequence of packets from a legitimate handshake and then uses offline processing to determine the password is known as:',
      options: [
        'a) A man-in-the-middle attack.',
        'b) A buffer overflow attack.',
        'c) A PMKID or 4-way handshake capture attack.',
        'd) A fragmentation attack.',
      ],
      answer: 'c) A PMKID or 4-way handshake capture attack.',
      rationale: 'The 4-way handshake contains the necessary data to crack the PSK offline (though this is prevented by WPA3-SAE).',
    },
    {
      question: 'What is the security risk associated with SSID cloaking (hiding the SSID)?',
      options: [
        'a) It makes the network slower due to increased overhead.',
        'b) It prevents WPA3 from functioning correctly.',
        'c) It offers minimal security, as the SSID can still be easily discovered by sniffing probe requests/responses.',
        'd) It automatically defaults the network security to WEP.',
      ],
      answer: 'c) It offers minimal security, as the SSID can still be easily discovered by sniffing probe requests/responses.',
      rationale: 'Cloaking is a weak security control because the SSID is still broadcast in management frames during client communication.',
    },
    {
      question: 'The 802.11i amendment to the 802.11 standard is the basis for which widely adopted security protocol?',
      options: [
        'a) WPA',
        'b) WPA2',
        'c) WEP',
        'd) IPsec',
      ],
      answer: 'b) WPA2',
      rationale: '802.11i finalized the security requirements that were commercialized as WPA2.',
    },
  ],

  // --- Unit 4: Identity and Access Management (IAM) Questions ---
  unit4: [
    {
      question: 'What is the primary difference between Authentication and Authorization in an IAM system?',
      options: [
        'a) Authentication is for external users; Authorization is for internal users.',
        'b) Authentication grants permissions; Authorization verifies identity.',
        'c) Authentication verifies the user\'s identity; Authorization determines what the verified user can access or do.',
        'd) Authentication is performed by a directory service; Authorization is performed by a firewall.',
      ],
      answer: 'c) Authentication verifies the user\'s identity; Authorization determines what the verified user can access or do.',
      rationale: 'Authentication answers "Who are you?"; Authorization answers "What are you allowed to do?".',
    },
    {
      question: 'The core principle of Privilege Management that states a user should be granted only the minimum level of access required to perform their specific job functions is known as:',
      options: [
        'a) Role-Based Access Control (RBAC)',
        'b) Least Access Principle (LAP)',
        'c) Principle of Least Privilege (PoLP)',
        'd) Attribute-Based Access Control (ABAC)',
      ],
      answer: 'c) Principle of Least Privilege (PoLP)',
      rationale: 'PoLP is the fundamental security concept of limiting user access to the absolute minimum necessary.',
    },
    {
      question: 'Which phase of the Identity Lifecycle is primarily concerned with removing all access rights and deleting or disabling the digital identity when an employee leaves the organization?',
      options: [
        'a) Provisioning',
        'b) Maintenance',
        'c) De-provisioning (or Offboarding)',
        'd) Access Review',
      ],
      answer: 'c) De-provisioning (or Offboarding)',
      rationale: 'De-provisioning ensures that all access is revoked to prevent security risks from stale accounts.',
    },
    {
      question: 'The step in Identity Proofing and Establishment where the user submits government-issued documents or biometric data for verification is called:',
      options: [
        'a) Credential Management',
        'b) Registration and Data Collection',
        'c) Access Provisioning',
        'd) Authorization Review',
      ],
      answer: 'b) Registration and Data Collection',
      rationale: 'This is the initial administrative step of identity establishment.',
    },
    {
      question: 'What is the function of a Directory Service (e.g., Active Directory or LDAP) in the context of IAM?',
      options: [
        'a) It executes application code and business logic.',
        'b) It manages network routing and traffic prioritization.',
        'c) It stores and manages a centralized hierarchy of user accounts, passwords, and access attributes.',
        'd) It performs endpoint security and antivirus scanning.',
      ],
      answer: 'c) It stores and manages a centralized hierarchy of user accounts, passwords, and access attributes.',
      rationale: 'Directory services are the central repository for identity information.',
    },
    {
      question: 'The three main Authentication Factors (or categories) upon which Multi-Factor Authentication (MFA) is based are:',
      options: [
        'a) Username, Password, and PIN.',
        'b) Knowledge, Possession, and Inherence.',
        'c) Access, Authorization, and Audit.',
        'd) Time, Location, and Device.',
      ],
      answer: 'b) Knowledge, Possession, and Inherence.',
      rationale: 'These correspond to Something you know, Something you have, and Something you are.',
    },
    {
      question: 'A password or a PIN falls under which category of Authentication Factor?',
      options: [
        'a) Possession (Something you have)',
        'b) Knowledge (Something you know)',
        'c) Inherence (Something you are)',
        'd) Behavioral (Something you do)',
      ],
      answer: 'b) Knowledge (Something you know)',
      rationale: 'A password or PIN is information only the user should know.',
    },
    {
      question: 'A fingerprint scan, retina scan, or facial recognition falls under which category of Authentication Factor?',
      options: [
        'a) Knowledge (Something you know)',
        'b) Possession (Something you have)',
        'c) Inherence (Something you are)',
        'd) Behavioral (Something you do)',
      ],
      answer: 'c) Inherence (Something you are)',
      rationale: 'Biometric data is inherent to the user\'s physical self.',
    },
    {
      question: 'What is the key benefit of Multi-Factor Authentication (MFA) over Single-Factor Authentication (SFA)?',
      options: [
        'a) MFA is always faster and easier for the user.',
        'b) MFA only works for cloud services, while SFA works for on-premise.',
        'c) MFA requires an attacker to compromise factors from at least two different categories, significantly increasing the difficulty of a breach.',
        'd) MFA eliminates the need for any password or PIN.',
      ],
      answer: 'c) MFA requires an attacker to compromise factors from at least two different categories, significantly increasing the difficulty of a breach.',
      rationale: 'MFA provides a layered defense, as the compromise of one factor is insufficient for access.',
    },
    {
      question: 'Which authentication method is a subset of MFA that explicitly requires two distinct factors for verification?',
      options: [
        'a) Risk-Based Authentication (RBA)',
        'b) Passwordless Authentication',
        'c) Two-Factor Authentication (2FA)',
        'd) Single Sign-On (SSO)',
      ],
      answer: 'c) Two-Factor Authentication (2FA)',
      rationale: '2FA is a specific instance of MFA that strictly requires two factors.',
    },
    {
      question: 'What is the process of confirming that the claimed identity details (e.g., name, date of birth) match verifiable information from authoritative sources?',
      options: [
        'a) Identity Proofing',
        'b) Privilege Elevation',
        'c) Role Management',
        'd) De-provisioning',
      ],
      answer: 'a) Identity Proofing',
      rationale: 'Identity proofing validates the physical identity against official records.',
    },
    {
      question: 'In Privilege Management, what mechanism simplifies authorization by assigning permissions to a job title (e.g., \'Manager\') rather than to individual users?',
      options: [
        'a) Attribute-Based Access Control (ABAC)',
        'b) Mandatory Access Control (MAC)',
        'c) Discretionary Access Control (DAC)',
        'd) Role-Based Access Control (RBAC)',
      ],
      answer: 'd) Role-Based Access Control (RBAC)',
      rationale: 'RBAC makes administration scalable by grouping permissions into roles.',
    },
    {
      question: 'What is the main security risk associated with poor Identity Lifecycle Management?',
      options: [
        'a) Too many users accessing the network at once.',
        'b) Orphaned accounts or stale access rights, leading to security vulnerabilities after users change roles or leave the company.',
        'c) Slow network speeds due to high authentication traffic.',
        'd) Users setting passwords that are too complex to remember.',
      ],
      answer: 'b) Orphaned accounts or stale access rights, leading to security vulnerabilities after users change roles or leave the company.',
      rationale: 'Orphaned accounts with old permissions are prime targets for attackers.',
    },
    {
      question: 'Password Management policies are critical for IAM. Which feature is most effective at preventing large-scale dictionary attacks against user credentials?',
      options: [
        'a) Allowing users to set short, memorable passwords.',
        'b) Implementing account lockout thresholds and requiring complex characters.',
        'c) Storing passwords in plain text for easy recovery.',
        'd) Allowing password reuse across multiple accounts.',
      ],
      answer: 'b) Implementing account lockout thresholds and requiring complex characters.',
      rationale: 'Lockout thresholds prevent automated, rapid-fire guessing of credentials.',
    },
    {
      question: 'What is the standard industry practice for securely storing user passwords within a directory service or repository?',
      options: [
        'a) Reversible encryption (e.g., AES).',
        'b) Storing them in a secure database table.',
        'c) Storing them as one-way cryptographic hashes (e.g., SHA-256) with a salt.',
        'd) Storing them only on the user\'s local device.',
      ],
      answer: 'c) Storing them as one-way cryptographic hashes (e.g., SHA-256) with a salt.',
      rationale: 'Hashing prevents recovery of the plaintext password, even if the database is compromised.',
    },
    {
      question: 'Which type of authentication factor uses contextual information like the user\'s current location, time of day, or device posture to grant or deny access?',
      options: [
        'a) Inherence Factor',
        'b) Possession Factor',
        'c) Adaptive/Context-Aware Authentication',
        'd) Passwordless Authentication',
      ],
      answer: 'c) Adaptive/Context-Aware Authentication',
      rationale: 'Adaptive authentication uses environmental context for risk scoring and access control.',
    },
    {
      question: 'Which of the following is a component of the Identity Lifecycle that ensures access rights are reviewed periodically to confirm they are still necessary and appropriate?',
      options: [
        'a) Credential Rotation',
        'b) Access Certification (or Access Review)',
        'c) Federated Identity',
        'd) Continuous Provisioning',
      ],
      answer: 'b) Access Certification (or Access Review)',
      rationale: 'Certification is the formal process of reviewing and approving current access rights.',
    },
    {
      question: 'Single Sign-On (SSO) is a key feature in Access Management. What is its primary benefit?',
      options: [
        'a) It makes every application use the same authentication protocol.',
        'b) It allows users to authenticate once and gain access to multiple independent systems without re-entering credentials.',
        'c) It eliminates the need for multi-factor authentication entirely.',
        'd) It automatically encrypts all network traffic between systems.',
      ],
      answer: 'b) It allows users to authenticate once and gain access to multiple independent systems without re-entering credentials.',
      rationale: 'SSO improves security (fewer passwords) and convenience (one login).',
    },
    {
      question: 'In the context of Identity Establishment, which step immediately follows the collection of user information and identity documents?',
      options: [
        'a) Issuing the user\'s first password.',
        'b) Granting final access permissions.',
        'c) Document and Data Validation (Verification against authoritative sources).',
        'd) Auditing all previous access attempts.',
      ],
      answer: 'c) Document and Data Validation (Verification against authoritative sources).',
      rationale: 'Validation and verification must occur before a digital identity is fully created.',
    },
    {
      question: 'A hardware security token that generates a new six-digit code every 30 seconds is an example of which authentication factor?',
      options: [
        'a) Knowledge (Something you know)',
        'b) Possession (Something you have)',
        'c) Inherence (Something you are)',
        'd) Behavioral (Something you do)',
      ],
      answer: 'b) Possession (Something you have)',
      rationale: 'The physical token is a thing the user possesses (possession factor).',
    },
    {
      question: 'What is the term for an account, usually found in a directory service, that is no longer associated with an active user but still retains its permissions and privileges?',
      options: [
        'a) Service Account',
        'b) Orphaned Account',
        'c) Dormant Account',
        'd) Elevated Account',
      ],
      answer: 'b) Orphaned Account',
      rationale: 'Orphaned accounts pose a high security risk because they are unmonitored.',
    },
    {
      question: 'Privileged Access Management (PAM) systems are used to tightly control accounts with elevated rights. What is the primary function of a PAM vault?',
      options: [
        'a) To store application data securely.',
        'b) To manage virtual machine images.',
        'c) To securely store and automatically rotate the credentials of privileged accounts (e.g., admin passwords).',
        'd) To perform backup and recovery operations for the network.',
      ],
      answer: 'c) To securely store and automatically rotate the credentials of privileged accounts (e.g., admin passwords).',
    },
    {
      question: 'Which authentication type is considered the weakest security mechanism in modern IAM systems?',
      options: [
        'a) Two-Factor Authentication (2FA)',
        'b) Single-Factor Authentication (SFA) using only a password.',
        'c) Certificate-based authentication.',
        'd) Passwordless authentication using biometrics.',
      ],
      answer: 'b) Single-Factor Authentication (SFA) using only a password.',
      rationale: 'A single password is the easiest factor to compromise (e.g., via phishing).',
    },
    {
      question: 'In the Identity Lifecycle, the initial granting of access rights and creation of a digital account for a new employee is called:',
      options: [
        'a) Re-provisioning',
        'b) De-provisioning',
        'c) Provisioning (or Onboarding)',
        'd) Access Certification',
      ],
      answer: 'c) Provisioning (or Onboarding)',
      rationale: 'Provisioning is the process of setting up the account and initial access.',
    },
    {
      question: 'The process of verifying a user\'s unique typing patterns, mouse movements, or interaction speed to add a subtle layer of continuous identity verification is known as:',
      options: [
        'a) Inherence authentication',
        'b) Possessive authentication',
        'c) Behavioral biometrics',
        'd) Adaptive authentication',
      ],
      answer: 'c) Behavioral biometrics',
      rationale: 'Behavioral biometrics uses patterns of action for continuous, subtle authentication.',
    },
  ],

  // --- Unit 5: Microsoft Active Directory Fundamentals Questions ---
  unit5: [
    {
      question: 'What is the core function of Microsoft Active Directory (AD)?',
      options: [
        'a) To manage application databases and SQL queries.',
        'b) To serve as an integrated firewall for network security.',
        'c) To centralize network identity and resource management for Windows domain environments.',
        'd) To provide dynamic IP addressing (DHCP) services.',
      ],
      answer: 'c) To centralize network identity and resource management for Windows domain environments.',
      rationale: 'AD is the central directory service for authentication and authorization in Windows domains.',
    },
    {
      question: 'Historically, Active Directory was introduced by Microsoft with which major server operating system?',
      options: [
        'a) Windows NT 4.0',
        'b) Windows 2000 Server',
        'c) Windows Server 2003',
        'd) Windows Server 2008',
      ],
      answer: 'b) Windows 2000 Server',
      rationale: 'AD was a key feature in Windows 2000, replacing the NT domain model.',
    },
    {
      question: 'In the context of IDAM, what primary role does Active Directory play?',
      options: [
        'a) Primarily providing behavioral biometrics for authentication.',
        'b) Serving as the centralized directory service for identity storage, authentication, and authorization policies.',
        'c) Acting as a cloud-based key management system.',
        'd) Performing deep packet inspection (DPI) on network traffic.',
      ],
      answer: 'b) Serving as the centralized directory service for identity storage, authentication, and authorization policies.',
      rationale: 'AD is the default directory for Windows environments.',
    },
    {
      question: 'A Domain Controller (DC) is a server running Active Directory Domain Services (AD DS). What is the primary function of a DC?',
      options: [
        'a) Running all user applications and software.',
        'b) Storing a copy of the domain database and handling all authentication and policy application requests.',
        'c) Managing external firewall rules and VPN connections.',
        'd) Serving web pages to users on the internet.',
      ],
      answer: 'b) Storing a copy of the domain database and handling all authentication and policy application requests.',
      rationale: 'DCs hold the master database and perform all core AD functions.',
    },
    {
      question: 'What happens if a network loses connection to all its Domain Controllers?',
      options: [
        'a) Only file sharing stops working.',
        'b) Users can still authenticate but cannot access shared files.',
        'c) Users will generally be unable to log in to the domain or access resources, and security policy enforcement will fail.',
        'd) The network automatically switches to a cloud-based authentication system.',
      ],
      answer: 'c) Users will generally be unable to log in to the domain or access resources, and security policy enforcement will fail.',
      rationale: 'Authentication and policy checks require a functioning DC.',
    },
    {
      question: 'Which Active Directory object is a container used to logically group users, computers, and groups, and is the smallest unit to which a Group Policy Object (GPO) can be applied?',
      options: [
        'a) Domain',
        'b) Forest',
        'c) Organizational Unit (OU)',
        'd) Global Catalog',
      ],
      answer: 'c) Organizational Unit (OU)',
      rationale: 'OUs allow for granular delegation of administrative rights and GPO application.',
    },
    {
      question: 'A Domain in Active Directory is defined as a:',
      options: [
        'a) Single building or physical location.',
        'b) Logical group of users and computers sharing a common Internet Service Provider (ISP).',
        'c) Logical grouping of users and computers that share a common security policy and directory database.',
        'd) Collection of multiple forests linked by trust relationships.',
      ],
      answer: 'c) Logical grouping of users and computers that share a common security policy and directory database.',
      rationale: 'The domain is the boundary for security and policy application.',
    },
    {
      question: 'What is the highest level of the Active Directory structure, representing the entire enterprise and encompassing one or more domains that share a common schema?',
      options: [
        'a) Domain Tree',
        'b) Forest',
        'c) Organizational Unit (OU)',
        'd) Global Catalog',
      ],
      answer: 'b) Forest',
      rationale: 'The Forest is the top-level boundary, sharing the schema and a common root trust.',
    },
    {
      question: 'When multiple Active Directory domains are linked together in a hierarchical structure, this structure is known as a:',
      options: [
        'a) Site',
        'b) Organizational Unit (OU)',
        'c) Domain Tree',
        'd) Global Catalog',
      ],
      answer: 'c) Domain Tree',
      rationale: 'A Domain Tree is a hierarchy of domains that share a contiguous namespace.',
    },
    {
      question: 'What object in Active Directory is a collection of settings that define security, application management, and desktop environment configurations for users and computers within a specific site, domain, or OU?',
      options: [
        'a) Group Policy Object (GPO)',
        'b) Security Identifier (SID)',
        'c) Organizational Unit (OU)',
        'd) Domain Name System (DNS) record',
      ],
      answer: 'a) Group Policy Object (GPO)',
      rationale: 'GPOs are the primary means of central configuration and management.',
    },
    {
      question: 'Where are Group Policy Objects (GPOs) typically processed and applied?',
      options: [
        'a) Only on the Domain Controllers.',
        'b) Only on the user\'s home router.',
        'c) Locally by the client computer or user account during startup or login.',
        'd) Only on the global firewall appliance.',
      ],
      answer: 'c) Locally by the client computer or user account during startup or login.',
      rationale: 'The client machine pulls and applies the policy settings.',
    },
    {
      question: 'A GPO applied at the Domain level will apply to:',
      options: [
        'a) Only the users in the root OU.',
        'b) Only the Domain Controllers.',
        'c) All users and computers within that entire domain, unless blocked or overridden.',
        'd) Only resources located in the same physical site.',
      ],
      answer: 'c) All users and computers within that entire domain, unless blocked or overridden.',
      rationale: 'Domain-level GPOs have a broad scope within the domain.',
    },
    {
      question: 'What feature of Active Directory ensures that if a Domain Controller fails, other DCs can take over its role seamlessly?',
      options: [
        'a) Single Sign-On (SSO)',
        'b) Multi-Master Replication',
        'c) DHCP Leasing',
        'd) Kerberos Ticket Generation',
      ],
      answer: 'b) Multi-Master Replication',
      rationale: 'Multi-Master Replication allows all DCs to accept and replicate changes, providing redundancy.',
    },
    {
      question: 'The concept of schema in Active Directory defines:',
      options: [
        'a) The physical location of all servers.',
        'b) The list of all approved applications.',
        'c) The formal definitions of every object class (e.g., User, Computer) and the attributes those objects can possess.',
        'd) The backup rotation schedule for the Domain Controllers.',
      ],
      answer: 'c) The formal definitions of every object class (e.g., User, Computer) and the attributes those objects can possess.',
      rationale: 'The schema is the underlying blueprint of the directory database.',
    },
    {
      question: 'What is the role of the Global Catalog (GC) in a multi-domain Active Directory Forest?',
      options: [
        'a) It stores all user passwords in an unencrypted format.',
        'b) It stores a partial, searchable replica of every object from every domain in the forest, enabling fast forest-wide lookups.',
        'c) It manages the time synchronization for all domain members.',
        'd) It exclusively handles printer and file sharing services.',
      ],
      answer: 'b) It stores a partial, searchable replica of every object from every domain in the forest, enabling fast forest-wide lookups.',
      rationale: 'The GC facilitates forest-wide searching and user logon.',
    },
    {
      question: 'What is the name of the built-in Active Directory protocol used for authentication?',
      options: [
        'a) NTLMv1',
        'b) OAuth 2.0',
        'c) Kerberos',
        'd) Secure Shell (SSH)',
      ],
      answer: 'c) Kerberos',
      rationale: 'Kerberos is the default and preferred authentication protocol for AD.',
    },
    {
      question: 'Within an Active Directory object\'s security properties, every user and group is represented by a unique, non-reusable identifier called the:',
      options: [
        'a) Group Policy Object (GPO)',
        'b) Globally Unique Identifier (GUID)',
        'c) Security Identifier (SID)',
        'd) Distinguished Name (DN)',
      ],
      answer: 'c) Security Identifier (SID)',
      rationale: 'The SID is the immutable identifier used by the Windows operating system for authorization checks.',
    },
    {
      question: 'What command-line tool is commonly used by administrators to force an immediate update of Group Policy on a client machine?',
      options: [
        'a) ipconfig /flushdns',
        'b) net user',
        'c) gpupdate /force',
        'd) netdom query fsmo',
      ],
      answer: 'c) gpupdate /force',
      rationale: 'This command instructs the client to immediately retrieve and apply any new GPOs.',
    },
    {
      question: 'In the hierarchical structure of Active Directory, what term describes the unique path that specifies the exact location of an object within the directory (e.g., CN=user,OU=Sales,DC=company,DC=com)?',
      options: [
        'a) Security Descriptor',
        'b) Relative Distinguished Name (RDN)',
        'c) Distinguished Name (DN)',
        'd) Global Catalog Pointer',
      ],
      answer: 'c) Distinguished Name (DN)',
      rationale: 'The DN provides the full, unambiguous path to an object in the directory structure.',
    },
    {
      question: 'A user needs to access resources in Domain B, but their account is in Domain A. What must be established between Domain A and Domain B to allow this access?',
      options: [
        'a) Replication Schedule',
        'b) Trust Relationship',
        'c) Schema Extension',
        'd) Group Policy Link',
      ],
      answer: 'b) Trust Relationship',
      rationale: 'Trusts allow one domain to authenticate users from another domain.',
    },
    {
      question: 'What is the default hierarchy and processing order of GPOs (from highest priority to lowest priority, where lowest priority is applied first)?',
      options: [
        'a) Local, Site, Domain, Organizational Unit (LSDOU)',
        'b) Site, Domain, OU, Local',
        'c) OU, Domain, Site, Local',
        'd) Domain, Site, OU, Local',
      ],
      answer: 'a) Local, Site, Domain, Organizational Unit (LSDOU)',
      rationale: 'The processing order is Local, Site, Domain, and finally OU, with later settings overriding earlier ones.',
    },
    {
      question: 'The ability to use AD credentials to access cloud services (like Microsoft 365 or Azure) is enabled by Federated Identity. What Microsoft service often facilitates this connection and authentication?',
      options: [
        'a) Group Policy Management Console (GPMC)',
        'b) Azure Active Directory Connect (Azure AD Connect) or Active Directory Federation Services (AD FS)',
        'c) DNS Forwarders',
        'd) DHCP Server',
      ],
      answer: 'b) Azure Active Directory Connect (Azure AD Connect) or Active Directory Federation Services (AD FS)',
      rationale: 'These services synchronize or federate identities between on-premises AD and Azure AD.',
    },
    {
      question: 'What is the name of the Microsoft Windows console tool primarily used to manage users, groups, and computers within an Active Directory Domain?',
      options: [
        'a) Group Policy Management Console (GPMC)',
        'b) Active Directory Users and Computers (ADUC)',
        'c) Windows Event Viewer',
        'd) Server Manager',
      ],
      answer: 'b) Active Directory Users and Computers (ADUC)',
      rationale: 'ADUC (dsa.msc) is the core administrative tool for day-to-day AD object management.',
    },
    {
      question: 'In the context of Group Policy Objects, what is the term for a setting configured at a higher level (like the Domain) that prevents a GPO configured at a lower level (like the OU) from overriding it?',
      options: [
        'a) Enforced (or No Override)',
        'b) Disabled',
        'c) Block Inheritance',
        'd) Filtering',
      ],
      answer: 'a) Enforced (or No Override)',
      rationale: 'Enforcing a GPO forces it to apply regardless of lower-level policy settings or Block Inheritance settings.',
    },
    {
      question: 'Which critical network service must be functioning correctly for Active Directory Domain Controllers and clients to find each other and communicate effectively?',
      options: [
        'a) DHCP (Dynamic Host Configuration Protocol)',
        'b) FTP (File Transfer Protocol)',
        'c) DNS (Domain Name System)',
        'd) SMTP (Simple Mail Transfer Protocol)',
      ],
      answer: 'c) DNS (Domain Name System)',
      rationale: 'AD is tightly integrated with DNS; DCs use it to register service records (SRV records) for clients to locate them.',
    },
  ],
};

// Helper function to flatten the nested unit structure into a single array
function flattenAndCategorizeQuestions(quizzesObject) {
    const allQuestions = [];
    
    // Map unit keys to readable topic names (used in the results feedback)
    const unitTopicMap = {
        unit1: 'Network/Web Fundamentals',
        unit2: 'Firewalls, IDS, and VPNs',
        unit3: 'Wireless Security (802.11/WPA)',
        unit4: 'Identity & Access Management (IAM)',
        unit5: 'Active Directory (AD)',
    };

    for (const unitKey in quizzesObject) {
        if (quizzesObject.hasOwnProperty(unitKey)) {
            const topic = unitTopicMap[unitKey] || 'Uncategorized';
            quizzesObject[unitKey].forEach(q => {
                allQuestions.push({
                    question: q.question,
                    options: q.options,
                    answer: q.answer,
                    explanation: q.rationale, // Mapping 'rationale' to 'explanation'
                    topic: topic 
                });
            });
        }
    }
    return allQuestions;
}

// Export the final, flat array under the expected name
export const allQuestions = flattenAndCategorizeQuestions(quizzes);

// **NEW: Export individual units for potential future use (like custom quiz builder)**
export const getQuestionsByUnit = (unitKey) => {
    const unitTopicMap = {
        unit1: 'Network/Web Fundamentals',
        unit2: 'Firewalls, IDS, and VPNs',
        unit3: 'Wireless Security (802.11/WPA)',
        unit4: 'Identity & Access Management (IAM)',
        unit5: 'Active Directory (AD)',
    };
    
    if (quizzes[unitKey]) {
        return quizzes[unitKey].map(q => ({
            question: q.question,
            options: q.options,
            answer: q.answer,
            explanation: q.rationale,
            topic: unitTopicMap[unitKey] || 'Uncategorized'
        }));
    }
    return [];
};

// **NEW: Get all unit names for UI display**
export const getAllUnitNames = () => {
    return [
        { id: 'unit1', name: 'Network/Web Fundamentals', count: quizzes.unit1.length },
        { id: 'unit2', name: 'Firewalls, IDS, and VPNs', count: quizzes.unit2.length },
        { id: 'unit3', name: 'Wireless Security (802.11/WPA)', count: quizzes.unit3.length },
        { id: 'unit4', name: 'Identity & Access Management (IAM)', count: quizzes.unit4.length },
        { id: 'unit5', name: 'Active Directory (AD)', count: quizzes.unit5.length }
    ];
};

// **NEW: Get total question count**
export const getTotalQuestionCount = () => {
    return allQuestions.length;
};

// **NEW: Get random questions by topic (for future study mode)**
export const getRandomQuestionsByTopic = (topic, count) => {
    const questionsByTopic = allQuestions.filter(q => q.topic === topic);
    if (questionsByTopic.length === 0) return [];
    
    const shuffled = [...questionsByTopic].sort(() => 0.5 - Math.random());
    return shuffled.slice(0, Math.min(count, shuffled.length));
};

// **NEW: Get question statistics**
export const getQuestionStatistics = () => {
    const stats = {};
    const unitTopicMap = {
        unit1: 'Network/Web Fundamentals',
        unit2: 'Firewalls, IDS, and VPNs',
        unit3: 'Wireless Security (802.11/WPA)',
        unit4: 'Identity & Access Management (IAM)',
        unit5: 'Active Directory (AD)',
    };
    
    for (const unitKey in quizzes) {
        if (quizzes.hasOwnProperty(unitKey)) {
            stats[unitTopicMap[unitKey]] = quizzes[unitKey].length;
        }
    }
    
    return {
        totalQuestions: getTotalQuestionCount(),
        byTopic: stats,
        units: getAllUnitNames()
    };
};

// **NEW: Search questions by keyword**
export const searchQuestions = (keyword) => {
    const searchTerm = keyword.toLowerCase();
    return allQuestions.filter(q => 
        q.question.toLowerCase().includes(searchTerm) ||
        q.options.some(opt => opt.toLowerCase().includes(searchTerm)) ||
        q.explanation.toLowerCase().includes(searchTerm) ||
        q.topic.toLowerCase().includes(searchTerm)
    );
};

// **NEW: Get difficulty level suggestions (for future enhancement)**
export const getDifficultyLevel = (question) => {
    // Simple heuristic based on question length and options
    const questionLength = question.question.length;
    const optionsLength = question.options.reduce((sum, opt) => sum + opt.length, 0);
    const totalLength = questionLength + optionsLength;
    
    if (totalLength > 500) return 'Advanced';
    if (totalLength > 300) return 'Intermediate';
    return 'Beginner';
};

// **NEW: Export quizzes object for direct access if needed**
export { quizzes };

// **NEW: Get all topics array**
export const getAllTopics = () => {
    return [
        'Network/Web Fundamentals',
        'Firewalls, IDS, and VPNs',
        'Wireless Security (802.11/WPA)',
        'Identity & Access Management (IAM)',
        'Active Directory (AD)'
    ];
};