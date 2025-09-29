const QUESTIONS = [
{ q: "Which of the following best describes the CIA triad in information security?", 
  choices: ["Confidentiality, Integrity, Availability", "Control, Identification, Authorization", "Confidentiality, Isolation, Accountability", "Compliance, Integrity, Authentication"], 
  answer: 0, domain: "General Security Concepts", 
  explanation: "The CIA triad refers to Confidentiality, Integrity, and Availability, the three core principles of information security." },

{ q: "What is the primary goal of implementing least privilege?", 
  choices: ["Prevent all external attacks", "Limit user access rights to only what is necessary", "Ensure encryption on all data", "Monitor employee activities"], 
  answer: 1, domain: "General Security Concepts", 
  explanation: "Least privilege minimizes potential damage by granting users only the permissions required for their job functions." },

{ q: "Which type of control is a security guard monitoring physical access?", 
  choices: ["Technical", "Administrative", "Detective", "Physical"], 
  answer: 3, domain: "General Security Concepts", 
  explanation: "A security guard is a physical control because it prevents unauthorized physical access to resources." },

{ q: "Hashing is primarily used to ensure which security property?", 
  choices: ["Confidentiality", "Integrity", "Availability", "Authentication"], 
  answer: 1, domain: "General Security Concepts", 
  explanation: "Hashing ensures integrity by verifying that data has not been altered." },

{ q: "Which security concept ensures that an action or event can be traced back to an individual?", 
  choices: ["Authorization", "Non-repudiation", "Confidentiality", "Availability"], 
  answer: 1, domain: "General Security Concepts", 
  explanation: "Non-repudiation ensures accountability by preventing individuals from denying their actions." },

{ q: "What is the main difference between symmetric and asymmetric encryption?", 
  choices: ["Symmetric uses two keys, asymmetric uses one", "Symmetric uses the same key, asymmetric uses a key pair", "Symmetric is slower, asymmetric is faster", "Symmetric only provides integrity, asymmetric only provides confidentiality"], 
  answer: 1, domain: "General Security Concepts", 
  explanation: "Symmetric encryption uses the same key for encryption and decryption, while asymmetric uses a public/private key pair." },

{ q: "Which of the following is an example of multifactor authentication?", 
  choices: ["Password and PIN", "Fingerprint and retina scan", "Password and smart card", "Username and password"], 
  answer: 2, domain: "General Security Concepts", 
  explanation: "Multifactor authentication requires different categories (e.g., something you know + something you have). A password + smart card is two factors." },

{ q: "Which document defines the acceptable use of company resources?", 
  choices: ["Privacy Policy", "Acceptable Use Policy", "Incident Response Plan", "Service Level Agreement"], 
  answer: 1, domain: "General Security Concepts", 
  explanation: "The Acceptable Use Policy (AUP) defines how employees may use company IT resources." },

{ q: "Which of the following is considered an administrative control?", 
  choices: ["Firewall rules", "Security awareness training", "Biometric locks", "Encryption"], 
  answer: 1, domain: "General Security Concepts", 
  explanation: "Administrative controls include policies, procedures, and training, such as user awareness programs." },

{ q: "Which term describes ensuring that data is available to authorized users when needed?", 
  choices: ["Integrity", "Resiliency", "Availability", "Confidentiality"], 
  answer: 2, domain: "General Security Concepts", 
  explanation: "Availability ensures data and systems are accessible to authorized users when required." },

{ q: "Which type of attack attempts to guess a password by systematically trying every possible combination?", 
  choices: ["Phishing", "Brute force", "Dictionary", "Man-in-the-middle"], 
  answer: 1, domain: "General Security Concepts", 
  explanation: "A brute force attack attempts all possible combinations until the correct password is found." },

{ q: "What is the primary function of a digital signature?", 
  choices: ["Provide confidentiality", "Provide authentication and integrity", "Provide availability", "Provide redundancy"], 
  answer: 1, domain: "General Security Concepts", 
  explanation: "Digital signatures verify the authenticity of the sender and ensure data integrity." },

{ q: "Which cryptographic algorithm is commonly used for hashing?", 
  choices: ["RSA", "AES", "SHA-256", "Diffie-Hellman"], 
  answer: 2, domain: "General Security Concepts", 
  explanation: "SHA-256 is a secure hashing algorithm used to ensure integrity." },

{ q: "Which security concept refers to dividing a network into smaller segments for security purposes?", 
  choices: ["Segmentation", "Obfuscation", "Normalization", "Enumeration"], 
  answer: 0, domain: "General Security Concepts", 
  explanation: "Segmentation isolates network parts, reducing the impact of attacks and limiting access." },

{ q: "What type of control is an intrusion detection system (IDS)?", 
  choices: ["Preventive", "Detective", "Corrective", "Compensating"], 
  answer: 1, domain: "General Security Concepts", 
  explanation: "IDS is a detective control because it monitors and alerts when suspicious activity occurs." },

{ q: "Which of the following best describes defense in depth?", 
  choices: ["Using one strong security control", "Relying only on encryption", "Layered security controls at multiple levels", "Outsourcing all security operations"], 
  answer: 2, domain: "General Security Concepts", 
  explanation: "Defense in depth means using multiple layers of security to protect systems and data." },

{ q: "Which concept ensures that users cannot deny sending an email if they actually sent it?", 
  choices: ["Integrity", "Availability", "Non-repudiation", "Authorization"], 
  answer: 2, domain: "General Security Concepts", 
  explanation: "Non-repudiation prevents someone from denying actions, often enforced with digital signatures." },

{ q: "Which type of attack relies on deceiving a user into providing sensitive information?", 
  choices: ["Phishing", "SQL injection", "DoS attack", "Replay attack"], 
  answer: 0, domain: "General Security Concepts", 
  explanation: "Phishing uses deception, typically through email or messages, to trick users into revealing information." },

{ q: "What is the role of a certificate authority (CA) in PKI?", 
  choices: ["Generate symmetric keys", "Validate and issue digital certificates", "Encrypt database entries", "Manage passwords"], 
  answer: 1, domain: "General Security Concepts", 
  explanation: "Certificate Authorities issue and validate digital certificates to establish trust in PKI." },

{ q: "What is the primary benefit of using a VPN?", 
  choices: ["Increased bandwidth", "Secure remote communication over untrusted networks", "Blocking spam emails", "Replacing firewalls"], 
  answer: 1, domain: "General Security Concepts", 
  explanation: "VPNs create encrypted tunnels to secure communication across untrusted networks like the internet." },

{ q: "Which attack targets two parties by secretly intercepting and altering communications between them?", 
  choices: ["Man-in-the-middle", "Replay attack", "Phishing", "Brute force"], 
  answer: 0, domain: "General Security Concepts", 
  explanation: "A man-in-the-middle (MITM) attack intercepts and possibly alters communication between two parties." },

{ q: "Which type of malware disguises itself as a legitimate program?", 
  choices: ["Worm", "Trojan horse", "Rootkit", "Ransomware"], 
  answer: 1, domain: "General Security Concepts", 
  explanation: "A Trojan horse appears to be a legitimate program but carries malicious code." },

{ q: "Which concept ensures that only authorized users can make changes to data?", 
  choices: ["Confidentiality", "Availability", "Integrity", "Authorization"], 
  answer: 2, domain: "General Security Concepts", 
  explanation: "Integrity ensures data remains accurate and unchanged by unauthorized users." },

{ q: "What is the primary purpose of a honeypot?", 
  choices: ["Protect production servers", "Divert and study attackers", "Block phishing emails", "Encrypt data"], 
  answer: 1, domain: "General Security Concepts", 
  explanation: "A honeypot is a decoy system designed to attract attackers and analyze their techniques." },

{ q: "What is the main difference between risk and vulnerability?", 
  choices: ["Risk is a weakness, vulnerability is potential loss", "Vulnerability is a weakness, risk is the likelihood of exploitation", "Risk is always lower than vulnerability", "They are identical concepts"], 
  answer: 1, domain: "General Security Concepts", 
  explanation: "A vulnerability is a weakness, while risk is the likelihood and impact of that weakness being exploited." },

{ q: "Which security model uses labels such as Top Secret, Secret, and Confidential?", 
  choices: ["Bell-LaPadula", "Clark-Wilson", "Biba", "Lattice-based"], 
  answer: 0, domain: "General Security Concepts", 
  explanation: "The Bell-LaPadula model enforces confidentiality using security labels." },

{ q: "Which of the following is an example of a deterrent control?", 
  choices: ["Security training", "Encryption", "Warning signs", "Backup system"], 
  answer: 2, domain: "General Security Concepts", 
  explanation: "Warning signs act as deterrent controls by discouraging malicious activity." },

{ q: "What does the principle of separation of duties help prevent?", 
  choices: ["Single point of failure", "Privilege escalation", "Fraud or abuse", "System downtime"], 
  answer: 2, domain: "General Security Concepts", 
  explanation: "Separation of duties ensures no single individual controls all parts of a process, reducing fraud risk." },

{ q: "Which of the following is a symmetric encryption algorithm?", 
  choices: ["RSA", "AES", "ECC", "Diffie-Hellman"], 
  answer: 1, domain: "General Security Concepts", 
  explanation: "AES (Advanced Encryption Standard) is a widely used symmetric encryption algorithm." },

{ q: "Which access control model uses predefined roles to assign permissions?", 
  choices: ["RBAC", "MAC", "DAC", "ABAC"], 
  answer: 0, domain: "General Security Concepts", 
  explanation: "Role-Based Access Control (RBAC) assigns permissions based on user roles." },

{ q: "Which type of attack floods a system with traffic to make it unavailable?", 
  choices: ["Phishing", "DoS", "Brute force", "Backdoor"], 
  answer: 1, domain: "General Security Concepts", 
  explanation: "A Denial-of-Service (DoS) attack overwhelms a system, making it unavailable to legitimate users." },

{ q: "What is the primary purpose of salting passwords before hashing?", 
  choices: ["Increase password length", "Prevent rainbow table attacks", "Improve encryption speed", "Enable multifactor authentication"], 
  answer: 1, domain: "General Security Concepts", 
  explanation: "Salting adds randomness to passwords, making rainbow table attacks ineffective." },

{ q: "Which protocol provides secure communication for web traffic?", 
  choices: ["HTTP", "HTTPS", "FTP", "SMTP"], 
  answer: 1, domain: "General Security Concepts", 
  explanation: "HTTPS uses TLS/SSL to secure web traffic between clients and servers." },

{ q: "Which of the following is an example of a corrective control?", 
  choices: ["Firewall", "Security camera", "Patch management", "Access policy"], 
  answer: 2, domain: "General Security Concepts", 
  explanation: "Corrective controls fix issues after they occur, like applying patches to fix vulnerabilities." },

{ q: "Which key exchange protocol is commonly used in secure communications?", 
  choices: ["RSA", "Diffie-Hellman", "AES", "DES"], 
  answer: 1, domain: "General Security Concepts", 
  explanation: "Diffie-Hellman is widely used for secure key exchange in cryptography." },

{ q: "Which type of control is designed to reduce the impact of an incident?", 
  choices: ["Preventive", "Compensating", "Corrective", "Detective"], 
  answer: 2, domain: "General Security Concepts", 
  explanation: "Corrective controls mitigate the impact after an incident, e.g., restoring backups." },

{ q: "Which type of malware replicates itself without user interaction?", 
  choices: ["Virus", "Trojan", "Worm", "Rootkit"], 
  answer: 2, domain: "General Security Concepts", 
  explanation: "Worms spread automatically across networks without user action." },

{ q: "What does two-person integrity enforce?", 
  choices: ["Two-factor authentication", "Dual control over sensitive operations", "Encrypted communication", "Mandatory access control"], 
  answer: 1, domain: "General Security Concepts", 
  explanation: "Two-person integrity requires two individuals to perform sensitive operations, reducing insider threats." },

{ q: "Which of the following is an example of strong authentication?", 
  choices: ["Username + password", "Password + OTP token", "PIN + password", "Password + secret question"], 
  answer: 1, domain: "General Security Concepts", 
  explanation: "Password + OTP token combines knowledge and possession, making it stronger authentication." },

{ q: "Which of the following is an example of a preventive control?", 
  choices: ["Incident response plan", "Firewall rules", "Audit logs", "Security cameras"], 
  answer: 1, domain: "General Security Concepts", 
  explanation: "Preventive controls stop incidents from happening, like firewalls blocking malicious traffic." },

{ q: "Which of the following is a property of asymmetric encryption?", 
  choices: ["Faster than symmetric", "Uses a single key", "Uses public and private keys", "Cannot provide authentication"], 
  answer: 2, domain: "General Security Concepts", 
  explanation: "Asymmetric encryption relies on public and private key pairs." },

{ q: "Which attack involves sending fake ARP messages to a local network?", 
  choices: ["ARP poisoning", "DNS spoofing", "MITM", "Replay attack"], 
  answer: 0, domain: "General Security Concepts", 
  explanation: "ARP poisoning corrupts the ARP table to redirect traffic in a network." },

{ q: "Which of the following is the main benefit of hashing passwords?", 
  choices: ["Faster authentication", "Prevent plaintext storage", "Increase availability", "Enable multifactor authentication"], 
  answer: 1, domain: "General Security Concepts", 
  explanation: "Hashing prevents passwords from being stored in plaintext, improving security." },

{ q: "Which framework is widely used for cybersecurity best practices?", 
  choices: ["COBIT", "ITIL", "NIST CSF", "ISO 9001"], 
  answer: 2, domain: "General Security Concepts", 
  explanation: "The NIST Cybersecurity Framework provides best practices for managing cybersecurity risks." },

{ q: "Which protocol is commonly used to encrypt emails?", 
  choices: ["S/MIME", "FTP", "IMAP", "HTTP"], 
  answer: 0, domain: "General Security Concepts", 
  explanation: "S/MIME is used to secure email through encryption and digital signatures." },

{ q: "What is the main purpose of an SLA (Service Level Agreement)?", 
  choices: ["Define acceptable use", "Outline responsibilities and service guarantees", "Set encryption standards", "Define risk tolerance"], 
  answer: 1, domain: "General Security Concepts", 
  explanation: "SLAs define service expectations, responsibilities, and performance guarantees between parties." },

{ q: "Which type of attack attempts to reuse captured authentication tokens?", 
  choices: ["Replay attack", "Brute force", "MITM", "SQL injection"], 
  answer: 0, domain: "General Security Concepts", 
  explanation: "Replay attacks involve capturing and reusing valid authentication data to gain access." },

{ q: "Which of the following is a common method to mitigate social engineering attacks?", 
  choices: ["Encryption", "Awareness training", "Firewalls", "Load balancers"], 
  answer: 1, domain: "General Security Concepts", 
  explanation: "Security awareness training helps users recognize and avoid social engineering attempts." },

{ q: "Which type of backup only copies data that changed since the last full backup?", 
  choices: ["Incremental", "Differential", "Snapshot", "Continuous"], 
  answer: 0, domain: "General Security Concepts", 
  explanation: "Incremental backups only copy data changed since the last backup, saving time and space." },

{ q: "Which of the following defines how long logs or data must be retained?", 
  choices: ["Data classification policy", "Retention policy", "Access control policy", "Audit policy"], 
  answer: 1, domain: "General Security Concepts", 
  explanation: "Retention policies specify how long organizations must keep data or logs." },

{ q: "Which encryption protocol is used by WPA3 for Wi-Fi security?", 
  choices: ["WEP", "TKIP", "AES-GCMP", "DES"], 
  answer: 2, domain: "General Security Concepts", 
  explanation: "WPA3 uses AES-GCMP for secure wireless communications." },

{ q: "Which process ensures that systems are configured securely and consistently?", 
  choices: ["Hardening", "Normalization", "Patch management", "Load balancing"], 
  answer: 0, domain: "General Security Concepts", 
  explanation: "Hardening involves securing systems by removing vulnerabilities and ensuring consistent secure configurations." },

{ q: "Which of the following is a common way to enforce confidentiality?", 
  choices: ["Backups", "Encryption", "Hashing", "Firewalls"], 
  answer: 1, domain: "General Security Concepts", 
  explanation: "Encryption is used to protect confidentiality of sensitive data." },

{ q: "Which type of security testing simulates real-world attacks?", 
  choices: ["Vulnerability scanning", "Penetration testing", "Code review", "Log analysis"], 
  answer: 1, domain: "General Security Concepts", 
  explanation: "Penetration testing simulates real-world attacks to identify exploitable weaknesses." }
];
