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
  explanation: "Penetration testing simulates real-world attacks to identify exploitable weaknesses." },

{ q: "Which type of malware encrypts files and demands payment for decryption?", 
  choices: ["Trojan", "Spyware", "Ransomware", "Rootkit"], 
  answer: 2, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "Ransomware encrypts data and requires a ransom payment to restore access." },

{ q: "What type of vulnerability arises when applications fail to sanitize user input?", 
  choices: ["SQL injection", "Privilege escalation", "Race condition", "Zero-day"], 
  answer: 0, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "Improper input validation can lead to SQL injection attacks." },

{ q: "Which attack involves exploiting simultaneous actions to manipulate shared resources?", 
  choices: ["Race condition", "Logic bomb", "Brute force", "Man-in-the-middle"], 
  answer: 0, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "A race condition occurs when processes access shared resources at the same time, creating security flaws." },

{ q: "What is the main characteristic of a zero-day vulnerability?", 
  choices: ["Already patched", "No patch available", "Occurs only on Windows", "Low severity"], 
  answer: 1, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "A zero-day vulnerability is unknown to the vendor and has no patch available." },

{ q: "Which social engineering attack involves pretending to be from technical support?", 
  choices: ["Whaling", "Vishing", "Pretexting", "Pharming"], 
  answer: 2, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "Pretexting involves creating a fabricated scenario, like impersonating IT staff, to trick a victim." },

{ q: "Which wireless attack tricks users into connecting to a malicious access point?", 
  choices: ["Evil twin", "Replay attack", "Jamming", "Bluejacking"], 
  answer: 0, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "An evil twin attack sets up a rogue AP with the same SSID to lure users." },

{ q: "Which type of malware hides its presence by altering system processes?", 
  choices: ["Worm", "Rootkit", "Trojan", "Adware"], 
  answer: 1, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "Rootkits hide malicious activity by modifying system processes or the kernel." },

{ q: "What is the main purpose of vulnerability scanning?", 
  choices: ["Exploit systems", "Identify security weaknesses", "Patch vulnerabilities automatically", "Launch penetration tests"], 
  answer: 1, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "Vulnerability scanning identifies potential weaknesses without exploiting them." },

{ q: "Which type of attack attempts to overwhelm wireless signals with interference?", 
  choices: ["Evil twin", "Jamming", "Spoofing", "Pharming"], 
  answer: 1, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "Jamming disrupts legitimate wireless communication by flooding frequencies with noise." },

{ q: "Which attack involves sending fraudulent emails that appear from a trusted source?", 
  choices: ["Phishing", "Whaling", "Vishing", "Smishing"], 
  answer: 0, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "Phishing uses fraudulent emails to trick users into revealing sensitive data." },

{ q: "Which vulnerability allows attackers to execute code in a process’s memory?", 
  choices: ["Buffer overflow", "Cross-site scripting", "Privilege escalation", "Brute force"], 
  answer: 0, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "Buffer overflow occurs when memory is overwritten, allowing code execution." },

{ q: "Which type of threat actor is primarily motivated by financial gain?", 
  choices: ["Hacktivist", "Insider", "Cybercriminal", "Nation-state"], 
  answer: 2, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "Cybercriminals typically attack systems to steal money or valuable data." },

{ q: "What type of attack injects malicious code into a website to target users?", 
  choices: ["SQL injection", "Cross-site scripting (XSS)", "Command injection", "Directory traversal"], 
  answer: 1, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "XSS injects malicious scripts into websites to execute on visitors' browsers." },

{ q: "Which best practice reduces the risk of privilege escalation?", 
  choices: ["Strong passwords", "Regular patching", "Least privilege principle", "Encryption"], 
  answer: 2, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "Applying least privilege prevents attackers from escalating privileges if accounts are compromised." },

{ q: "Which attack manipulates users into visiting a malicious website through DNS poisoning?", 
  choices: ["Pharming", "Smishing", "MITM", "Whaling"], 
  answer: 0, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "Pharming redirects users from legitimate sites to malicious ones via DNS manipulation." },

{ q: "Which vulnerability scanning type involves sending crafted inputs to test for flaws?", 
  choices: ["Credentialed scan", "Non-credentialed scan", "Fuzzing", "Static analysis"], 
  answer: 2, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "Fuzzing sends random or malformed inputs to detect vulnerabilities." },

{ q: "Which type of threat actor is often well-funded and targets government or military systems?", 
  choices: ["Hacktivist", "Nation-state", "Insider", "Script kiddie"], 
  answer: 1, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "Nation-state actors are highly skilled and funded, targeting strategic systems." },

{ q: "Which vulnerability allows attackers to move from one virtual machine to another?", 
  choices: ["VM escape", "Privilege escalation", "Sandboxing", "Buffer overflow"], 
  answer: 0, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "VM escape exploits allow attackers to break out of a virtual machine to the host or other VMs." },

{ q: "Which type of insider threat is accidental?", 
  choices: ["Malicious insider", "Negligent insider", "Disgruntled insider", "External attacker"], 
  answer: 1, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "Negligent insiders cause harm unintentionally, such as mishandling sensitive data." },

{ q: "Which technique helps protect against brute-force login attacks?", 
  choices: ["Salting", "Account lockout", "Hashing", "Encryption"], 
  answer: 1, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "Account lockout policies prevent repeated brute-force attempts by locking accounts after failures." },

{ q: "Which type of malware displays unwanted advertisements?", 
  choices: ["Adware", "Trojan", "Ransomware", "Spyware"], 
  answer: 0, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "Adware generates unwanted advertisements, sometimes bundled with other malware." },

{ q: "Which vulnerability allows directory traversal using '../' sequences?", 
  choices: ["Command injection", "Path traversal", "SQL injection", "Cross-site request forgery"], 
  answer: 1, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "Path traversal exploits use '../' to access restricted directories and files." },

{ q: "What type of wireless attack exploits the WPS feature?", 
  choices: ["PIN brute force", "Evil twin", "Deauthentication", "Jamming"], 
  answer: 0, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "WPS PIN brute force attacks exploit weak PIN authentication in Wi-Fi Protected Setup." },

{ q: "Which attack occurs when attackers resend captured authentication packets?", 
  choices: ["Replay attack", "MITM", "Brute force", "Phishing"], 
  answer: 0, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "Replay attacks involve resending valid authentication messages to gain access." },

{ q: "Which type of assessment involves actively exploiting vulnerabilities?", 
  choices: ["Penetration testing", "Vulnerability scanning", "Static code analysis", "Threat modeling"], 
  answer: 0, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "Penetration testing goes beyond scanning by exploiting vulnerabilities to demonstrate risks." },

{ q: "Which mitigation best prevents SQL injection?", 
  choices: ["Input validation", "Encryption", "Hashing", "Access logs"], 
  answer: 0, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "Input validation and parameterized queries prevent SQL injection attacks." },

{ q: "What is a primary characteristic of spyware?", 
  choices: ["Encrypts data", "Monitors user activity", "Replicates automatically", "Deletes system files"], 
  answer: 1, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "Spyware secretly monitors user activity and transmits information without consent." },

{ q: "Which attack attempts to inject commands into an application to run on the OS?", 
  choices: ["Command injection", "SQL injection", "Cross-site scripting", "Buffer overflow"], 
  answer: 0, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "Command injection occurs when attackers run arbitrary OS commands via vulnerable apps." },

{ q: "Which type of threat actor uses attacks for political or ideological motives?", 
  choices: ["Nation-state", "Hacktivist", "Script kiddie", "Insider"], 
  answer: 1, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "Hacktivists conduct attacks for political or social causes." },

{ q: "Which type of vulnerability scan uses valid user credentials?", 
  choices: ["Credentialed scan", "Non-credentialed scan", "Black-box scan", "Fuzzing"], 
  answer: 0, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "Credentialed scans use valid credentials to test vulnerabilities as an authenticated user." },

{ q: "Which attack involves flooding a target with SYN requests?", 
  choices: ["Ping flood", "SYN flood", "Smurf attack", "Replay attack"], 
  answer: 1, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "A SYN flood overwhelms a system by sending many half-open TCP requests." },

{ q: "Which method can prevent cross-site request forgery (CSRF) attacks?", 
  choices: ["Tokens in requests", "Encryption", "Firewall rules", "Input validation"], 
  answer: 0, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "CSRF tokens ensure requests come from legitimate users and not attackers." },

{ q: "What is the main goal of threat intelligence?", 
  choices: ["Exploit vulnerabilities", "Understand and anticipate threats", "Patch systems", "Monitor logs"], 
  answer: 1, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "Threat intelligence provides knowledge about adversaries, techniques, and risks." },

{ q: "Which malware spreads via self-replication without attaching to files?", 
  choices: ["Virus", "Worm", "Trojan", "Spyware"], 
  answer: 1, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "Worms self-replicate and spread independently, unlike viruses that attach to files." },

{ q: "Which vulnerability allows attackers to access uninitialized memory contents?", 
  choices: ["Race condition", "Memory leak", "Use-after-free", "Privilege escalation"], 
  answer: 2, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "Use-after-free flaws allow access to memory after it is freed, enabling exploitation." },

{ q: "Which attack attempts to guess a password from a predefined list?", 
  choices: ["Brute force", "Dictionary attack", "Rainbow table", "Replay attack"], 
  answer: 1, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "Dictionary attacks try common words or lists of passwords to gain access." },

{ q: "Which vulnerability scanner provides detailed results about missing patches?", 
  choices: ["Credentialed scanner", "Non-credentialed scanner", "Black-box tool", "Fuzzer"], 
  answer: 0, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "Credentialed scans provide detailed results on missing patches and insecure settings." },

{ q: "Which wireless attack forces clients to disconnect by sending spoofed deauth frames?", 
  choices: ["Evil twin", "Jamming", "Deauthentication attack", "Bluejacking"], 
  answer: 2, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "Deauthentication attacks force clients off legitimate APs, enabling hijacking attempts." },

{ q: "Which attack targets executives with highly customized phishing emails?", 
  choices: ["Pharming", "Whaling", "Smishing", "Vishing"], 
  answer: 1, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "Whaling is a phishing attack targeting high-level executives." },

{ q: "Which mitigation helps against insider threats?", 
  choices: ["Awareness training", "Multifactor authentication", "Separation of duties", "Encryption"], 
  answer: 2, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "Separation of duties prevents a single insider from having too much control." },

{ q: "Which assessment simulates the perspective of an external attacker?", 
  choices: ["White-box test", "Gray-box test", "Black-box test", "Credentialed scan"], 
  answer: 2, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "Black-box tests simulate external attackers with no prior knowledge." },

{ q: "Which type of vulnerability occurs when sensitive data is stored in plaintext?", 
  choices: ["Improper cryptography", "Race condition", "Cross-site scripting", "Privilege escalation"], 
  answer: 0, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "Improper cryptography occurs when sensitive data is stored or transmitted without protection." },

{ q: "Which term describes the delay between vulnerability discovery and patch release?", 
  choices: ["Exploit window", "Threat window", "Vulnerability window", "Exposure window"], 
  answer: 2, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "The vulnerability window is the time from discovery until a patch or mitigation is released." },

{ q: "Which mitigation reduces the effectiveness of rainbow table attacks?", 
  choices: ["Salting", "Encryption", "Two-factor authentication", "Input validation"], 
  answer: 0, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "Salting makes rainbow table pre-computation ineffective by adding unique random data." },

{ q: "Which vulnerability allows attackers to alter queries sent to a database?", 
  choices: ["Buffer overflow", "SQL injection", "Command injection", "Cross-site scripting"], 
  answer: 1, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "SQL injection manipulates database queries through unsanitized inputs." },

{ q: "Which type of social engineering attack is conducted via phone calls?", 
  choices: ["Vishing", "Smishing", "Phishing", "Pretexting"], 
  answer: 0, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "Vishing (voice phishing) uses phone calls to trick victims into revealing sensitive data." },

{ q: "Which mitigation reduces the risk of buffer overflow attacks?", 
  choices: ["Input validation", "Encryption", "Hashing", "Access controls"], 
  answer: 0, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "Input validation prevents attackers from sending oversized or malicious inputs." },

{ q: "Which type of assessment provides the most realistic attack simulation?", 
  choices: ["Penetration testing", "Vulnerability scanning", "Static analysis", "Log monitoring"], 
  answer: 0, domain: "Threats, Vulnerabilities, and Mitigations", 
  explanation: "Penetration tests provide realistic attack simulations by exploiting vulnerabilities." },

{ q: "Which security principle focuses on giving users only the access they need?", 
  choices: ["Defense in depth", "Least privilege", "Zero trust", "Separation of duties"], 
  answer: 1, domain: "Security Architecture", 
  explanation: "Least privilege ensures users only have the minimum access rights required to perform their tasks." },

{ q: "What is the primary goal of a demilitarized zone (DMZ)?", 
  choices: ["Encrypt traffic", "Host public-facing services", "Provide redundancy", "Monitor insider threats"], 
  answer: 1, domain: "Security Architecture", 
  explanation: "A DMZ isolates public-facing services from the internal network to reduce exposure." },

{ q: "Which type of firewall inspects traffic at the application layer?", 
  choices: ["Packet-filtering firewall", "Stateful firewall", "Next-generation firewall", "Circuit-level gateway"], 
  answer: 2, domain: "Security Architecture", 
  explanation: "Next-generation firewalls analyze traffic at the application layer, including deep packet inspection." },

{ q: "Which component is responsible for enforcing authentication and authorization in a federated identity system?", 
  choices: ["Service provider", "Identity provider", "Certificate authority", "Directory server"], 
  answer: 1, domain: "Security Architecture", 
  explanation: "Identity providers authenticate users and provide tokens to service providers in federated systems." },

{ q: "What is the main security benefit of network segmentation?", 
  choices: ["Higher bandwidth", "Reduced attack surface", "Better redundancy", "Easier logging"], 
  answer: 1, domain: "Security Architecture", 
  explanation: "Segmentation isolates parts of the network, reducing the spread of attacks." },

{ q: "Which architecture principle assumes that no device or user should be trusted by default?", 
  choices: ["Least privilege", "Zero trust", "Separation of duties", "Defense in depth"], 
  answer: 1, domain: "Security Architecture", 
  explanation: "Zero trust assumes that all access must be verified, regardless of location or user." },

{ q: "Which device is used to hide internal IP addresses from external networks?", 
  choices: ["Firewall", "IDS", "NAT gateway", "Proxy"], 
  answer: 2, domain: "Security Architecture", 
  explanation: "NAT gateways translate private IP addresses into public ones, hiding internal devices." },

{ q: "Which type of IDS actively blocks malicious traffic?", 
  choices: ["Passive IDS", "IPS", "SIEM", "Firewall"], 
  answer: 1, domain: "Security Architecture", 
  explanation: "An Intrusion Prevention System (IPS) can block or reject traffic in real time." },

{ q: "Which access control model is based on user roles?", 
  choices: ["RBAC", "MAC", "DAC", "ABAC"], 
  answer: 0, domain: "Security Architecture", 
  explanation: "Role-Based Access Control (RBAC) assigns permissions according to job functions." },

{ q: "Which security control ensures continued operations during a data center power outage?", 
  choices: ["Firewall", "Backup generator", "IDS", "Proxy server"], 
  answer: 1, domain: "Security Architecture", 
  explanation: "Backup generators provide power continuity in case of outages." },

{ q: "Which technology creates isolated environments for running applications securely?", 
  choices: ["Firewalls", "Hypervisors", "Containers", "Proxies"], 
  answer: 2, domain: "Security Architecture", 
  explanation: "Containers isolate applications, improving security by limiting interaction with the host system." },

{ q: "Which network design principle ensures that a single failure does not bring down the system?", 
  choices: ["Segmentation", "Redundancy", "Obfuscation", "Hardening"], 
  answer: 1, domain: "Security Architecture", 
  explanation: "Redundancy ensures systems remain available even if one component fails." },

{ q: "Which cryptographic concept ensures that messages cannot be altered without detection?", 
  choices: ["Confidentiality", "Integrity", "Availability", "Non-repudiation"], 
  answer: 1, domain: "Security Architecture", 
  explanation: "Integrity ensures that data remains unmodified and tamper-evident." },

{ q: "Which system collects and correlates security log data across the enterprise?", 
  choices: ["NIDS", "SIEM", "Proxy", "WAF"], 
  answer: 1, domain: "Security Architecture", 
  explanation: "A SIEM aggregates, correlates, and analyzes security events for incident detection." },

{ q: "Which type of VPN requires SSL/TLS for secure connectivity?", 
  choices: ["IPSec VPN", "SSL VPN", "PPTP VPN", "GRE VPN"], 
  answer: 1, domain: "Security Architecture", 
  explanation: "SSL VPNs use TLS encryption for secure remote access." },

{ q: "Which security architecture concept ensures critical systems are physically separate?", 
  choices: ["Air gap", "Zero trust", "Defense in depth", "Load balancing"], 
  answer: 0, domain: "Security Architecture", 
  explanation: "An air gap physically separates critical systems from unsecured networks." },

{ q: "Which protocol secures directory authentication traffic?", 
  choices: ["LDAP", "LDAPS", "RADIUS", "TACACS+"], 
  answer: 1, domain: "Security Architecture", 
  explanation: "LDAPS secures LDAP communications with TLS/SSL." },

{ q: "Which authentication method uses tickets for access?", 
  choices: ["OAuth", "Kerberos", "SAML", "RADIUS"], 
  answer: 1, domain: "Security Architecture", 
  explanation: "Kerberos uses tickets issued by a Key Distribution Center (KDC) for authentication." },

{ q: "Which device inspects and filters HTTP traffic specifically?", 
  choices: ["WAF", "IDS", "SIEM", "NAC"], 
  answer: 0, domain: "Security Architecture", 
  explanation: "A Web Application Firewall (WAF) protects against application-layer attacks like XSS and SQL injection." },

{ q: "Which security concept ensures that two people are required to perform sensitive actions?", 
  choices: ["Least privilege", "Separation of duties", "Dual control", "Zero trust"], 
  answer: 2, domain: "Security Architecture", 
  explanation: "Dual control requires two individuals to complete critical tasks, reducing insider threats." },

{ q: "Which type of proxy caches content to improve performance?", 
  choices: ["Transparent proxy", "Forward proxy", "Reverse proxy", "Caching proxy"], 
  answer: 3, domain: "Security Architecture", 
  explanation: "A caching proxy stores content to speed up repeated requests and reduce load." },

{ q: "Which type of access control is based on rules set by a system administrator?", 
  choices: ["DAC", "MAC", "RBAC", "ABAC"], 
  answer: 1, domain: "Security Architecture", 
  explanation: "Mandatory Access Control (MAC) enforces rules defined by administrators, not users." },

{ q: "Which authentication protocol uses a challenge-response mechanism?", 
  choices: ["CHAP", "PAP", "RADIUS", "Kerberos"], 
  answer: 0, domain: "Security Architecture", 
  explanation: "CHAP authenticates using a challenge-response handshake instead of sending passwords in cleartext." },

{ q: "Which system ensures compliance with security baselines before granting network access?", 
  choices: ["IDS", "NAC", "SIEM", "Proxy"], 
  answer: 1, domain: "Security Architecture", 
  explanation: "Network Access Control (NAC) checks compliance before allowing devices onto the network." },

{ q: "Which type of cryptography uses the same key for encryption and decryption?", 
  choices: ["Asymmetric", "Symmetric", "Hashing", "Steganography"], 
  answer: 1, domain: "Security Architecture", 
  explanation: "Symmetric cryptography relies on one shared key for both encryption and decryption." },

{ q: "Which control ensures sensitive data is unreadable if stolen?", 
  choices: ["Hashing", "Obfuscation", "Encryption", "Redundancy"], 
  answer: 2, domain: "Security Architecture", 
  explanation: "Encryption protects confidentiality by making data unreadable without the decryption key." },

{ q: "Which type of attack is a reverse proxy most effective against?", 
  choices: ["SQL injection", "DDoS", "ARP poisoning", "Man-in-the-middle"], 
  answer: 1, domain: "Security Architecture", 
  explanation: "Reverse proxies can help mitigate DDoS attacks by absorbing malicious traffic." },

{ q: "Which standard defines best practices for information security management systems (ISMS)?", 
  choices: ["ISO 9001", "ISO 27001", "NIST CSF", "COBIT"], 
  answer: 1, domain: "Security Architecture", 
  explanation: "ISO/IEC 27001 is the international standard for ISMS best practices." },

{ q: "Which concept ensures that critical services remain available even during disasters?", 
  choices: ["Redundancy", "Resiliency", "Obfuscation", "Air gap"], 
  answer: 1, domain: "Security Architecture", 
  explanation: "Resiliency focuses on continuing operations despite disruptions." },

{ q: "Which model uses attributes like time and location to grant access?", 
  choices: ["RBAC", "MAC", "DAC", "ABAC"], 
  answer: 3, domain: "Security Architecture", 
  explanation: "Attribute-Based Access Control (ABAC) evaluates multiple attributes for access decisions." },

{ q: "Which key distribution method relies on asymmetric cryptography?", 
  choices: ["Symmetric key exchange", "Diffie-Hellman", "Hashing", "Salting"], 
  answer: 1, domain: "Security Architecture", 
  explanation: "Diffie-Hellman allows secure key exchange over untrusted networks using asymmetric methods." },

{ q: "Which concept ensures that sensitive data is not exposed during system testing?", 
  choices: ["Tokenization", "Encryption", "Hashing", "Redundancy"], 
  answer: 0, domain: "Security Architecture", 
  explanation: "Tokenization replaces sensitive data with non-sensitive equivalents during testing or processing." },

{ q: "Which cloud deployment model is shared among multiple organizations with common goals?", 
  choices: ["Public cloud", "Private cloud", "Hybrid cloud", "Community cloud"], 
  answer: 3, domain: "Security Architecture", 
  explanation: "Community clouds are shared by organizations with similar needs and security requirements." },

{ q: "Which principle requires that systems continue operating despite hardware failures?", 
  choices: ["Obfuscation", "Fault tolerance", "Zero trust", "Hardening"], 
  answer: 1, domain: "Security Architecture", 
  explanation: "Fault tolerance ensures systems continue functioning even when components fail." },

{ q: "Which type of cryptographic attack attempts to find two different inputs producing the same hash?", 
  choices: ["Birthday attack", "Brute force attack", "Replay attack", "Collision attack"], 
  answer: 3, domain: "Security Architecture", 
  explanation: "Collision attacks exploit hashing algorithms to find two inputs with the same hash value." },

{ q: "Which type of cloud service provides virtual machines and networking resources?", 
  choices: ["IaaS", "PaaS", "SaaS", "FaaS"], 
  answer: 0, domain: "Security Architecture", 
  explanation: "Infrastructure as a Service (IaaS) provides virtualized computing and networking infrastructure." },

{ q: "Which type of device prevents unauthorized data exfiltration by monitoring outbound traffic?", 
  choices: ["Firewall", "IDS", "DLP system", "Proxy"], 
  answer: 2, domain: "Security Architecture", 
  explanation: "Data Loss Prevention (DLP) systems monitor and block unauthorized data transfers." },

{ q: "Which technology allows different operating systems to run on a single host?", 
  choices: ["Containers", "Hypervisors", "Proxies", "Load balancers"], 
  answer: 1, domain: "Security Architecture", 
  explanation: "Hypervisors allow multiple virtual machines with different OSes to run on one physical host." },

{ q: "Which security model prevents write-downs to lower classification levels?", 
  choices: ["Bell-LaPadula", "Biba", "Clark-Wilson", "ABAC"], 
  answer: 0, domain: "Security Architecture", 
  explanation: "Bell-LaPadula enforces confidentiality by preventing subjects from writing down to lower levels." },

{ q: "Which type of architecture places controls closest to the resource being protected?", 
  choices: ["Perimeter-based", "Microsegmentation", "Zero trust", "Air gap"], 
  answer: 1, domain: "Security Architecture", 
  explanation: "Microsegmentation applies security controls at the workload or application level." },

{ q: "Which key management practice reduces the risk of key compromise?", 
  choices: ["Using the same key for all systems", "Key rotation", "Plaintext storage", "Disabling encryption"], 
  answer: 1, domain: "Security Architecture", 
  explanation: "Regular key rotation reduces the risk of long-term exposure if keys are compromised." },

{ q: "Which network design ensures sensitive data is logically isolated within VLANs?", 
  choices: ["Redundancy", "Segmentation", "Load balancing", "Hardening"], 
  answer: 1, domain: "Security Architecture", 
  explanation: "VLAN segmentation isolates traffic logically, improving security and reducing attack spread." },

{ q: "Which system verifies the integrity of operating system files at startup?", 
  choices: ["TPM", "SIEM", "IDS", "DLP"], 
  answer: 0, domain: "Security Architecture", 
  explanation: "Trusted Platform Module (TPM) verifies OS integrity during secure boot." },

{ q: "Which protocol allows single sign-on (SSO) between web applications?", 
  choices: ["Kerberos", "SAML", "RADIUS", "LDAP"], 
  answer: 1, domain: "Security Architecture", 
  explanation: "SAML enables SSO by exchanging authentication and authorization data between parties." },

{ q: "Which technology helps prevent credential theft by isolating authentication secrets?", 
  choices: ["HSM", "TPM", "VPN", "Firewall"], 
  answer: 0, domain: "Security Architecture", 
  explanation: "Hardware Security Modules (HSMs) securely store and protect authentication secrets." },

{ q: "Which cloud model combines private and public cloud resources?", 
  choices: ["Private", "Hybrid", "Community", "Public"], 
  answer: 1, domain: "Security Architecture", 
  explanation: "Hybrid cloud combines private and public cloud services to balance control and scalability." },

{ q: "Which authentication mechanism provides time-based one-time passwords?", 
  choices: ["TOTP", "HOTP", "Biometrics", "SAML"], 
  answer: 0, domain: "Security Architecture", 
  explanation: "TOTP generates time-based one-time passwords for stronger authentication." },

{ q: "Which phase of incident response involves containing and stopping an attack?", 
  choices: ["Preparation", "Detection", "Containment", "Recovery"], 
  answer: 2, domain: "Security Operations", 
  explanation: "Containment focuses on isolating and stopping the attack before it spreads further." },

{ q: "Which tool is commonly used to monitor network traffic in real time?", 
  choices: ["Wireshark", "Nmap", "Metasploit", "Nessus"], 
  answer: 0, domain: "Security Operations", 
  explanation: "Wireshark is a packet analyzer used to capture and analyze real-time network traffic." },

{ q: "What is the purpose of a playbook in incident response?", 
  choices: ["To define access policies", "To provide step-by-step response procedures", "To configure firewalls", "To encrypt backups"], 
  answer: 1, domain: "Security Operations", 
  explanation: "Playbooks provide structured, repeatable steps for responding to specific security incidents." },

{ q: "Which metric measures the average time taken to detect a security incident?", 
  choices: ["MTTR", "MTBF", "MTTD", "RTO"], 
  answer: 2, domain: "Security Operations", 
  explanation: "Mean Time to Detect (MTTD) is the average time it takes to identify an incident." },

{ q: "Which type of backup copies all data regardless of changes?", 
  choices: ["Incremental", "Differential", "Full backup", "Snapshot"], 
  answer: 2, domain: "Security Operations", 
  explanation: "Full backups copy all data, regardless of whether it has changed since the last backup." },

{ q: "Which log type records successful and failed login attempts?", 
  choices: ["Application log", "Security log", "System log", "Performance log"], 
  answer: 1, domain: "Security Operations", 
  explanation: "Security logs track authentication attempts, including both successes and failures." },

{ q: "Which tool is primarily used to detect vulnerabilities in a system?", 
  choices: ["SIEM", "IDS", "Vulnerability scanner", "Firewall"], 
  answer: 2, domain: "Security Operations", 
  explanation: "Vulnerability scanners identify weaknesses in systems before they can be exploited." },

{ q: "Which metric defines the maximum tolerable downtime for a system?", 
  choices: ["MTTR", "RTO", "RPO", "MTBF"], 
  answer: 1, domain: "Security Operations", 
  explanation: "Recovery Time Objective (RTO) is the maximum acceptable downtime for a system." },

{ q: "Which forensic practice ensures digital evidence remains unchanged?", 
  choices: ["Hashing", "Encryption", "Compression", "Redundancy"], 
  answer: 0, domain: "Security Operations", 
  explanation: "Hashing validates integrity, ensuring digital evidence is not altered during collection." },

{ q: "Which type of testing verifies that incident response procedures work effectively?", 
  choices: ["Penetration testing", "Tabletop exercises", "Vulnerability scanning", "Red teaming"], 
  answer: 1, domain: "Security Operations", 
  explanation: "Tabletop exercises simulate incidents to test and improve response plans." },

{ q: "Which backup strategy stores copies of data offsite?", 
  choices: ["Incremental", "Differential", "Cloud backup", "Snapshot"], 
  answer: 2, domain: "Security Operations", 
  explanation: "Cloud or offsite backups protect against disasters that affect on-premises systems." },

{ q: "Which term describes the average time to restore a system after an incident?", 
  choices: ["MTTR", "RTO", "RPO", "MTBF"], 
  answer: 0, domain: "Security Operations", 
  explanation: "Mean Time to Repair (MTTR) measures the average time to restore functionality after a failure." },

{ q: "Which log analysis technique looks for unusual behavior?", 
  choices: ["Baseline comparison", "Hashing", "Encryption", "Salting"], 
  answer: 0, domain: "Security Operations", 
  explanation: "Baseline comparison helps identify anomalies by comparing logs against normal activity." },

{ q: "Which security control prevents attackers from escalating privileges if accounts are compromised?", 
  choices: ["Least privilege", "Encryption", "Hashing", "Segmentation"], 
  answer: 0, domain: "Security Operations", 
  explanation: "Applying least privilege limits damage if an account is compromised." },

{ q: "Which part of incident response ensures lessons learned are documented?", 
  choices: ["Preparation", "Detection", "Containment", "Post-incident review"], 
  answer: 3, domain: "Security Operations", 
  explanation: "Post-incident reviews identify improvements and update policies after incidents." },

{ q: "Which disaster recovery site is fully equipped and can be used immediately?", 
  choices: ["Cold site", "Warm site", "Hot site", "Hybrid site"], 
  answer: 2, domain: "Security Operations", 
  explanation: "Hot sites are fully operational facilities ready for immediate use." },

{ q: "Which process ensures backups are tested regularly?", 
  choices: ["Backup validation", "Integrity checking", "Hashing", "Redundancy"], 
  answer: 0, domain: "Security Operations", 
  explanation: "Backup validation ensures backup data can actually be restored during recovery." },

{ q: "Which type of threat hunting uses known indicators of compromise (IOCs)?", 
  choices: ["Intelligence-driven", "Analytics-driven", "Hypothesis-driven", "Proactive-driven"], 
  answer: 0, domain: "Security Operations", 
  explanation: "Intelligence-driven hunting uses known IOCs to search for threats in systems." },

{ q: "Which forensic principle ensures evidence is accounted for at all times?", 
  choices: ["Hashing", "Chain of custody", "Encryption", "Replication"], 
  answer: 1, domain: "Security Operations", 
  explanation: "Chain of custody documents who handled evidence and when, ensuring integrity in court." },

{ q: "Which monitoring approach triggers alerts when a known attack pattern occurs?", 
  choices: ["Anomaly-based", "Signature-based", "Heuristic-based", "Behavioral-based"], 
  answer: 1, domain: "Security Operations", 
  explanation: "Signature-based detection identifies attacks by matching known patterns." },

{ q: "Which phase of business continuity planning identifies critical systems?", 
  choices: ["Risk assessment", "Business impact analysis", "Recovery testing", "Redundancy planning"], 
  answer: 1, domain: "Security Operations", 
  explanation: "Business Impact Analysis (BIA) identifies critical systems and their impact if disrupted." },

{ q: "Which monitoring tool centralizes logs from multiple systems?", 
  choices: ["IDS", "Firewall", "SIEM", "Proxy"], 
  answer: 2, domain: "Security Operations", 
  explanation: "SIEM systems aggregate and correlate logs from different sources for analysis." },

{ q: "Which recovery strategy prioritizes restoring the most critical systems first?", 
  choices: ["Incremental recovery", "Phased recovery", "Critical path recovery", "Sequential recovery"], 
  answer: 2, domain: "Security Operations", 
  explanation: "Critical path recovery restores essential systems before less important ones." },

{ q: "Which type of test simulates a real cyberattack to test defenses?", 
  choices: ["Tabletop exercise", "Penetration test", "Baseline test", "Vulnerability scan"], 
  answer: 1, domain: "Security Operations", 
  explanation: "Penetration tests simulate real attacks to assess security effectiveness." },

{ q: "Which backup type copies only data that changed since the last full backup?", 
  choices: ["Differential", "Incremental", "Snapshot", "Continuous"], 
  answer: 1, domain: "Security Operations", 
  explanation: "Incremental backups copy only changes since the last full or incremental backup." },

{ q: "Which incident response phase focuses on restoring normal operations?", 
  choices: ["Containment", "Recovery", "Preparation", "Detection"], 
  answer: 1, domain: "Security Operations", 
  explanation: "Recovery restores systems and returns business to normal operations." },

{ q: "Which team is responsible for managing security incidents?", 
  choices: ["SOC", "IR Team", "Blue Team", "All of the above"], 
  answer: 3, domain: "Security Operations", 
  explanation: "SOC, IR teams, and blue teams all play roles in managing incidents." },

{ q: "Which disaster recovery site provides basic infrastructure but not equipment?", 
  choices: ["Hot site", "Warm site", "Cold site", "Hybrid site"], 
  answer: 2, domain: "Security Operations", 
  explanation: "Cold sites provide physical space and utilities but lack IT equipment." },

{ q: "Which metric defines acceptable data loss in time units?", 
  choices: ["RTO", "MTTR", "RPO", "MTBF"], 
  answer: 2, domain: "Security Operations", 
  explanation: "Recovery Point Objective (RPO) defines how much data loss is tolerable in terms of time." },

{ q: "Which monitoring method compares current activity to historical norms?", 
  choices: ["Signature-based", "Anomaly-based", "Heuristic-based", "Rule-based"], 
  answer: 1, domain: "Security Operations", 
  explanation: "Anomaly-based monitoring looks for deviations from baseline behavior." },

{ q: "Which control ensures that critical systems are available during natural disasters?", 
  choices: ["Encryption", "Redundancy", "Segmentation", "Hashing"], 
  answer: 1, domain: "Security Operations", 
  explanation: "Redundancy keeps systems available by having backup resources in place." },

{ q: "Which log type records errors and crashes of applications?", 
  choices: ["Application log", "System log", "Security log", "Performance log"], 
  answer: 0, domain: "Security Operations", 
  explanation: "Application logs record events such as errors and crashes within applications." },

{ q: "Which response strategy isolates a compromised system from the network?", 
  choices: ["Detection", "Containment", "Recovery", "Eradication"], 
  answer: 1, domain: "Security Operations", 
  explanation: "Containment isolates compromised systems to prevent spread of an attack." },

{ q: "Which SIEM feature identifies correlated attacks across systems?", 
  choices: ["Aggregation", "Correlation", "Normalization", "Tokenization"], 
  answer: 1, domain: "Security Operations", 
  explanation: "Correlation links events from multiple sources to identify complex attacks." },

{ q: "Which recovery method restores systems using preconfigured images?", 
  choices: ["Bare-metal recovery", "Incremental recovery", "Differential restore", "File-level restore"], 
  answer: 0, domain: "Security Operations", 
  explanation: "Bare-metal recovery uses full images to restore systems on new hardware." },

{ q: "Which incident response step removes malicious software from a system?", 
  choices: ["Eradication", "Recovery", "Containment", "Detection"], 
  answer: 0, domain: "Security Operations", 
  explanation: "Eradication removes malware and other threats from compromised systems." },

{ q: "Which forensic technique creates an exact copy of digital evidence?", 
  choices: ["Imaging", "Hashing", "Encryption", "Replication"], 
  answer: 0, domain: "Security Operations", 
  explanation: "Imaging creates a bit-for-bit copy of digital evidence for analysis." },

{ q: "Which metric measures the average time between system failures?", 
  choices: ["MTTR", "MTTD", "MTBF", "RPO"], 
  answer: 2, domain: "Security Operations", 
  explanation: "Mean Time Between Failures (MTBF) estimates system reliability." },

{ q: "Which process involves continuously searching for unknown threats?", 
  choices: ["Threat modeling", "Threat hunting", "Vulnerability scanning", "Penetration testing"], 
  answer: 1, domain: "Security Operations", 
  explanation: "Threat hunting is proactive detection of unknown threats inside the network." },

{ q: "Which phase of incident response involves preparing tools and policies?", 
  choices: ["Preparation", "Containment", "Detection", "Recovery"], 
  answer: 0, domain: "Security Operations", 
  explanation: "Preparation ensures readiness through training, tools, and policies." },

{ q: "Which backup method keeps data continuously updated?", 
  choices: ["Incremental", "Differential", "Snapshot", "Continuous data protection"], 
  answer: 3, domain: "Security Operations", 
  explanation: "Continuous data protection updates backups in near real-time." },

{ q: "Which forensic principle requires documenting every action taken on evidence?", 
  choices: ["Integrity validation", "Chain of custody", "Confidentiality", "Non-repudiation"], 
  answer: 1, domain: "Security Operations", 
  explanation: "Chain of custody ensures evidence handling is documented to maintain validity." },

{ q: "Which monitoring approach detects threats based on abnormal user behavior?", 
  choices: ["Signature-based", "Anomaly-based", "Heuristic-based", "Baseline-based"], 
  answer: 1, domain: "Security Operations", 
  explanation: "Anomaly-based monitoring detects deviations in user behavior that may indicate threats." },

{ q: "Which control ensures system recovery is possible after ransomware?", 
  choices: ["Encryption", "Segmentation", "Regular backups", "Hashing"], 
  answer: 2, domain: "Security Operations", 
  explanation: "Regular backups ensure data can be restored after ransomware attacks." },

{ q: "Which type of test evaluates staff awareness and response to phishing?", 
  choices: ["Red team test", "Penetration test", "Phishing simulation", "Tabletop exercise"], 
  answer: 2, domain: "Security Operations", 
  explanation: "Phishing simulations test how employees respond to simulated phishing emails." },

{ q: "Which disaster recovery site has partial equipment and requires some setup?", 
  choices: ["Hot site", "Warm site", "Cold site", "Hybrid site"], 
  answer: 1, domain: "Security Operations", 
  explanation: "Warm sites have some infrastructure and require additional configuration to be fully functional." },

{ q: "Which security practice ensures employees know how to report suspicious activities?", 
  choices: ["Technical training", "Security awareness training", "Incident response training", "Forensic training"], 
  answer: 1, domain: "Security Operations", 
  explanation: "Security awareness training educates employees on identifying and reporting threats." },

{ q: "Which document defines the overall direction of security within an organization?", 
  choices: ["Policy", "Standard", "Procedure", "Guideline"], 
  answer: 0, domain: "Security Program Management & Oversight", 
  explanation: "Policies define high-level security objectives and direction for the organization." },

{ q: "Which framework is commonly used for cybersecurity risk management?", 
  choices: ["ISO 27001", "NIST CSF", "COBIT", "ITIL"], 
  answer: 1, domain: "Security Program Management & Oversight", 
  explanation: "NIST Cybersecurity Framework (CSF) provides guidelines for managing cybersecurity risks." },

{ q: "Which law protects healthcare data in the United States?", 
  choices: ["GDPR", "SOX", "HIPAA", "PCI DSS"], 
  answer: 2, domain: "Security Program Management & Oversight", 
  explanation: "HIPAA regulates how healthcare organizations protect patient data." },

{ q: "Which compliance requirement applies to organizations handling credit card data?", 
  choices: ["GDPR", "PCI DSS", "HIPAA", "FERPA"], 
  answer: 1, domain: "Security Program Management & Oversight", 
  explanation: "PCI DSS applies to organizations that store, process, or transmit credit card data." },

{ q: "Which role is responsible for day-to-day security operations?", 
  choices: ["CISO", "CIO", "Security analyst", "Auditor"], 
  answer: 2, domain: "Security Program Management & Oversight", 
  explanation: "Security analysts monitor and manage daily security operations." },

{ q: "Which role is accountable for the overall security strategy?", 
  choices: ["CISO", "CIO", "System administrator", "Network engineer"], 
  answer: 0, domain: "Security Program Management & Oversight", 
  explanation: "The Chief Information Security Officer (CISO) oversees security strategy and governance." },

{ q: "Which principle requires that risks be managed at an acceptable level?", 
  choices: ["Risk tolerance", "Risk avoidance", "Risk mitigation", "Risk acceptance"], 
  answer: 0, domain: "Security Program Management & Oversight", 
  explanation: "Risk tolerance defines the level of risk an organization is willing to accept." },

{ q: "Which risk response involves transferring risk to a third party?", 
  choices: ["Avoidance", "Mitigation", "Transference", "Acceptance"], 
  answer: 2, domain: "Security Program Management & Oversight", 
  explanation: "Risk transference shifts risk to a third party, often via insurance or outsourcing." },

{ q: "Which law protects personal data of EU citizens?", 
  choices: ["PCI DSS", "HIPAA", "GDPR", "SOX"], 
  answer: 2, domain: "Security Program Management & Oversight", 
  explanation: "The General Data Protection Regulation (GDPR) protects EU citizens' personal data." },

{ q: "Which activity ensures employees understand organizational security policies?", 
  choices: ["Technical controls", "Risk assessment", "Awareness training", "Encryption"], 
  answer: 2, domain: "Security Program Management & Oversight", 
  explanation: "Security awareness training ensures employees understand and follow security policies." },

{ q: "Which type of audit verifies compliance with regulations like PCI DSS?", 
  choices: ["Internal audit", "External audit", "Vulnerability scan", "Penetration test"], 
  answer: 1, domain: "Security Program Management & Oversight", 
  explanation: "External audits validate compliance with industry regulations and standards." },

{ q: "Which framework focuses on IT governance and management?", 
  choices: ["COBIT", "ISO 27001", "NIST CSF", "PCI DSS"], 
  answer: 0, domain: "Security Program Management & Oversight", 
  explanation: "COBIT provides a framework for IT governance and management." },

{ q: "Which regulation applies to protecting student educational records in the U.S.?", 
  choices: ["FERPA", "HIPAA", "GDPR", "SOX"], 
  answer: 0, domain: "Security Program Management & Oversight", 
  explanation: "FERPA protects student education records and privacy rights." },

{ q: "Which type of risk is associated with financial loss from cyberattacks?", 
  choices: ["Strategic risk", "Operational risk", "Financial risk", "Compliance risk"], 
  answer: 2, domain: "Security Program Management & Oversight", 
  explanation: "Financial risk includes monetary losses due to cyber incidents." },

{ q: "Which document provides detailed steps to achieve security policy objectives?", 
  choices: ["Policy", "Standard", "Procedure", "Guideline"], 
  answer: 2, domain: "Security Program Management & Oversight", 
  explanation: "Procedures provide step-by-step instructions to implement policies." },

{ q: "Which concept ensures accountability by documenting who has access to data?", 
  choices: ["Authentication", "Authorization", "Auditing", "Non-repudiation"], 
  answer: 2, domain: "Security Program Management & Oversight", 
  explanation: "Auditing ensures accountability by recording access and actions taken on data." },

{ q: "Which document provides recommendations but not mandatory requirements?", 
  choices: ["Policy", "Standard", "Procedure", "Guideline"], 
  answer: 3, domain: "Security Program Management & Oversight", 
  explanation: "Guidelines provide best practices but are not mandatory like policies or standards." },

{ q: "Which regulation applies to financial reporting in publicly traded U.S. companies?", 
  choices: ["GDPR", "SOX", "HIPAA", "PCI DSS"], 
  answer: 1, domain: "Security Program Management & Oversight", 
  explanation: "Sarbanes-Oxley (SOX) ensures accuracy of financial reporting and controls." },

{ q: "Which control type includes encryption and firewalls?", 
  choices: ["Technical", "Administrative", "Physical", "Compensating"], 
  answer: 0, domain: "Security Program Management & Oversight", 
  explanation: "Technical controls include mechanisms like encryption, firewalls, and IDS/IPS." },

{ q: "Which control type includes background checks and policies?", 
  choices: ["Technical", "Administrative", "Physical", "Corrective"], 
  answer: 1, domain: "Security Program Management & Oversight", 
  explanation: "Administrative controls include policies, procedures, and personnel checks." },

{ q: "Which document outlines responsibilities in third-party relationships?", 
  choices: ["MOU", "SLA", "NDA", "Privacy policy"], 
  answer: 1, domain: "Security Program Management & Oversight", 
  explanation: "Service Level Agreements (SLAs) define responsibilities and performance expectations with third parties." },

{ q: "Which document legally prevents disclosure of sensitive information?", 
  choices: ["SLA", "NDA", "MOU", "Guideline"], 
  answer: 1, domain: "Security Program Management & Oversight", 
  explanation: "Non-Disclosure Agreements (NDAs) prevent parties from sharing confidential data." },

{ q: "Which framework provides international standards for information security?", 
  choices: ["ISO 27001", "PCI DSS", "NIST CSF", "ITIL"], 
  answer: 0, domain: "Security Program Management & Oversight", 
  explanation: "ISO 27001 is the international standard for information security management systems." },

{ q: "Which risk response strategy eliminates exposure by not engaging in the risky activity?", 
  choices: ["Avoidance", "Mitigation", "Acceptance", "Transference"], 
  answer: 0, domain: "Security Program Management & Oversight", 
  explanation: "Risk avoidance means eliminating exposure by avoiding the risky activity altogether." },

{ q: "Which type of assessment evaluates organizational compliance with policies?", 
  choices: ["Gap analysis", "Penetration test", "Vulnerability scan", "Threat modeling"], 
  answer: 0, domain: "Security Program Management & Oversight", 
  explanation: "Gap analysis compares current practices against policies and standards." },

{ q: "Which law requires financial institutions to protect customer financial data?", 
  choices: ["SOX", "HIPAA", "GLBA", "FERPA"], 
  answer: 2, domain: "Security Program Management & Oversight", 
  explanation: "Gramm-Leach-Bliley Act (GLBA) requires financial institutions to safeguard customer data." },

{ q: "Which security role ensures compliance with privacy regulations?", 
  choices: ["Data Protection Officer", "CISO", "CIO", "Auditor"], 
  answer: 0, domain: "Security Program Management & Oversight", 
  explanation: "The Data Protection Officer (DPO) ensures compliance with privacy regulations like GDPR." },

{ q: "Which control type includes door locks and security guards?", 
  choices: ["Technical", "Physical", "Administrative", "Compensating"], 
  answer: 1, domain: "Security Program Management & Oversight", 
  explanation: "Physical controls include barriers like locks, fences, and guards." },

{ q: "Which compliance requirement applies to government agencies handling classified data?", 
  choices: ["PCI DSS", "HIPAA", "FISMA", "GDPR"], 
  answer: 2, domain: "Security Program Management & Oversight", 
  explanation: "The Federal Information Security Management Act (FISMA) applies to U.S. government systems." },

{ q: "Which risk assessment identifies potential financial, legal, and operational impacts?", 
  choices: ["Quantitative", "Qualitative", "Gap analysis", "Penetration test"], 
  answer: 1, domain: "Security Program Management & Oversight", 
  explanation: "Qualitative assessments evaluate risks based on impact categories without strict numeric values." },

{ q: "Which framework provides a lifecycle approach to IT service management?", 
  choices: ["ISO 27001", "NIST CSF", "ITIL", "COBIT"], 
  answer: 2, domain: "Security Program Management & Oversight", 
  explanation: "ITIL provides a framework for IT service management processes." },

{ q: "Which risk response accepts the likelihood and impact without action?", 
  choices: ["Avoidance", "Mitigation", "Acceptance", "Transference"], 
  answer: 2, domain: "Security Program Management & Oversight", 
  explanation: "Risk acceptance means choosing to tolerate the risk without taking action." },

{ q: "Which control is implemented to meet compliance when primary controls are not feasible?", 
  choices: ["Compensating control", "Preventive control", "Detective control", "Corrective control"], 
  answer: 0, domain: "Security Program Management & Oversight", 
  explanation: "Compensating controls substitute for primary controls to meet compliance." },

{ q: "Which risk assessment uses dollar values to quantify impact?", 
  choices: ["Qualitative", "Quantitative", "Gap analysis", "Penetration test"], 
  answer: 1, domain: "Security Program Management & Oversight", 
  explanation: "Quantitative assessments use numeric and financial data to measure risks." },

{ q: "Which framework is widely used for auditing IT controls?", 
  choices: ["COBIT", "ISO 27001", "NIST CSF", "PCI DSS"], 
  answer: 0, domain: "Security Program Management & Oversight", 
  explanation: "COBIT is often used in auditing and evaluating IT governance and controls." },

{ q: "Which document defines security objectives for protecting customer data?", 
  choices: ["Privacy policy", "SLA", "NDA", "MOU"], 
  answer: 0, domain: "Security Program Management & Oversight", 
  explanation: "Privacy policies outline how organizations protect customer personal data." },

{ q: "Which regulation requires protecting children's data under age 13 in the U.S.?", 
  choices: ["COPPA", "FERPA", "HIPAA", "SOX"], 
  answer: 0, domain: "Security Program Management & Oversight", 
  explanation: "The Children's Online Privacy Protection Act (COPPA) protects children's data online." },

{ q: "Which risk management step prioritizes risks by severity?", 
  choices: ["Risk acceptance", "Risk assessment", "Risk mitigation", "Risk avoidance"], 
  answer: 1, domain: "Security Program Management & Oversight", 
  explanation: "Risk assessment identifies and prioritizes risks based on likelihood and impact." },

{ q: "Which type of audit is performed by employees within the organization?", 
  choices: ["Internal audit", "External audit", "Third-party audit", "Compliance audit"], 
  answer: 0, domain: "Security Program Management & Oversight", 
  explanation: "Internal audits are conducted by internal staff to check compliance with policies." },

{ q: "Which law regulates email marketing and spam in the U.S.?", 
  choices: ["SOX", "CAN-SPAM Act", "HIPAA", "FERPA"], 
  answer: 1, domain: "Security Program Management & Oversight", 
  explanation: "The CAN-SPAM Act regulates commercial emails and marketing messages." },

{ q: "Which compliance requirement applies to publicly traded companies’ IT systems?", 
  choices: ["SOX", "PCI DSS", "HIPAA", "FISMA"], 
  answer: 0, domain: "Security Program Management & Oversight", 
  explanation: "SOX enforces accountability and internal controls for financial reporting in public companies." },

{ q: "Which control type is logging and monitoring considered?", 
  choices: ["Preventive", "Detective", "Corrective", "Compensating"], 
  answer: 1, domain: "Security Program Management & Oversight", 
  explanation: "Logging and monitoring are detective controls used to identify incidents." },

{ q: "Which law enforces data breach notifications in California?", 
  choices: ["GDPR", "CCPA", "SOX", "HIPAA"], 
  answer: 1, domain: "Security Program Management & Oversight", 
  explanation: "The California Consumer Privacy Act (CCPA) enforces consumer data protections and breach notifications." },

{ q: "Which framework provides risk-based security controls for federal agencies?", 
  choices: ["NIST RMF", "ISO 27001", "COBIT", "ITIL"], 
  answer: 0, domain: "Security Program Management & Oversight", 
  explanation: "NIST Risk Management Framework (RMF) provides security control guidance for federal systems." },

{ q: "Which risk treatment involves reducing likelihood or impact of risk?", 
  choices: ["Acceptance", "Avoidance", "Mitigation", "Transference"], 
  answer: 2, domain: "Security Program Management & Oversight", 
  explanation: "Risk mitigation reduces risk through security controls and safeguards." },

{ q: "Which compliance regulation enforces privacy rights for California residents?", 
  choices: ["HIPAA", "GDPR", "CCPA", "SOX"], 
  answer: 2, domain: "Security Program Management & Oversight", 
  explanation: "The CCPA provides privacy rights and control over personal information for California residents." },

{ q: "Which governance concept ensures roles and responsibilities are clearly defined?", 
  choices: ["Risk assessment", "Separation of duties", "Access control", "Change management"], 
  answer: 1, domain: "Security Program Management & Oversight", 
  explanation: "Separation of duties ensures no individual has too much control, improving accountability." }
];
