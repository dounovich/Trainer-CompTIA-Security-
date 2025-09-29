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
  explanation: "Penetration tests provide realistic attack simulations by exploiting vulnerabilities." }
];
