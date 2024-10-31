# Complete Analysis of a Target Machine on a Local Network Using NMAP

## Context of the Exercise

Imagine you have a machine on your local network (IP: 192.168.1.58) that you want to analyze using NMAP. This target machine is in the same network as your main computer, allowing you to perform safe and authorized scans to understand its open ports, services, and overall security posture. This exercise will guide you through using NMAP’s essential commands to gather information about this machine.

## Objective of the Exercise

- Identify open ports on the target machine.
- Obtain detailed information on the services and their versions.
- Attempt to determine the operating system of the target machine.
- Practice using different NMAP options for precise and effective network scanning.
  
### Steps of the Exercise

#### Step 1: Quick Scan of Common Ports

```
nmap -T4 -F 192.168.1.58
```
![Capture d'écran 2024-10-31 121004](https://github.com/user-attachments/assets/e25063e5-a84f-40be-93ca-876b7c88335a)

Explanation:
-T4: Sets the scan speed to "aggressive" for a faster scan.
-F: Scans only the most commonly used ports (around 100).
Goal: Get a quick overview of the main ports on the target machine to see which ones are open.

#### Step 2: Scan All Ports

```
nmap -p- 192.168.1.58
```
![Capture d'écran 2024-10-31 121018](https://github.com/user-attachments/assets/df86e0fa-7b8d-438d-a85c-7da4a1a28d21)

Explanation:
-p-: Instructs NMAP to scan all ports (from 1 to 65535).
Goal: Discover all open ports, including uncommon ones or those using non-standard ports. This will give a more complete view of the machine’s potential points of entry.

#### Step 3: Service Version Detection

```
nmap -sV 192.168.1.58
```
![Capture d'écran 2024-10-31 121032](https://github.com/user-attachments/assets/fcef1790-2c9a-4872-8096-fcd2385a625c)

Explanation:
-sV: Enables version detection for services running on the open ports.
Goal: Obtain detailed information about the version of each service on open ports, which will help in assessing potential vulnerabilities based on outdated or vulnerable software versions.

#### Step 4: OS Detection

```
nmap -O 192.168.1.58
```
![Capture d'écran 2024-10-31 121046](https://github.com/user-attachments/assets/e111ab87-0307-4f16-8be9-b1f1e66a1b85)

Explanation:
-O: Activates operating system detection by analyzing network fingerprints.
Goal: Attempt to identify the operating system of the target machine. Knowing the OS can be valuable for adapting the scan approach and understanding possible security issues associated with that OS.

#### Step 5: Comprehensive Analysis with the -A Option

```
nmap -A 192.168.1.58
```
![Capture d'écran 2024-10-31 121101](https://github.com/user-attachments/assets/90921fd6-5b23-435a-a619-9e48ca6b0790)

Explanation:
-A: Activates several advanced options at once, including OS detection, version detection, and traceroute.
Goal: Obtain a complete profile of the target machine in a single scan. This command combines multiple NMAP features, making it an efficient way to gather detailed information.

#### Step 6: Search for Potential Vulnerabilities

```
nmap --script vuln 192.168.1.58
```
![Capture d'écran 2024-10-31 121115](https://github.com/user-attachments/assets/c87cb4b4-1651-4611-b8fd-4f26f7ff5231)

Explanation:
--script vuln: Uses NMAP’s vulnerability detection scripts to analyze possible weaknesses on detected services.
Goal: Check if the target machine has any known vulnerabilities in its running services. This step helps you understand potential risks associated with outdated or misconfigured services.

#### Expected Results and Analysis

- Open Ports: Take note of any ports that appear as open in each scan. Pay attention to differences between the quick scan (-F) and the full port scan (-p-).
- Services and Versions: In the version detection step (-sV), identify the services associated with open ports and note their exact versions. This information is essential for evaluating whether these services are up-to-date or potentially vulnerable.
- Operating System: The -O or -A command should provide an estimated operating system for the target machine. Note any clues or details that confirm the OS.
- Vulnerabilities: Check the output from --script vuln to see if any known security flaws were detected. This step can give you insight into possible security threats on the machine.

#### Reflection Questions After the Exercise

1. Which ports are open on the target machine? Are these ports commonly used or unusual?
Answer: From the scans, the following ports are open on the target machine (IP: 192.168.1.58):

- 135/tcp - msrpc (Microsoft RPC)
- 139/tcp - netbios-ssn (NetBIOS Session Service)
- 445/tcp - microsoft-ds (Microsoft Directory Services, SMB)
- 808/tcp - mc-nmf (.NET Message Framing)
- 903/tcp - ssl/vmware-auth (VMware Authentication Daemon)
- 908/tcp - iss-console-mgr (unknown purpose in this context)

These ports are typical for a Windows machine:

- Ports 135, 139, and 445 are commonly used by Microsoft services, particularly for network file sharing and remote procedure calls, which are standard on Windows networks.
- Port 903 is used by VMware, indicating that the target may have VMware services installed.
- Port 808 may be used for .NET applications.

Overall, the open ports align with services typically found on a Windows machine, especially in a corporate environment.

2. Are the detected service versions up-to-date or potentially vulnerable? If they’re outdated, what security measures could be taken?
Answer: The scans reveal several Windows services, including Microsoft RPC, NetBIOS, and SMB, which are known to be vulnerable if not properly patched or if the system is outdated. The --script vuln scan did not detect any critical vulnerabilities, but it indicated potential SMB issues:

- SMB vulnerabilities are often a concern on port 445. Even though there were no specific SMB vulnerabilities identified, it’s crucial to ensure that the system is up-to-date with all security patches, particularly to avoid exploits like EternalBlue, which targeted SMB.

As a precaution, security measures could include:

- Regularly applying Windows updates and security patches.
- Disabling unnecessary services (like NetBIOS over TCP/IP) if they are not actively used.
- Restricting access to these ports from external networks to prevent unauthorized access.

3. Was the operating system correctly identified? Are there any signs or details that confirm the OS on the target machine?

- Answer: The operating system detection scan (-O and -A) identified the target as running Microsoft Windows 10, with version details indicating Windows 10 1709 - 1909. This identification aligns well with the open ports and services, such as SMB, Microsoft RPC, and NetBIOS, which are typically associated with Windows operating systems.

These results provide a reliable confirmation that the target machine is indeed a Windows 10 system, possibly used in a general-purpose role within the network.

4. Did NSE scripts detect any vulnerabilities? What are the potential risks, and what actions could you take to address them?

- Answer: The --script vuln scan results indicate that no specific vulnerabilities were detected on the SMB services, though there were connection errors during the scan. This may imply that certain aspects of SMB were inaccessible or that the target does not have the particular SMB vulnerabilities that the scripts tested for.

- Potential Risks and Actions:

- Risks: Since SMB and NetBIOS are exposed, these services could be vulnerable to brute-force attacks, unauthorized access, or exploitation of SMB-related vulnerabilities if not adequately secured.

- Actions:

Ensure that all Windows security patches are applied, especially for SMB.

Consider restricting SMB and NetBIOS access to trusted IP ranges only.

Disable NetBIOS over TCP/IP if it’s not required, as it can reduce the network attack surface.

Regularly audit and monitor open ports and services for unusual activity to quickly detect and respond to potential threats.
