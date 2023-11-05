# Executive Summary and Vulnerability Rating Table

Summary:  
- A total of X high vulnerabilities were discovered within the scope, with Y leading to {level of
access/penetration}.
• Explain in detail the highest level of penetration
- Table with vulnerability rating being High, Medium and Low with Overall Count and Unique Count of vulnerabilities

## EXAMPLE
Overall it is assessed that the SecurityHolesRUs system/s tested represents a {specify risk} to the business
operations of SecurityHolesRUs. These risks relate to the possibility of a malicious party {list relevant examples
and provide the brief description (is able to obtain the hashes from the tested system thus allowing full
control of the compromised system)}

To reduce the risk associated with the vulnerability, it is recommended that SecurityHolesRUs initiate a
remediation program that covers the actions outlined in this report. The recommendations include, but
are not constrained to (keep it to 3-4 if possible):

- Update the relevant operating system;
- Update the relevant applications deployed in the {scope}
• Enforce a strong password policy
• Review the privileges associated with the different user roles
• Remove any unnecessary services and resources
• Train users on the CIA principles.

# Methodology 

Specify which methodology used (for example NIST). Provide a
brief description and explain who used this methodology to do
penetration testing.

https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf

## EXAMPLE

The penetration testing assessment was carried out as a
four-step process, based primarily on the NIST
methodology, sourced from NIST 800-115. 

The NIST methodology is considered standard for conducting
penetration tests throughout the world and involves a
dynamic process that start with a planning stage
followed by a discovery (reconnaissance) stage, an
attack stage and concludes with a formal reporting step.
The discovery and attack stages may be repeated
multiple depending on the vulnerability information
obtained as part of the testing process. This test was 
conducted externally to the target system
in order to simulate an Internet based attacker.

# Planning
Specify: THE SCOPE in detail – IPs, URLs, accounts

The activities involved:

• Scanning and enumeration of services currently within the target scope
• Determination of possible vulnerabilities identified within services discovered
• Assessment and attempted exploitation of vulnerabilities, to eliminate false positive indications and penetrate the
scoped network as much as possible
• Reporting of any identified penetrations, vulnerabilities, and recommended remediation advice

# Enumeration
Provide a table with: IP , Ports, Service
SCREENSHOTS

## Example

The target was scanned with the standard tools and the scan results showed that the system was running over six (6)
different services which indicated a substantial attack surface. The detailed scan results are shown in Figures 1 and 2,

• The results showed that the system was running an anonymous FTP service as well as an outdated Apache web server.

Moreover, the system was running NFS with potentially Internet exposed mounts. Critically, the scan results showed
that the operating system was Linux with an outdated kernel, fact which was reinforced by the outdated versions of the
SSH and Apache services.

• Given the multiple possible attack vectors, the assessor focused, at the start, on the three most likely exploitable
services: FTP, HTTP and NFS and the details are provided in the next section

# Attack
(Exploitation + Payload + Privilege Escalation )
Specify how you found the vulnerability and explain what you could do with it. Needs to be systematic and cover all findings.

## Example

The first service investigated was FTP. The assessor attempted to access the service using default credentials (anonymous:password) and as the
scans had indicated, the system did allow anonymous access. However, the FTP access was found to be limited to a specific directory which was
empty and did not allow any user uploads (shown in Figure ….).

• The second service investigated was NFS. The assessor undertook a more specific test to determine whether or not any data areas could
potentially be mounted remotely. The results showed that the two areas could potentially be mountable: /srv/ftp and /tmp. Given that the /tmp
allows in most cases full write privileges, the assessor proceeded to mount the area as shown in Figure …. A quick check of the contents of the
/tmp directory revealed that a number of temporary files were stored in the directory which indicated that this area could be used for uploading
files to the remote machine. Moreover, it could be used to compile and run any local exploits should it become necessary to do so.

# Detailed vulnerability information

For each vulnerability specify:
• Name + CVE or CWE
• Description
• Risk
• Solution
• Assets Impacted.

# Conclusion and Appendix








