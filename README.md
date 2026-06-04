# splunk-projects
# Analyzing DHCP Log Files Using Splunk SIEM

## Introduction
DHCP (Dynamic Host Configuration Protocol) log files contain valuable information about IP address assignments, lease durations, client requests, and server responses. Analyzing DHCP logs using Splunk SIEM enables network administrators to monitor IP address usage, detect anomalies, and troubleshoot network issues effectively.

## Project Overview
In this project, we will upload sample DHCP log files to Splunk SIEM and perform various analyses to gain insights into IP address assignment within the network.

## Prerequisites
Before starting the project, ensure the following:
- Splunk instance is installed and configured.
- DHCP log data sources are configured to forward logs to Splunk.

## Steps to Upload Sample DHCP Log Files to Splunk SIEM

### 1. Prepare Sample DHCP Log Files
- Obtain sample [DHCP log files](https://www.secrepo.com/maccdc2012/dhcp.log.gz) in a suitable format.
- Ensure the log files contain relevant DHCP events, including timestamps, IP address assignments, lease durations, client identifiers, etc.
- Save the sample log files in a directory accessible by the Splunk instance.

### 2. Upload Log Files to Splunk
- Log in to the Splunk web interface.
- Navigate to **Settings** > **Add Data**.
- Select **Upload** as the data input method.

### 3. Choose File
- Click on **Select File** and choose the sample DHCP log file you prepared earlier.

### 4. Set Source Type
- In the **Set Source Type** section, specify the source type for the uploaded log file.
- Choose the appropriate source type for DHCP logs (e.g., `dhcpd` or a custom source type if applicable).

### 5. Review Settings
- Review other settings such as index, host, and sourcetype.
- Ensure the settings are configured correctly to match the sample DHCP log file.

### 6. Click Upload
- Once all settings are configured, click on the **Review** button.
- Review the settings one final time to ensure accuracy.
- Click **Submit** to upload the sample DHCP log file to Splunk.

### 7. Verify Upload
- After uploading, navigate to the search bar in the Splunk interface.
- Run a search query to verify that the uploaded DHCP events are visible.

## Steps to Analyze DHCP Log Files in Splunk SIEM


### 1. 1. Search for DHCP Events
- Open Splunk interface and navigate to the search bar.
- Enter the following search query to retrieve DHCP events:
```
index=<your_dhcp_index> sourcetype=<your_dhcp_sourcetype>
```

### 2. Extract Relevant Fields
- Identify key fields in DHCP logs such as timestamps, IP addresses, lease durations, client identifiers, etc.
- Use Splunk's field extraction capabilities or regular expressions to extract these fields for better analysis.
- Example extraction command
```
| rex field=_raw "<regex_pattern>"

```

### 3. Analyze Email Traffic Patterns
- Determine the distribution of IP address assignments:
```
index=<your_dhcp_index> sourcetype=<your_dhcp_sourcetype>
| stats count by leased_ip
```
- Identify top IP addresses leased by the DHCP server:
```
index=<your_dhcp_index> sourcetype=<your_dhcp_sourcetype>
| top limit=10 leased_ip
```

### 4. Detect Anomalies
- Look for unusual patterns in IP address assignments:
```
index=<your_dhcp_index> sourcetype=<your_dhcp_sourcetype>
| timechart span=1h count by _time
```

- Analyze DHCP requests from unauthorized or unknown clients:
```
index=<your_dhcp_index> sourcetype=<your_dhcp_sourcetype>
| search NOT client_identifier="authorized_identifier"
```

### 5. Monitor IP Address Usage
- Monitor IP address usage over time:
```
index=<your_dhcp_index> sourcetype=<your_dhcp_sourcetype>
| timechart span=1h count by leased_ip
```
- Identify IP addresses with multiple lease renewals or changes:
```
index=<your_dhcp_index> sourcetype=<your_dhcp_sourcetype>
| stats count by leased_ip, lease_renewal
| where count > 1 AND lease_renewal="true"
```
- Analyze DHCP traffic patterns and deviations from normal behavior:
```
index=<your_dhcp_index> sourcetype=<your_dhcp_sourcetype>
| timechart span=1d count by leased_ip
```



## Conclusion
Analyzing DHCP log files using Splunk SIEM provides valuable insights into IP address assignment within a network. By monitoring DHCP events, detecting anomalies, and correlating with other logs, organizations can enhance their network management capabilities, troubleshoot issues, and improve overall network security.

Feel free to customize these steps according to your specific use case and requirements. Happy analyzing!

Feel free to customize these steps according to your specific use case and requirements. 
# Analyzing DNS Log Files Using Splunk SIEM

## Introduction
DNS (Domain Name System) logs are crucial for understanding network activity and identifying potential security threats. Splunk SIEM (Security Information and Event Management) provides powerful capabilities for analyzing DNS logs and detecting anomalies or malicious activities.

## Prerequisites
Before analyzing DNS logs in Splunk, ensure the following:
- Splunk instance is installed and configured.
- DNS log data sources are configured to forward logs to Splunk.

## Steps to Upload Sample DNS Log Files to Splunk SIEM

### 1. Prepare Sample DNS Log Files
- Obtain sample [DNS log file](https://www.secrepo.com/maccdc2012/dns.log.gz) in a suitable format (e.g., text files).
- Ensure the log files contain relevant DNS events, including source IP, destination IP, domain name, query type, response code, etc.
- Save the sample log files in a directory accessible by the Splunk instance.

### 2. Upload Log Files to Splunk
- Log in to the Splunk web interface.
- Navigate to **Settings** > **Add Data**.
- Select **Upload** as the data input method.

### 3. Choose File
- Click on **Select File** and choose the sample DNS log file you prepared earlier.

### 4. Set Source Type
- In the **Set Source Type** section, specify the source type for the uploaded log file.
- Choose the appropriate source type for DNS logs (e.g., `dns` or a custom source type if applicable).

### 5. Review Settings
- Review other settings such as index, host, and sourcetype.
- Ensure the settings are configured correctly to match the sample DNS log file.

### 6. Click Upload
- Once all settings are configured, click on the **Review** button.
- Review the settings one final time to ensure accuracy.
- Click **Submit** to upload the sample DNS log file to Splunk.

### 7. Verify Upload
- After uploading, navigate to the search bar in the Splunk interface.
- Run a search query to verify that the uploaded DNS events are visible.
  
  ```spl
  index=<your_dns_index> sourcetype=<your_dns_sourcetype>


## Steps to Analyze DNS Log Files in Splunk SIEM

### 1. Search for DNS Events   
- Open Splunk interface and navigate to the search bar.   
- Enter the following search query to retrieve DNS events   
```
index=* sourcetype=dns_sample
```

### 2. Extract Relevant Fields
- Identify key fields in DNS logs such as source IP, destination IP, domain name, query type, response code, etc.   
- As mentioned below,  | regex _raw="(?i)\b(dns|domain|query|response|port 53)\b": This regex searches for common DNS-related keywords in the raw event data.
- Example extraction command:
```
index=* sourcetype=dns_sample | regex _raw="(?i)\b(dns|domain|query|response|port 53)\b"
```

### 3. Identify Anomalies
- Look for unusual patterns or anomalies in DNS activity.
- Example query to identify spikes
```
index=_* OR index=* sourcetype=dns_sample  | stats count by fqdn
```

### 4. Find the top DNS sources
- Use the top command to count the occurrences of each query type:   
```
index=* sourcetype=dns_sample | top fqdn, src_ip
```



### 5. Investigate Suspicious Domains
- Search for domains associated with known malicious activity or suspicious behavior.
- Utilize threat intelligence feeds or reputation databases to identify malicious domains such virustotal.com
- Example search for known malicious domains:
```
index=* sourcetype=dns_sample fqdn="maliciousdomain.com"
```

## Conclusion
Analyzing DNS log files using Splunk SIEM enables security professionals to detect and respond to potential security incidents effectively. By understanding DNS activity and identifying anomalies, organizations can enhance their overall security posture and protect against various cyber threats.
# Analyzing SMTP Log Files Using Splunk SIEM

## Introduction
SMTP (Simple Mail Transfer Protocol) log files contain valuable information about email communication, including sender and recipient addresses, timestamps, email subjects, and more. Analyzing SMTP logs using Splunk SIEM enables security professionals to monitor email traffic, detect anomalies, and identify potential security threats.

## Project Overview
In this project, we will upload sample SMTP log files to Splunk SIEM and perform various analyses to gain insights into email communication within the network.

## Prerequisites
Before starting the project, ensure the following:
- Splunk instance is installed and configured.
- SMTP log data sources are configured to forward logs to Splunk.

## Steps to Upload Sample SMTP Log Files to Splunk SIEM

### 1. Prepare Sample SMTP Log Files
- Obtain sample [SMTP log file](https://www.secrepo.com/maccdc2012/smtp.log.gz) in a suitable format (e.g., text files).
- Ensure the log files contain relevant SMTP events, including timestamps, sender and recipient addresses, email subjects, etc.
- Save the sample log files in a directory accessible by the Splunk instance.

### 2. Upload Log Files to Splunk
- Log in to the Splunk web interface.
- Navigate to **Settings** > **Add Data**.
- Select **Upload** as the data input method.

### 3. Choose File
- Click on **Select File** and choose the sample SMTP log file you prepared earlier.

### 4. Set Source Type
- In the **Set Source Type** section, specify the source type for the uploaded log file.
- Choose the appropriate source type for SMTP logs (e.g., `mail` or a custom source type if applicable).

### 5. Review Settings
- Review other settings such as index, host, and sourcetype.
- Ensure the settings are configured correctly to match the sample SMTP log file.

### 6. Click Upload
- Once all settings are configured, click on the **Review** button.
- Review the settings one final time to ensure accuracy.
- Click **Submit** to upload the sample SMTP log file to Splunk.

### 7. Verify Upload
- After uploading, navigate to the search bar in the Splunk interface.
- Run a search query to verify that the uploaded SMTP events are visible.

## Steps to Analyze SMTP Log Files in Splunk SIEM


### 1. Search for SMTP Events
- Open Splunk interface and navigate to the search bar.
- Enter the following search query to retrieve SMTP events
```
index=<your_smtp_index> sourcetype=<your_smtp_sourcetype>
```

### 2. Extract Relevant Fields
- Identify key fields in SMTP logs such as timestamps, sender and recipient addresses, email subjects, etc.
- Use Splunk's field extraction capabilities or regular expressions to extract these fields for better analysis.
- Example extraction command
```
| rex field=_raw "<regex_pattern>"

```

### 3. Analyze Email Traffic Patterns
- Determine the distribution of email senders:
```
index=<your_smtp_index> sourcetype=<your_smtp_sourcetype>
| top limit=10 sender_address
```
- Identify top recipient addresses:
```
index=<your_smtp_index> sourcetype=<your_smtp_sourcetype>
| top limit=10 recipient_address
```

### 4. Detect Anomalies
- Look for unusual patterns in email traffic:
```
index=<your_smtp_index> sourcetype=<your_smtp_sourcetype>
| timechart span=1h count by _time
```

- Investigate emails with unusual attachment types or sizes:
```
index=<your_smtp_index> sourcetype=<your_smtp_sourcetype>
| search attachment_type="unusual_type" OR attachment_size > 1000000
```

### 5. Monitor User Behavior
- Monitor user behavior related to email communication:
```
index=<your_smtp_index> sourcetype=<your_smtp_sourcetype>
| stats count by user
```
- Identify users with multiple failed login attempts or unauthorized access attempts to email accounts:
```
index=<your_smtp_index> sourcetype=<your_smtp_sourcetype>
| search action="login" status="failed"
| stats count by user
```
- Analyze email activity patterns and deviations from normal behavior:
```
index=<your_smtp_index> sourcetype=<your_smtp_sourcetype>
| timechart span=1d count by user
```



## Conclusion
Analyzing SMTP log files with Splunk SIEM enhances network security by monitoring email traffic, detecting anomalies, and correlating data for threat detection. By leveraging Splunk's capabilities, organizations can proactively identify and respond to email-based threats, ensuring the integrity and confidentiality of their communications.

Feel free to customize these steps according to your specific use case and requirements. 


Feel free to customize these steps according to your specific use case and requirements. 

Happy analyzing!
# Analyzing SSH Log Files Using Splunk SIEM

## Introduction
SSH (Secure Shell) log files contain valuable information about remote access to servers, including login attempts, commands executed, and session details. Analyzing SSH logs using Splunk SIEM enables security professionals to monitor access to critical systems, detect anomalies, and identify potential security threats.

## Project Overview
In this project, we will upload sample SSH log files to Splunk SIEM and perform various analyses to gain insights into SSH activity within the network.

## Prerequisites
Before starting the project, ensure the following:
- Splunk instance is installed and configured.
- SSH log data sources are configured to forward logs to Splunk.

## Steps to Upload Sample SSH Log Files to Splunk SIEM

### 1. Prepare Sample SSH Log Files
- Obtain sample [SSH log files](https://www.secrepo.com/maccdc2012/ssh.log.gz) in a suitable format (e.g., text files).
- Ensure the log files contain relevant SSH events, including timestamps, source IP addresses, usernames, actions (login, logout), etc.
- Save the sample log files in a directory accessible by the Splunk instance.

### 2. Upload Log Files to Splunk
- Log in to the Splunk web interface.
- Navigate to **Settings** > **Add Data**.
- Select **Upload** as the data input method.

### 3. Choose File
- Click on **Select File** and choose the sample SSH log file you prepared earlier.

### 4. Set Source Type
- In the **Set Source Type** section, specify the source type for the uploaded log file.
- Choose the appropriate source type for SSH logs (e.g., `syslog` or a custom source type if applicable).

### 5. Review Settings
- Review other settings such as index, host, and sourcetype.
- Ensure the settings are configured correctly to match the sample SSH log file.

### 6. Click Upload
- Once all settings are configured, click on the **Review** button.
- Review the settings one final time to ensure accuracy.
- Click **Submit** to upload the sample SSH log file to Splunk.

### 7. Verify Upload
- After uploading, navigate to the search bar in the Splunk interface.
- Run a search query to verify that the uploaded SSH events are visible.


## Steps to Analyze SSH Log Files in Splunk SIEM


### 1. Search for SSH Events
- Open Splunk interface and navigate to the search bar.
- Enter the following search query to retrieve SSH events:
```
index=<your_ssh_index> sourcetype=<your_ssh_sourcetype>
```

### 2. Extract Relevant Fields
- Identify key fields in SSH logs such as timestamps, source IP addresses, usernames, actions, etc.
- Use Splunk's field extraction capabilities or regular expressions to extract these fields for better analysis.
- Example extraction command:
```
| rex field=_raw "<regex_pattern>"

```

### 3. Analyze SSH Activity Patterns
- Determine the distribution of SSH commands executed:
```
index=<your_ssh_index> sourcetype=<your_ssh_sourcetype>
| stats count by command
```
- Identify top users or source IP addresses accessing the SSH server:
```
index=<your_ssh_index> sourcetype=<your_ssh_sourcetype>
| top limit=10 user src_ip
```
- Analyze successful vs. failed SSH login attempts:
```
index=<your_ssh_index> sourcetype=<your_ssh_sourcetype>
| stats count by action
```

### 4. Detect Anomalies
- Look for unusual patterns in SSH activity (e.g., sudden spikes in login attempts):
```
index=<your_ssh_index> sourcetype=<your_ssh_sourcetype>
| timechart span=1h count by _time
```
- Analyze failed login attempts:
```
index=<your_ssh_index> sourcetype=<your_ssh_sourcetype>
| search action="failed"

```
- Investigate SSH sessions from unusual or suspicious source IP addresses:
```
index=<your_ssh_index> sourcetype=<your_ssh_sourcetype>
| search src_ip="suspicious_ip"
```


### 5. Monitor User Behavior
- Identify users with multiple failed login attempts:
```
index=<your_ssh_index> sourcetype=<your_ssh_sourcetype>
| search action="failed"
| stats count by user
```
- Analyze user session durations:
```
index=<your_ssh_index> sourcetype=<your_ssh_sourcetype>
| stats range(_time) as session_duration by session_id
| stats avg(session_duration) as avg_session_duration by user
```

## Conclusion
Analyzing SSH log files using Splunk SIEM provides valuable insights into remote access to servers within a network. By monitoring SSH events, detecting anomalies, and correlating with other logs, organizations can enhance their security posture and protect against unauthorized access and potential security threats.

Feel free to customize these steps according to your specific use case and requirements. 

Happy analyzing!






