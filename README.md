# CertificateScanner
Java app for bulk scanning for certificates for provided URLs, IP addresses or IP address ranges

## Usage
```java

Usage: CertificateScanner InputFilePath OutputFilePath ErrorFilePath PortsFilePath ValidateChain MonthsToExpiry
```

#### InputFilePath
Path to the file the contains the list of IP addresses, subnets and URLs. It can contain all of the above

```text
google.com
https://google.com
10.0.0.0/24
```
#### OutputFilePath 

Path to the scan output text file.

#### ErrorFilePath 

Path to a text file to write errors encountered during the scan

#### PortsFilePath 

Path to text file containing list of ports to scan for each URL or IP address in the InputFilePath

```text
443,8443,9443,10443
```

#### ValidateChain

true or false value. True will validate the certificate chain as well while false will only validate the leaf certificate

#### MonthsToExpiry

A number that represents the number of months validity for a certificate to be considered valid/pass

--------------------------------------------------

#### Output file format
Status (Pass/Fail), IP address, domain name, CN name, expiry date

PASS,10.10.10.1,https://google.com:443,CN=google.com,02-Oct-2021
PASS,10.10.10.2,https://example.com:9443,CN=example.com,02-Oct-2020
