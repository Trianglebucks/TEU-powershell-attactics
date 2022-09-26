# TEU-powershell-attactics
### To download file/s using powershell:
- Run windows powershell as an administrator, enter the commands below:
```
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 
Invoke-WebRequest "Raw-download-link-of-the-file" -OutFile "Destination-Path-of-the-File"
```
