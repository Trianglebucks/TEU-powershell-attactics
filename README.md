# TEU-powershell-attactics
### To download file/s using powershell:
- Run windows powershell as an administrator, enter the commands below:
```
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 Invoke-WebRequest "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1110.001/src/passwords.txt" -OutFile "C:\temp\passwords.txt"
```
