Function Add-UServerFile {
    param(
        [parameter(Mandatory = $true, Position = 0)]
        [array]$Server
    )
    begin {
        if (!(Test-Path -Path (Join-Path -Path $Env:LOCALAPPDATA -ChildPath 'Unifi'))) {
            New-Item -Path $Env:LOCALAPPDATA -Name 'Unifi' -ItemType Directory | Out-Null
        }

    }

    process {
        foreach ($Item in $Server) {
            $Servers += @([PSCustomObject]@{
                    Address = (($Item).Split(':'))[0]
                    Port    = (($Item).Split(':'))[1]
                })
        }

    }

    end {
        $Servers | Export-CliXml -Path (Join-Path -Path $Env:LOCALAPPDATA -ChildPath 'Unifi\Server.xml') -Force | Out-Null
        Remove-Variable -Name 'Server', 'Servers', 'Item' -ErrorAction SilentlyContinue
    }

}

Function Add-UCredentialFile {
    param(
        [parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true)]
        [psobject]$Credential
    )
    begin { 
        if (!(Test-Path -Path (Join-Path -Path $Env:LOCALAPPDATA -ChildPath 'Unifi'))) {
            New-Item -Path $Env:LOCALAPPDATA -Name 'Unifi' -ItemType Directory | Out-Null
        }

    }

    process {
        if (!($Credential)) {
            $Credential = Get-Credential -Message 'Enter Credential with Superadmin privileges for Unifi Controller'
        }

    }

    end {
        $Credential | Export-CliXml -Path (Join-Path -Path $Env:LOCALAPPDATA -ChildPath 'Unifi\Credentials.xml') -Force | Out-Null
        Remove-Variable -Name 'Credential' -ErrorAction SilentlyContinue
    }

}

Function Add-USiteFile {
    param(
        [parameter(Mandatory = $false, Position = 0)]
        [array]$Server,
        [parameter(Mandatory = $false, Position = 1)]
        [psobject]$Credential,
        [switch]$Full
    )

    begin {
        if (!(Test-Path -Path (Join-Path -Path $Env:LOCALAPPDATA -ChildPath 'Unifi'))) {
            New-Item -Path $Env:LOCALAPPDATA -Name 'Unifi' -ItemType Directory | Out-Null
        }
        
        Write-Host 'Parsing all Sites - Please Wait'

        if ($Credential) {
            $Credential = Get-UCredentialsAsJson -Credential $Credential
        }
        else {
            $Credential = Get-UCredentialsAsJson
        }

        if ((Test-Path -Path (Join-Path -Path $Env:LOCALAPPDATA -ChildPath 'Unifi\Server.xml')) -and (!($Server))) {
            $Server = Import-CliXml -Path (Join-Path -Path $Env:LOCALAPPDATA -ChildPath 'Unifi\Server.xml')
        }
        elseif (!($Server)) {
            $Server = Read-Host -Prompt 'Enter Server'
        }

    }

    process {
        foreach ($Item in $Server) {
            if (Test-NetConnection -ComputerName $Item.Address -Port $Item.Port -InformationLevel Quiet) {
                $URL = "https://$($Item.Address):$($Item.Port)"
                try {
                    $Login = Invoke-RestMethod -Uri "$URL/api/login" -Method Post -Body $Credential -ContentType "application/json; charset=utf-8" -SessionVariable myWebSession -SkipCertificateCheck
                }
                catch {
                    Write-Warning -Message "Login to https://$($Item.Address):$($Item.Port) failed du to wrong credentials" 
                }
                if ($Login.meta.rc -eq 'ok') {
                    foreach ($Site in (Invoke-RestMethod -Uri "$URL/api/stat/sites" -WebSession $myWebSession -SkipCertificateCheck).data) {
                        if ($Full) {
                            $Sites += @([PSCustomObject]@{

                                    Server   = $URL
                                    SiteID   = $Site._id
                                    SiteURL  = $Site.name
                                    SiteName = $Site.desc
                                    Health   = $Site.health
                                    Devices  = Invoke-RestMethod -Uri "$URL/api/s/$($Site.Name)/stat/device" -WebSession $myWebSession -SkipCertificateCheck
                                })
                        }
                        else {
                            $Sites += @([PSCustomObject]@{

                                    Server   = $URL
                                    SiteID   = $Site._id
                                    SiteURL  = $Site.name
                                    SiteName = $Site.desc
                                })
                        }

                    }
                    Invoke-RestMethod -Uri "$URL/api/logout" -Method Post -ContentType "application/json; charset=utf-8" -SessionVariable myWebSession -SkipCertificateCheck | Out-Null
                }

            }

        }

    }

    end {
        if ($Full) {
            $Sites | Export-CliXml -Path (Join-Path -Path $Env:LOCALAPPDATA -ChildPath 'Unifi\SitesFull.xml') -Force | Out-Null
        }
        else {
            $Sites | Export-CliXml -Path (Join-Path -Path $Env:LOCALAPPDATA -ChildPath 'Unifi\Sites.xml') -Force | Out-Null
        }
        
        Remove-Variable -Name 'Credential', 'URL', 'Sites', 'Site', 'Item', 'Server' -ErrorAction SilentlyContinue
    }

}

Function Open-USite {
    param(
        [Parameter(Mandatory = $false, Position = 0)]
        [psobject]$Sites,
        [parameter(Mandatory = $false, Position = 1)]
        [psobject]$Credential,
        [switch]$Chrome,
        [switch]$Firefox,
        [switch]$Refresh
    )

    begin {
        if (!($Sites)) {
            try {
                if (Test-Path -Path "$env:LOCALAPPDATA\Unifi\Sites.xml") {
                    $Sites = Import-Clixml "$env:LOCALAPPDATA\Unifi\Sites.xml"
                }
                elseif (Test-Path -Path "$env:LOCALAPPDATA\Unifi\SitesFull.xml") {
                    $Sites = Import-Clixml "$env:LOCALAPPDATA\Unifi\SitesFull.xml"
                }
                else {
                    throw
                }

            }
            catch {
                Write-Warning "$env:LOCALAPPDATA\Unifi\Sites.xml not found"
                Write-Warning "Run Add-USiteFile or choice the file manually with -Sites <Path>"
                exit
            }

        }
        if ($Credential) {
            $Credential = Get-UCredentialsAsJson -Credential $Credential
        }
        else {
            $Credential = Get-UCredentialsAsJson
        }

        $DefaultBrowserName = (Get-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice' | Get-ItemProperty).ProgId
    }

    process {
        do {
            do {
                $SelectionSite = $Sites | Where-Object -Property SiteName -match (Read-Host -Prompt 'Search for Site Name / Customer ID (Enter for a list of all Sites)') -ErrorAction SilentlyContinue
            } while (!$SelectionSite)
        
            Write-Host -Object '[0] -- Return'
            for ($i = 1; $i -le $SelectionSite.length; $i++) {
                Write-Host -Object "[$i] -- $($SelectionSite[$i-1].SiteName)"
            }
            try {
                [int]$Selection = (Read-Host "Choice Site")
            }
            catch { }
        } while (($Selection -like 0) -or ($Selection -gt $i - 1) -or ($Selection -isnot [int]))
        
        $Switch = 'Switch($Selection){'
        for ($i = 1; $i -le $SelectionSite.length; $i++) {
            $Switch += "`n`t$i { Set-Variable -Name URL -Value '$($SelectionSite[$i-1].Server)/manage/site/$($SelectionSite[$i-1].SiteURL)/devices/1/100';  break }"
        }
        $Switch += "`n}"
        Invoke-Expression $Switch

        if (($DefaultBrowserName -like 'ChromeHTML') -or ($Chrome)) {
            if (Test-Path -Path "$env:LOCALAPPDATA\Unifi\Chrome\Unifi") {
                $Driver = Start-SeChrome -StartURL $URL -Maximized -Quiet -ProfileDirectoryPath "$env:LOCALAPPDATA\Unifi\Chrome\Unifi"
            }
            else {
                $Driver = Start-SeChrome -StartURL $URL -Maximized -Quiet
            }
            while ($Driver.Url -notmatch 'unifi.telmekom.net:8443') { }
        }

        elseif (($DefaultBrowserName -like 'FirefoxURL-308046B0AF4A39CB') -or ($Firefox)) {
            if (Test-Path -Path "$env:LOCALAPPDATA\Unifi\Firefox\Unifi") {
                $Args = "`" -profile`"", " Unifi"
                $Driver = Start-SeFirefox -StartURL $URL -Maximized -Quiet -Arguments $Args
            }
            else {
                $Driver = Start-SeFirefox -StartURL $URL -Maximized -Quiet
            }  
            while ($Driver.Url -notmatch 'unifi.telmekom.net:8443') { }
        }

        elseif ($DefaultBrowserName -like 'MSEdgeHTM') {
            if (Test-Path -Path "$env:LOCALAPPDATA\Unifi\Chrome\Unifi") {
                $Driver = Start-SeNewEdge -StartURL $URL -Maximized -Quiet -ProfileDirectoryPath "$env:LOCALAPPDATA\Unifi\Chrome\Unifi"
            }
            else {
                $Driver = Start-SeNewEdge -StartURL $URL -Maximized -Quiet
            }            
            while ($Driver.Url -notmatch 'unifi.telmekom.net:8443') { }
        }

        else {
            $Driver = Start-SeEdge -StartURL $URL -Maximized -Quiet
            while ($Driver.Url -notmatch 'unifi.telmekom.net:8443') { }
        }
        
        $ElementUsername = Get-SeElement -Driver $Driver -Name 'username' -Wait -Timeout 10
        $ElementPassword = Get-SeElement -Driver $Driver -Name 'password' -Wait -Timeout 10
        $ElementLogin = Get-SeElement -Driver $Driver -Id 'loginButton' -Wait -Timeout 10
        
        Send-SeKeys -Element $ElementUsername -Keys (($Credential | ConvertFrom-Json).username)
        Send-SeKeys -Element $ElementPassword -Keys (($Credential | ConvertFrom-Json).password)
        
        Invoke-SeClick -Driver $Driver -Element $ElementLogin -JavaScriptClick
        
        while ($Driver.Url -match 'login') { }
        Enter-SeUrl $URL -Driver $Driver
    }

    end {
        Remove-Variable -Name 'Sites', 'Credential', 'Switch', 'SelectionSite', 'i', 'DefaultBrowserName', 'Driver', 'ElementUsername', 'ElementPassword', 'ElementLogin', 'URL', 'Chrome', 'Firefox', 'Refresh' -ErrorAction SilentlyContinue
    }

}

Function Get-UCredentialsAsJson {
    param(
        [parameter(Mandatory = $false, Position = 0)]
        [psobject]$Credential
    ) 

    if ((Test-Path -Path (Join-Path -Path $Env:LOCALAPPDATA -ChildPath 'Unifi\Credentials.xml')) -and (!($Credential))) {
        $Credential = Import-CliXml -Path (Join-Path -Path $Env:LOCALAPPDATA -ChildPath 'Unifi\Credentials.xml')
    }
    elseif (!($Credential)) {
        $Credential = Get-Credential -Message 'Enter Credential with Superadmin privileges for Unifi Controller'
    }

    return ($Credential = @{
            username = $Credential.UserName
            password = ([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)))
        } | ConvertTo-Json)

}

Function Add-UProfile {    
    param(
        [switch]$Chrome,
        [switch]$Firefox,
        [switch]$Refresh
    )
    begin {

        if (!(Test-Path -Path (Join-Path -Path $Env:LOCALAPPDATA -ChildPath 'Unifi'))) {
            New-Item -Path $Env:LOCALAPPDATA -Name 'Unifi' -ItemType Directory | Out-Null
        }

        if ($Chrome) {
            $ChromeProcessID = (Get-Process -Name '*Chrome*').ID
            if (Test-Path -Path "$env:LOCALAPPDATA\Unifi\Unifi") {
                Remove-Item -Path "$env:LOCALAPPDATA\Unifi\Unifi" -Force -Recurse
            }
            Write-Warning -Message 'Creating new profile, please wait'
            $ChromePath = Get-Item (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe').'(Default)'
        }

        if ($Firefox) {
            $FirefoxProcessID = (Get-Process -Name '*Firefox*').ID
            if (Test-Path -Path "$env:LOCALAPPDATA\Unifi\Unifi") {
                Remove-Item -Path "$env:LOCALAPPDATA\Unifi\Unifi" -Force -Recurse
            }
            Write-Warning -Message 'Creating new profile, please wait'
            $FirefoxPath = Get-Item (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe').'(Default)'
        }

    }

    process {
        if ($Chrome) {
            Invoke-Expression -Command "&`"$($ChromePath.FullName)`" --user-data-dir=$env:LOCALAPPDATA\Unifi\Chrome\Unifi --silent-launch"
            Start-Sleep 10     
            foreach ($ProcessID in (Get-Process -Name '*Chrome*').ID) {
                if ($ProcessID -notin $ChromeProcessID) {
                    Stop-Process -Id $ProcessID -Force -ErrorAction SilentlyContinue
                }

            }

        }

        if ($Firefox) {
            Invoke-Expression -Command "&`"$($FirefoxPath.FullName)`" --CreateProfile `"Unifi $env:LOCALAPPDATA\Unifi\Firefox\Unifi`" --no-remote"  
            Start-Sleep 10     
            foreach ($ProcessID in (Get-Process -Name '*Firefox*').ID) {
                if ($ProcessID -notin $FirefoxProcessID) {
                    Stop-Process -Id $ProcessID -Force -ErrorAction SilentlyContinue
                }

            }

        }

    }

    end {
        Remove-Variable -Name 'ChromeProcessID', 'ProcessID', 'Chrome', 'FirefoxProcessID', 'Firefox', 'ChromePath', 'FirefoxPath' -ErrorAction SilentlyContinue

    }

}

Function Get-USiteURL {    
    param(
        [Parameter(Mandatory = $false, Position = 0)]
        [psobject]$Sites,
        [parameter(Mandatory = $false, Position = 1)]
        [psobject]$Credential
    )
    begin {
        if (!($Sites)) {
            try {
                if (Test-Path -Path "$env:LOCALAPPDATA\Unifi\Sites.xml") {
                    $Sites = Import-Clixml "$env:LOCALAPPDATA\Unifi\Sites.xml"
                }
                elseif (Test-Path -Path "$env:LOCALAPPDATA\Unifi\SitesFull.xml") {
                    $Sites = Import-Clixml "$env:LOCALAPPDATA\Unifi\SitesFull.xml"
                }
                else {
                    throw
                }

            }
            catch {
                Write-Warning "$env:LOCALAPPDATA\Unifi\Sites.xml not found"
                Write-Warning "Run Add-USiteFile or choice the file manually with -Sites <Path>"
                exit
            }

        }
        if ($Credential) {
            $Credential = Get-UCredentialsAsJson -Credential $Credential
        }
        else {
            $Credential = Get-UCredentialsAsJson
        }

    }

    process {
        do {
            do {
                $SelectionSite = $Sites | Where-Object -Property SiteName -match (Read-Host -Prompt 'Search for Site Name / Customer ID (Enter for a list of all Sites)') -ErrorAction SilentlyContinue
            } while (!$SelectionSite)
        
            Write-Host -Object '[0] -- Return'
            for ($i = 1; $i -le $SelectionSite.length; $i++) {
                Write-Host -Object "[$i] -- $($SelectionSite[$i-1].SiteName)"
            }
            try {
                [int]$Selection = (Read-Host "Choice Site")
            }
            catch { }
        } while (($Selection -like 0) -or ($Selection -gt $i - 1) -or ($Selection -isnot [int]))
        
        $Switch = 'Switch($Selection){'
        for ($i = 1; $i -le $SelectionSite.length; $i++) {
            $Switch += "`n`t$i { Set-Variable -Name URL -Value '$($SelectionSite[$i-1].Server)/manage/site/$($SelectionSite[$i-1].SiteURL)/dashboard';  break }"
        }
        $Switch += "`n}"
        Invoke-Expression $Switch
    }

    end {
        Write-Host -Object $URL
        Remove-Variable -Name 'Sites', 'Credential', 'Switch', 'SelectionSite', 'i', 'URL' -ErrorAction SilentlyContinue
    }

}

Function Get-UServerStats {
    param(
        [Parameter(Mandatory = $false, Position = 0)]
        [psobject]$Sites,
        [switch]$Device,
        [switch]$Distribution
    )    
    begin {
        if (!($Sites)) {
            try {
                if (Test-Path -Path "$env:LOCALAPPDATA\Unifi\SitesFull.xml") {
                    $Sites = Import-Clixml "$env:LOCALAPPDATA\Unifi\SitesFull.xml"
                }
                else {
                    throw
                }

            }
            catch {
                Write-Warning "$env:LOCALAPPDATA\Unifi\SitesFull.xml not found"
                Write-Warning "Run Add-USiteFile -Full or choice the file manually with -Sites <Path>"
                exit
            }

        }

    }

    process {
        if ($Device) {
            $DeviceStats = [PSCustomObject]@{
                Upgradeable  = ($Sites.Devices.data | Where-Object -Property upgradable -eq $true).Count
                Unsupported  = ($Sites.Devices.data | Where-Object -Property unsupported -eq $true).Count
                Incompatible = ($Sites.Devices.data | Where-Object -Property model_incompatible -eq $true).Count
                Mesh         = ($Sites.Devices.data | Where-Object -Property mesh_sta_vap_enabled -eq $true).Count
                Locating     = ($Sites.Devices.data | Where-Object -Property locating -eq $true).Count
                Overheating  = ($Sites.Devices.data | Where-Object -Property overheating -eq $true).Count
            }

        }
        if ($Distribution) {
            foreach ($Server in ($Sites.Server | Sort-Object -Unique)) {
                $DistributionStats += @([PSCustomObject]@{ 
                        Server              = $Server
                        Sites               = (($Sites | Where-Object -Property Server -Match $Server).Count)
                        DevicesAdopted      = (($Sites | Where-Object -Property Server -Match $Server).health.num_adopted | Measure-Object -sum).sum
                        DevicesOnline       = ((($Sites | Where-Object -Property Server -Match $Server).health.num_ap | Measure-Object -sum).sum) + ((($Sites | Where-Object -Property Server -Match $Server).health.num_sw | Measure-Object -sum).sum)
                        DevicesDisconnected = (($Sites | Where-Object -Property Server -Match $Server).health.num_disconnected | Measure-Object -sum).sum
                        Clients             = (($Sites | Where-Object -Property Server -Match $Server).health.num_user | Measure-Object -sum).sum
                    })

            }

        }
        else {
            $ServerStats = [PSCustomObject]@{
                Sites               = $Sites.Count
                DevicesAdopted      = ($Sites.health.num_adopted | Measure-Object -sum).sum
                DevicesOnline       = (($Sites.health.num_ap | Measure-Object -sum).sum) + (($Sites.health.num_sw | Measure-Object -sum).sum)
                DevicesDisconnected = ($Sites.health.num_disconnected | Measure-Object -sum).sum
                Clients             = ($Sites.health.num_user | Measure-Object -sum).sum  
            }

        }

    }

    end {
        if ($Device) { 
            $DeviceStats
        }
        if ($Distribution) {
            foreach ($DistributionStat in $DistributionStats) {
            $DistributionStat
            }

        }
        else {
            $ServerStats
        }
        Remove-Variable -Name 'Sites', 'Device', 'DeviceStats', 'ServerStats', 'Distribution', 'Server', 'DistributionStat' -ErrorAction SilentlyContinue
    }

}



NEW NEW 
gdsvdx

