if (!(Test-Path -Path (Join-Path -Path $Env:LOCALAPPDATA -ChildPath 'Unifi'))) {
    New-Item -Path $Env:LOCALAPPDATA -Name 'Unifi' -ItemType Directory | Out-Null
}
$Global:ProgressPreference = 'SilentlyContinue'
Function Add-UServerFile {
    param(
        [parameter(Mandatory = $true, Position = 0)]
        [ValidatePattern("^(?:http(s)?:*)", ErrorMessage = 'Insert correct form of an URL <http|https://<server>:<port>>')]
        [ValidateScript( { [uri]::TryCreate($_, [System.UriKind]::Absolute, [ref]$null) }, ErrorMessage = 'Insert correct form of an URL <http|https://<server>:<port>>')]
        [array]$Server
    )
    try {
        foreach ($Item in $Server) {
            $ServerUnreachable = $false
            do {
                try {
                    $URISplit = $null
                    while ($ServerUnreachable) {
                        [ValidatePattern("^(?:http(s)?:*)", ErrorMessage = 'Insert correct form of an URL <http|https://<server>:<port>>')]
                        [ValidateScript( { [uri]::TryCreate($_, [System.UriKind]::Absolute, [ref]$null) }, ErrorMessage = 'Insert correct form of an URL <http|https://<server>:<port>>')]        
                        $Item = Read-Host -Prompt 'Insert correct form of an URL <http|https://<server>:<port>>'
                        if ($Item) {
                            $ServerUnreachable = $false
                        }
                    }
                    [uri]::TryCreate($Item, [System.UriKind]::Absolute, [ref]$URISplit) | Out-Null
                    $Reachable = Test-NetConnection -ComputerName $URISplit.Host -Port $URISplit.Port -InformationLevel Quiet -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                    if (!($Reachable)) {
                        throw
                    }
                }
                catch {
                    Remove-Variable 'Item'
                    $ServerUnreachable = $true
                }
            }while (!($Reachable))

            do {
                try {
                    $Credential = (Get-Credential -Message "Enter Credential with Superadmin privileges for $Item")
                    $CredentialTMP = @{
                        username = $Credential.UserName
                        password = ([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)))
                    } | ConvertTo-Json
                    $Login = $null
                    $Login = Invoke-RestMethod -Uri "$Item/api/login" -Method Post -Body $CredentialTMP -ContentType "application/json; charset=utf-8" -SessionVariable myWebSession -SkipCertificateCheck
                }
                catch {
                    Write-Warning -Message "Login to $Item failed du to wrong credentials" 
                }
            }while ($Login.meta.rc -notlike 'ok')

            $Servers += @([PSCustomObject]@{
                    Protocol    = $URISplit.Scheme
                    Host        = $URISplit.Host
                    InformURL   = (Invoke-RestMethod -Uri "$Item/api/s/default/stat/sysinfo" -WebSession $myWebSession -SkipCertificateCheck).data.hostname
                    Port        = $URISplit.Port
                    InformPort  = (Invoke-RestMethod -Uri "$Item/api/s/default/stat/sysinfo" -WebSession $myWebSession -SkipCertificateCheck).data.inform_port
                    Server      = "$($URISplit.Scheme)://$($URISplit.Authority)"
                    Exclude     = $false
                    Migrate     = $false
                    MigrateAble = $false
                    UserName    = $Credential.UserName
                    Password    = $Credential.Password
                })
            Invoke-RestMethod -Uri "$Item/api/logout" -Method Post -ContentType "application/json; charset=utf-8" -SessionVariable myWebSession -SkipCertificateCheck | Out-Null
        }
        $Servers | Export-CliXml -Path (Join-Path -Path $Env:LOCALAPPDATA -ChildPath 'Unifi\Server.xml') -Force | Out-Null
    }
    finally {
        Remove-Variable * -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 5
        [System.GC]::Collect()
    }
}

Function Set-UServerFile {
    param(
        [array]$Exlude,
        [array]$Include
    )
    try {
        $Servers = (Import-UData -WithoutSite).Host
        foreach ($Item in $Exlude) {
            $Servers[(($Servers.Host).IndexOf($Item))].Exlude = $true
        }
        foreach ($Item in $Include) {
            $Servers[(($Servers.Host).IndexOf($Item))].Exlude = $false
        }
        $Servers | Export-CliXml -Path (Join-Path -Path $Env:LOCALAPPDATA -ChildPath 'Unifi\Server.xml') -Force | Out-Null
    }
    finally {
        Remove-Variable * -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 5
        [System.GC]::Collect()
    }
}

Function Add-USiteFile {
    param(
        [switch]$Full
    )
    try {
        $UData = Import-UData -WithoutSite
        if ($UData -like 'Error') {
            return
        }

        if ($Full) {
            $Sites = Get-USiteInformation -Server $UData.Server -Full
            if ($Sites -like 'Error') {
                return
            }
            $Sites | Export-CliXml -Path (Join-Path -Path $Env:LOCALAPPDATA -ChildPath 'Unifi\SitesFull.xml') -Force | Out-Null
        }
        else {
            $Sites = Get-USiteInformation -Server $UData.Server
            if ($Sites -like 'Error') {
                return
            }
            $Sites | Export-CliXml -Path (Join-Path -Path $Env:LOCALAPPDATA -ChildPath 'Unifi\Sites.xml') -Force | Out-Null
        }
    }
    finally {
        Remove-Variable * -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 5
        [System.GC]::Collect()
    }
}

Function Open-USite {
    param(
        [switch]$Chrome,
        [switch]$Firefox,
        [switch]$Live
    )
    try {
        if ($Live) {
            $UData = Import-UData -Live
        }
        else {
            $UData = Import-UData
        }
        if ($UData -like 'Error') {
            return
        }
        $URL = Search-USite -UData $UData
    

        try {
            $URISplit = $null
            [uri]::TryCreate($URL, [System.UriKind]::Absolute, [ref]$URISplit) | Out-Null
            $Reachable = Test-NetConnection -ComputerName $URISplit.Host -Port $URISplit.Port -InformationLevel Quiet -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            if (!($Reachable)) {
                throw
            }
            $Credential = @{
                username = ($UData.Server[(($UData.Server.Host).IndexOf($URISplit.Host))].UserName)
                password = ([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR(($UData.Server[(($UData.Server.Host).IndexOf($URISplit.Host))].Password))))
            } | ConvertTo-Json
            $Login = $null
            $Login = Invoke-RestMethod -Uri "$($URISplit.Scheme)://$($URISplit.Authority)/api/login" -Method Post -Body $Credential -ContentType "application/json; charset=utf-8" -SessionVariable myWebSession -SkipCertificateCheck
            if ($Login.meta.rc -notlike 'ok') {
                throw
            }
        }
        catch {
            Write-Warning -Message "Login to $($URISplit.Host):$($URISplit.Port) failed"
            return
        }
        Invoke-RestMethod -Uri "$($URISplit.Scheme)://$($URISplit.Authority)/api/logout" -Method Post -ContentType "application/json; charset=utf-8" -SessionVariable myWebSession -SkipCertificateCheck | Out-Null
        $DefaultBrowserName = (Get-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice' | Get-ItemProperty).ProgId
        $FirstLogin = $false
        try {
            if (!($global:Driver)) {
                if (($DefaultBrowserName -like 'ChromeHTML') -or ($Chrome)) {
                    if (Test-Path -Path "$env:LOCALAPPDATA\Unifi\Chrome\Unifi") {
                        $global:Driver = Start-SeChrome -Maximized -Quiet -ProfileDirectoryPath "$env:LOCALAPPDATA\Unifi\Chrome\Unifi"
                    }
                    else {
                        $global:Driver = Start-SeChrome -Maximized -Quiet
                    }
                }

                elseif (($DefaultBrowserName -like 'FirefoxURL-308046B0AF4A39CB') -or ($Firefox)) {
                    if (Test-Path -Path "$env:LOCALAPPDATA\Unifi\Firefox\Unifi") {
                        $global:Driver = Start-SeFirefox -Maximized -Quiet -Arguments '-profile', "$env:LOCALAPPDATA\Unifi\Firefox\Unifi"
                    }
                    else {
                        $global:Driver = Start-SeFirefox -Maximized -Quiet
                    }
                }

                elseif ($DefaultBrowserName -like 'MSEdgeHTM') {
                    if (Test-Path -Path "$env:LOCALAPPDATA\Unifi\Chrome\Unifi") {
                        $global:Driver = Start-SeNewEdge -Maximized -Quiet -ProfileDirectoryPath "$env:LOCALAPPDATA\Unifi\Chrome\Unifi"
                    }
                    else {
                        $global:Driver = Start-SeNewEdge -Maximized -Quiet
                    }
                }

                else {
                    $global:Driver = Start-SeEdge -Maximized -Quiet
                }
                $FirstLogin = $true
            }
    
            if (($global:Driver.Url -notmatch $URISplit.Authority) -or ($FirstLogin)) {
                $Counter = 0
                Open-SeUrl -Url $URL -Driver $global:Driver
                Start-Sleep -Seconds 0.3
                while (($global:Driver.Url -notmatch 'login') -and ($Counter -lt 10)) { 
                    Start-sleep -Seconds 0.1
                    $Counter += 1
                }
                if ($Counter -lt 10) {

                    Send-SeKeys -Element (Get-SeElement -Driver $global:Driver -Name 'username') -Keys (($Credential | ConvertFrom-Json).username)
                    Send-SeKeys -Element (Get-SeElement -Driver $global:Driver -Name 'password') -Keys (($Credential | ConvertFrom-Json).password)    
                    Invoke-SeClick -Driver $global:Driver -Element (Get-SeElement -Driver $global:Driver -Id 'loginButton') -JavaScriptClick
        
                    while ($global:Driver.Url -match 'login') { }
                }
            }
            if ($global:Driver.Url -notlike $URL) {
                Open-SeUrl -Url $URL -Driver $global:Driver
            }
        }
        catch {
            return
        }
        finally {
            Remove-Variable -Name 'UData'
        }
    }
    finally {
        Remove-Variable * -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 5
        [System.GC]::Collect()
    }
}

Function Add-UProfile {
    param(
        [switch]$Chrome,
        [switch]$Firefox,
        [switch]$Refresh
    )
    try {
        if ($Chrome) {
            $ChromeProcessID = (Get-Process -Name '*Chrome*').ID
            if ((Test-Path -Path "$env:LOCALAPPDATA\Unifi\Chrome\Unifi") -and ($Refresh)) {
                Remove-Item -Path "$env:LOCALAPPDATA\Unifi\Chrome\Unifi" -Force -Recurse
            }
            Write-Warning -Message 'Creating new profile, please wait'
            $ChromePath = Get-Item (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe').'(Default)'
        }

        if ($Firefox) {
            $FirefoxProcessID = (Get-Process -Name '*Firefox*').ID
            if ((Test-Path -Path "$env:LOCALAPPDATA\Unifi\Firefox\Unifi") -and ($Refresh)) {
                Remove-Item -Path "$env:LOCALAPPDATA\Unifi\Firefox\Unifi" -Force -Recurse
            }
            Write-Warning -Message 'Creating new profile, please wait'
            $FirefoxPath = Get-Item (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe').'(Default)'
        }

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
    finally {
        Remove-Variable * -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 5
        [System.GC]::Collect()
    }
}

Function Get-USiteURL {
    param(
        [switch]$Live
    )
    try {
        if ($Live) {
            $UData = Import-UData -Live
        }
        else {
            $UData = Import-UData
        }
        if ($UData -like 'Error') {
            return
        }
        try {
            $URL = Search-USite -UData $UData
            Write-Host -Object $URL
        }
        catch {
            return
        }
        finally {
            Remove-Variable -Name 'UData'
        }
    }
    finally {
        Remove-Variable * -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 5
        [System.GC]::Collect()
    }
}

Function Get-UServerStats {
    param(
        [switch]$Device,
        [switch]$Distribution,
        [switch]$Live
    ) 
    try {
        if ($Live) {
            $UData = Import-UData -Live -Full
        }
        else {
            $UData = Import-UData -Full 
        }
        if ($UData -like 'Error') {
            return
        }

        try {
            if ($Device) {
                foreach ($Server in ($UData.Server | Where-Object -Property Exclude -eq $false).Server) {
                    $DeviceStats = [PSCustomObject]@{
                        PendingUpdates = ((($UData.Sites | Where-Object -Property Server -Match $Server).Devices.data | Where-Object -Property upgradable -eq $true).count) + $DeviceStats.PendingUpdates
                        Unsupported    = ((($UData.Sites | Where-Object -Property Server -Match $Server).Devices.data | Where-Object -Property unsupported -eq $true).count) + $DeviceStats.Unsupported
                        Incompatible   = ((($UData.Sites | Where-Object -Property Server -Match $Server).Devices.data | Where-Object -Property model_incompatible -eq $true).count) + $DeviceStats.Incompatible
                        Mesh           = ((($UData.Sites | Where-Object -Property Server -Match $Server).Devices.data | Where-Object -Property mesh_sta_vap_enabled -eq $true).count) + $DeviceStats.Mesh
                        Locating       = ((($UData.Sites | Where-Object -Property Server -Match $Server).Devices.data | Where-Object -Property locating -eq $true).count) + $DeviceStats.Locating
                        Overheating    = ((($UData.Sites | Where-Object -Property Server -Match $Server).Devices.data | Where-Object -Property overheating -eq $true).count) + $DeviceStats.Overheating
                    }
                }
            }
    
            elseif ($Distribution) {
                foreach ($Server in ($UData.Server | Where-Object -Property Exclude -eq $false).Server) {
                    $DistributionStats += @([PSCustomObject]@{ 
                            Server              = $Server
                            Sites               = ($UData.Sites | Where-Object -Property Server -Match $Server).Count
                            PendingUpdates      = (($UData.Sites | Where-Object -Property Server -Match $Server).Devices.data.upgradable | Measure-Object -sum).sum
                            DevicesAdopted      = (($UData.Sites | Where-Object -Property Server -Match $Server).health.num_adopted | Measure-Object -sum).sum
                            DevicesOnline       = ((($UData.Sites | Where-Object -Property Server -Match $Server).health.num_ap | Measure-Object -sum).sum) + ((($UData.Sites | Where-Object -Property Server -Match $Server).health.num_sw | Measure-Object -sum).sum)
                            DevicesDisconnected = (($UData.Sites | Where-Object -Property Server -Match $Server).health.num_disconnected | Measure-Object -sum).sum
                            Clients             = (($UData.Sites | Where-Object -Property Server -Match $Server).health.num_user | Measure-Object -sum).sum
                        })
                }
            }

            else {
                foreach ($Server in ($UData.Server | Where-Object -Property Exclude -eq $false).Server) {
                    $ServerStats = [PSCustomObject]@{
                        Sites               = (($UData.Sites | Where-Object -Property Server -Match $Server).Count) + $ServerStats.Sites
                        DevicesAdopted      = ((($UData.Sites | Where-Object -Property Server -Match $Server).health.num_adopted | Measure-Object -sum).sum) + $ServerStats.DevicesAdopted
                        DevicesOnline       = ((($UData.Sites | Where-Object -Property Server -Match $Server).health.num_ap | Measure-Object -sum).sum) + ((($UData.Sites | Where-Object -Property Server -Match $Server).health.num_sw | Measure-Object -sum).sum) + $ServerStats.DevicesOnline
                        DevicesDisconnected = ((($UData.Sites | Where-Object -Property Server -Match $Server).health.num_disconnected | Measure-Object -sum).sum) + $ServerStats.DevicesDisconnected
                        Clients             = ((($UData.Sites | Where-Object -Property Server -Match $Server).health.num_user | Measure-Object -sum).sum) + $ServerStats.Clients 
                    }
                }
            }

            if ($Device) { 
                $DeviceStats
            }
            elseif ($Distribution) {
                foreach ($DistributionStat in $DistributionStats) {
                    $DistributionStat
                }
            }
            else {
                $ServerStats
            }
        }
        catch {
            return
        }
        finally {
            Remove-Variable -Name 'UData'
        }
    }
    finally {
        Remove-Variable * -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 5
        [System.GC]::Collect()
    }
}

Function Remove-USiteAlerts {
    param(
        [switch]$Live,
        [switch]$Show
    ) 
    try {
        if ($Live) {
            $UData = Import-UData -Live
        }
        else {
            $UData = Import-UData 
        }
        if ($UData -like 'Error') {
            return
        }

        foreach ($Site in $UData.Sites | Where-Object -Property Alarms -gt 0) {
            try {
                $URISplit = $null
                [uri]::TryCreate($Site.Server, [System.UriKind]::Absolute, [ref]$URISplit) | Out-Null
                $URL = "$($Site.Server)/manage/site/$($Site.SiteURL)/dashboard"

                if (!($Driver)) {
                    if ($Show) {
                        $Driver = Start-SeChrome -Quiet
                    }
                    else {
                        $Driver = Start-SeChrome -Headless -Quiet
                    }
                }

                Open-SeUrl -Driver $Driver -Url $URL
                while ($Driver.Url -notmatch 'unifi.telmekom.net:8443') { }

                if ($Driver.URL -match 'login') {
                    $Credential = @{
                        username = ($UData.Server[(($UData.Server.Host).IndexOf($URISplit.Host))].UserName)
                        password = ([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR(($UData.Server[(($UData.Server.Host).IndexOf($URISplit.Host))].Password))))
                    } | ConvertTo-Json

                    Send-SeKeys -Element (Get-SeElement -Driver $Driver -Name 'username') -Keys (($Credential | ConvertFrom-Json).username)
                    Send-SeKeys -Element (Get-SeElement -Driver $Driver -Name 'password') -Keys (($Credential | ConvertFrom-Json).password)
                    Invoke-SeClick -Driver $Driver -Element (Get-SeElement -Driver $Driver -Id 'loginButton') -JavaScriptClick
                    while ($Driver.Url -match 'login') { }
                    if ($Driver.Url -notlike $URL) {
                        Open-SeUrl -Driver $Driver -Url $URL
                        while ($Driver.Url -notlike $URL) { }
                    }
                }
                Invoke-SeClick -Driver $Driver -Element (Get-SeElement -Driver $Driver -XPath '//*[@id="alertsLink"]')
                Invoke-SeClick -Driver $Driver -Element (Get-SeElement -Driver $Driver -TagName 'BUTTON' | Where-Object -Property Text -Like 'ARCHIVE ALL')
            }   
            catch {
                return
            }     
        }
    }
    finally {
        Remove-Variable * -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 5
        [System.GC]::Collect()
    }
}

Function Invoke-UAutoMigrate {
    param (
        [parameter(Mandatory = $false, Position = 0)]
        [array]$Exclude,
        [switch]$Show
    )
    try {
        $UData = Import-UData -Full -Live
        if ($UData -like 'Error') {
            return
        }

        foreach ($Server in ($UData.Server | Where-Object -Property MigrateAble -eq $true).Server) {
            $Distribution += @([PSCustomObject]@{
                    Server         = $Server
                    Host           = ($UData.Server | Where-Object -Property Server -Match $Server).Host
                    InformURL      = ($UData.Server | Where-Object -Property Server -Match $Server).InformURL
                    InformPort     = ($UData.Server | Where-Object -Property Server -Match $Server).InformPort
                    DevicesAdopted = (($UData.Sites | Where-Object -Property Server -Match $Server).health.num_adopted | Measure-Object -sum).sum
                })
        }

        if ($Show) {
            $DriverOld = Start-SeChrome -Quiet -DefaultDownloadPath "$env:LOCALAPPDATA\Unifi\Export"
        }
        else {
            $DriverOld = Start-SeChrome -Headless -Quiet -DefaultDownloadPath "$env:LOCALAPPDATA\Unifi\Export"
        }

        try {
            foreach ($Server in ($UData.Server | Where-Object -Property Migrate -eq $true).Server) {
                $LogedIN = $false
                foreach ($Site in $UData.Sites | Where-Object -Property Server -Match $Server) {
                    if (('error' -notin $Site.Health.status) -and ((($Site.Health.num_disconnected | Measure-Object -sum).sum -like 0) -and (($Site.Health.num_adopted | Measure-Object -sum).sum -gt 0)) -and ($Site.Devices.data.unsupported -notcontains 'true') -and ($Site.SiteName -notlike $Exclude)) {
                        Write-Warning -Message "Starting migration of $($Site.SiteName)"

                        $URISplit = $null
                        [uri]::TryCreate($Site.Server, [System.UriKind]::Absolute, [ref]$URISplit) | Out-Null
                        $URL = "$($Site.Server)/manage/site/$($Site.SiteURL)/settings/site"

                        # login once
                        while (!($LogedIN)) {
                            $CredentialOld = @{
                                username = ($UData.Server[(($UData.Server.Host).IndexOf($URISplit.Host))].UserName)
                                password = ([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR(($UData.Server[(($UData.Server.Host).IndexOf($URISplit.Host))].Password))))
                            } | ConvertTo-Json
                            Open-SeUrl -Driver $DriverOld -Url $Site.Server
                            while ($DriverOld.Url -notmatch 'unifi.telmekom.net:8443') { }
   
                            Send-SeKeys -Element (Get-SeElement -Driver $DriverOld -Name 'username') -Keys (($CredentialOld | ConvertFrom-Json).username)
                            Send-SeKeys -Element (Get-SeElement -Driver $DriverOld -Name 'password') -Keys (($CredentialOld | ConvertFrom-Json).password)
                            Invoke-SeClick -Driver $DriverOld -Element (Get-SeElement -Driver $DriverOld -Id 'loginButton') -JavaScriptClick
                            while ($DriverOld.Url -match 'login') { }
                            $LogedIN = $true
                        }
                
                        try {
                            Invoke-RestMethod -Uri "$($Site.Server)/api/login" -Method Post -Body $CredentialOld -ContentType "application/json; charset=utf-8" -SessionVariable myWebSession -SkipCertificateCheck | Out-Null
                            $DeviceCount = ((Invoke-RestMethod -Uri "$($Site.Server)/api/s/$($Site.SiteURL)/stat/device" -WebSession $myWebSession -SkipCertificateCheck).data).count
                        }
                        catch {
                            Write-Warning -Message "Login to $($Site.Server) failed du to wrong credentials"
                            break
                        }
                        $DeviceOnline = ((((Invoke-RestMethod -Uri "$($Site.Server)/api/stat/sites" -WebSession $myWebSession -SkipCertificateCheck).data) | Where-Object -Property desc -like $Site.SiteName).health.num_disconnected).Where( { $null -ne $_ })
                        if ($DeviceOnline -eq 0) {
                            Invoke-RestMethod -Uri "$($Site.Server)/api/logout" -Method Post -ContentType "application/json; charset=utf-8" -SessionVariable myWebSession -SkipCertificateCheck | Out-Null
                            $MigrationHost = ($Distribution | Where-Object -Property DevicesAdopted -Like ($Distribution.DevicesAdopted | Measure-Object -Minimum).Minimum)
                    
                            Open-SeUrl -Driver $DriverOld -Url $URL
                            do { Start-Sleep 2 }while ($DriverOld.Url -notlike $URL)

                            Invoke-SeClick -Driver $DriverOld -Element ((Get-SeElement -Driver $DriverOld -TagName 'BUTTON') | Where-Object -Property Text -like 'EXPORT SITE') -JavaScriptClick

                            $ExportCount = (Get-ChildItem -Path "$env:LOCALAPPDATA\Unifi\Export").Count
                            Invoke-SeClick -Driver $DriverOld -Element ((Get-SeElement -Driver $DriverOld -TagName 'BUTTON') | Where-Object -Property Text -like 'Download backup file') -JavaScriptClick
                            while (((Get-ChildItem -Path "$env:LOCALAPPDATA\Unifi\Export").Count) -eq $ExportCount) { }

                            Invoke-SeClick -Driver $DriverOld -Element ((Get-SeElement -Driver $DriverOld -TagName 'BUTTON') | Where-Object -Property Text -like 'Confirm') -JavaScriptClick

                            ###############################
                            if ($Show) {
                                $DriverNew = Start-SeChrome -StartURL $MigrationHost[0].Server -Quiet -DefaultDownloadPath "$env:LOCALAPPDATA\Unifi\Export"
                            }
                            else {
                                $DriverNew = Start-SeChrome -Headless -StartURL $MigrationHost[0].Server -Quiet -DefaultDownloadPath "$env:LOCALAPPDATA\Unifi\Export"
                            }

                            while ($DriverNew.Url -notmatch 'unifi.telmekom.net:8443') { }

                            $CredentialNew = @{
                                username = ($UData.Server[(($UData.Server.Host).IndexOf($MigrationHost[0].Host))].UserName)
                                password = ([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR(($UData.Server[(($UData.Server.Host).IndexOf($MigrationHost[0].Host))].Password))))
                            } | ConvertTo-Json
                            Send-SeKeys -Element (Get-SeElement -Driver $DriverNew -Name 'username') -Keys (($CredentialNew | ConvertFrom-Json).username)
                            Send-SeKeys -Element (Get-SeElement -Driver $DriverNew -Name 'password') -Keys (($CredentialNew | ConvertFrom-Json).password)
                            Invoke-SeClick -Driver $DriverNew -Element (Get-SeElement -Driver $DriverNew -Id 'loginButton') -JavaScriptClick
                            while ($DriverNew.Url -match 'login') { }
                
                            Invoke-SeClick -Driver $DriverNew -Element (Get-SeElement -Driver $DriverNew -XPath '/html/body/div/ui-view/ui-view/div/unifi-global-header/header/div/div[3]/div[2]/div[1]/div') -JavaScriptClick
                            Invoke-SeClick -Driver $DriverNew -Element ((Get-SeElement -Driver $DriverNew -TagName 'a') | Where-Object -Property Text -like 'Import site') -JavaScriptClick
                            Send-SeKeys -Element (Get-SeElement -Driver $DriverNew -Name 'name') -Keys ($Site.SiteName)
                   
                            $SiteToImport = (Get-ChildItem -Path "$env:LOCALAPPDATA\Unifi\Export" | Sort-Object LastAccessTime -Descending | Select-Object -First 1)
                            $SiteRenamed = Rename-Item -Path $SiteToImport.FullName -NewName (($Site.SiteName).Replace('/', ' ').Replace('?', ' ') + '.unf') -Force -PassThru
                            $URLBeforImport = $DriverNew.Url
                            Send-SeKeys -Element (Get-SeElement -Driver $DriverNew -XPath '/html/body/label/input') -Keys $SiteRenamed.FullName
                            while ($DriverNew.Url -like $URLBeforImport) { Start-Sleep 2 }

                            Open-SeUrl -Driver $DriverNew -Url ($DriverNew.Url.Replace('dashboard', 'settings/site'))
                            do { Start-Sleep 2 } while ($DriverNew.Url -notmatch 'settings/site')

                            $ChangedSettings = 0
                            if ((Get-SeElement -Driver $DriverNew -Name 'siteEnableAdvancedFeatures').Selected -like $false) {
                                Invoke-SeClick -Driver $DriverNew -Element (Get-SeElement -Driver $DriverNew -Name 'siteEnableAdvancedFeatures') -JavaScriptClick
                                $ChangedSettings += 1
                            }
                            if ((Get-SeElement -Driver $DriverNew -Name 'siteEnableAutoUpgrade').Selected -like $true) {
                                Invoke-SeClick -Driver $DriverNew -Element (Get-SeElement -Driver $DriverNew -Name 'siteEnableAutoUpgrade') -JavaScriptClick
                                $ChangedSettings += 1
                            }
                            if ((Get-SeElement -Driver $DriverNew -Name 'siteEnableAlerts').Selected -like $true) {
                                Invoke-SeClick -Driver $DriverNew -Element (Get-SeElement -Driver $DriverNew -Name 'siteEnableAlerts') -JavaScriptClick
                                $ChangedSettings += 1
                            }
                            if ($ChangedSettings -gt 0) {
                                Invoke-SeClick -Driver $DriverNew -Element ((Get-SeElement -Driver $DriverNew -TagName 'BUTTON') | Where-Object -Property Text -like 'Apply Changes') -JavaScriptClick
                            }
                            #################################

                            ($Element = Get-SeElement -Driver $DriverOld -Name 'migrate_hostname').clear()
                            Send-SeKeys -Element $Element -Keys $MigrationHost[0].InformURL
                            ($Element = Get-SeElement -Driver $DriverOld -Name 'migrate_port').clear()
                            Send-SeKeys -Element $Element -Keys $MigrationHost[0].InformPort

                            Invoke-SeClick -Driver $DriverOld -Element ((Get-SeElement -Driver $DriverOld -TagName 'BUTTON') | Where-Object -Property Text -like 'Migrate devices') -JavaScriptClick

                            $TimeOut = 0
                            Invoke-RestMethod -Uri "$($MigrationHost[0].Server)/api/login" -Method Post -Body $CredentialNew -ContentType "application/json; charset=utf-8" -SessionVariable myWebSession -SkipCertificateCheck | Out-Null
                            $DeviceOnline = ((((Invoke-RestMethod -Uri "$($MigrationHost[0].Server)/api/stat/sites" -WebSession $myWebSession -SkipCertificateCheck).data) | Where-Object -Property desc -like $Site.SiteName).health.num_disconnected).Where( { $null -ne $_ })
                            while ($DeviceOnline -notmatch 0) {

                                Start-Sleep 30
                                $DeviceOnline = ((((Invoke-RestMethod -Uri "$($MigrationHost[0].Server)/api/stat/sites" -WebSession $myWebSession -SkipCertificateCheck).data) | Where-Object -Property desc -like $Site.SiteName).health.num_disconnected).Where( { $null -ne $_ })                    
                                $TimeOut += 1

                                if ($TimeOut -gt 15) {
                                    Write-Warning -Message "Migration of Site $($Site.SiteName) failed"
                                    Read-Host -Prompt 'Press enter to exit'
                                    break
                                }
                            }
                            Invoke-RestMethod -Uri "$($Site.Server)/api/logout" -Method Post -ContentType "application/json; charset=utf-8" -SessionVariable myWebSession -SkipCertificateCheck | Out-Null

                            Invoke-SeClick -Driver $DriverOld -Element ((Get-SeElement -Driver $DriverOld -TagName 'BUTTON') | Where-Object -Property Text -like 'Skip') -JavaScriptClick
                            Invoke-SeClick -Driver $DriverOld -Element ((Get-SeElement -Driver $DriverOld -TagName 'BUTTON') | Where-Object -Property Text -like 'DELETE SITE') -JavaScriptClick
                            Invoke-SeClick -Driver $DriverOld -Element ((Get-SeElement -Driver $DriverOld -TagName 'BUTTON') | Where-Object -Property Text -like 'Confirm') -JavaScriptClick
                            while ($DriverOld.Url -notmatch '/manage/site/default/dashboard') { Start-Sleep -Seconds 5 }

                            $DriverNew.Close()
                            Write-Warning -Message "$($Site.SiteName) has been successfully migrated to $($MigrationHost[0].Server)"
                            $Distribution[(($Distribution.Server).IndexOf($MigrationHost[0].Server))].DevicesAdopted += $DeviceCount
                        }   
                        else {
                            Write-Warning -Message "Migration of Site $($Site.SiteName) failed, not all devices where online"
                            Invoke-RestMethod -Uri "$($Site.Server)/api/logout" -Method Post -ContentType "application/json; charset=utf-8" -SessionVariable myWebSession -SkipCertificateCheck | Out-Null
                        }     
                    } 
                }
            }
        }
        catch {
            Write-Error -Message ($_.Exception.Message)
            if ($DriverOld) {
                $DriverOld.Close()
            }
            if ($DriverNew) {
                $DriverNew.Close()
            }
            return
        }
        finally {
            if ($DriverOld) {
                $DriverOld.Close()
            }
            if ($DriverNew) {
                $DriverNew.Close()
            }
            Get-process -Name 'chromedriver' -ErrorAction SilentlyContinue | Stop-Process -ErrorAction SilentlyContinue
        }
    }
    finally {
        Remove-Variable * -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 5
        [System.GC]::Collect()
    }
}

Function Invoke-UAutoUpgrade {
    param(
        [switch]$Live
    ) 
    try {
        if ($Live) {
            $UData = Import-UData -Full -Live
        }
        else {
            $UData = Import-UData -Full
        }
        if ($UData -like 'Error') {
            return
        }
    
        foreach ($Site in $UData.Sites) {
            foreach ($Device in ($Site.Devices.data) | Where-Object -Property upgradable -like 'true') {
                $URISplit = $null
                [uri]::TryCreate($Site.Server, [System.UriKind]::Absolute, [ref]$URISplit) | Out-Null
                $Credential = @{
                    username = ($UData.Server[(($UData.Server.Host).IndexOf($URISplit.Host))].UserName)
                    password = ([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR(($UData.Server[(($UData.Server.Host).IndexOf($URISplit.Host))].Password))))
                } | ConvertTo-Json

                Invoke-RestMethod -Uri "$($Site.Server)/api/login" -Method Post -Body $Credential -ContentType "application/json; charset=utf-8" -SessionVariable myWebSession -SkipCertificateCheck | Out-Null
                $DeviceStatus = (Invoke-RestMethod -Uri "$($Site.Server)/api/s/$($Site.SiteURL)/stat/device" -WebSession $myWebSession -SkipCertificateCheck).data | Where-Object -Property mac -like $Device.mac

                if ($DeviceStatus.state -like 1) {
                    Write-Host -Message "Starting Upgrade for $($Device.name) on site $($Site.SiteName) on server $($Site.Server)" -ForegroundColor Yellow

                    $Json = @{
                        cmd = 'upgrade'
                        mac = "$($Device.mac)"
                    } | ConvertTo-Json

                    Invoke-RestMethod -Uri "$($Site.Server)/api/s/$($Site.SiteURL)/cmd/devmgr" -WebSession $myWebSession -SkipCertificateCheck -Body $Json -Method Post | Out-Null

                    $DeviceStatus = (Invoke-RestMethod -Uri "$($Site.Server)/api/s/$($Site.SiteURL)/stat/device" -WebSession $myWebSession -SkipCertificateCheck).data | Where-Object -Property mac -like $Device.mac

                    $TimeOut = 0
                    while (($DeviceStatus.state -notlike 1) -and ($TimeOut -le 15)) {
                        Start-Sleep 30

                        $DeviceStatus = (Invoke-RestMethod -Uri "$($Site.Server)/api/s/$($Site.SiteURL)/stat/device" -WebSession $myWebSession -SkipCertificateCheck).data | Where-Object -Property mac -like $Device.mac

                        $TimeOut += 1
                        if ($TimeOut -gt 15) {
                            Write-Host -Message "Upgrade for $($Device.name) on site $($Site.SiteName) on server $($Site.Server) failed" -ForegroundColor Red
                        }
                    }
                    if ($TimeOut -le 15) {
                        Write-Host -Message "Upgrade for $($Device.name) on site $($Site.SiteName) on server $($Site.Server) successfully" -ForegroundColor Green
                    }
                    Invoke-RestMethod -Uri "$($Site.Server)/api/logout" -Method Post -ContentType "application/json; charset=utf-8" -SessionVariable myWebSession -SkipCertificateCheck | Out-Null
                }
            }
        }
    }
    finally {
        Remove-Variable * -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 5
        [System.GC]::Collect()
    }
}

Function Invoke-UAutoClusterUpgrade {
    param(
        [switch]$Live
    ) 

    if ($Live) {
        $UData = Import-UData -Full -Live
    }
    else {
        $UData = Import-UData -Full
    }
    if ($UData -like 'Error') {
        return
    }
    foreach ($Server in $UData.Server) {
        $Sites = @()
        foreach ($Site in $UData.Sites | Where-Object { $_.Server -Match $Server.Server }) {
            $Sites += $Site
        }
        $Sites | Export-CliXml -Path (Join-Path -Path $Env:LOCALAPPDATA -ChildPath "Unifi\Cluster-$($Server.Host).xml") -Force | Out-Null
    }

    try {
        foreach ($Server in $UData.Server) {
            Start-Job -Name $Server.Host -ScriptBlock {
                $UData = Import-CliXml -Path (Join-Path -Path $Env:LOCALAPPDATA -ChildPath "Unifi\Cluster-$($Using:Server.Host).xml")
                Start-Sleep -Seconds 30
                Register-EngineEvent -SourceIdentifier SuccessEvent -Forward
                Register-EngineEvent -SourceIdentifier InfoEvent -Forward
                Register-EngineEvent -SourceIdentifier ErrorEvent -Forward
                Register-EngineEvent -SourceIdentifier CommonEvent -Forward

                $Credential = @{
                    username = $Using:Server.UserName
                    password = ([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Using:Server.Password)))

                } | ConvertTo-Json
                try {
                    $Login = Invoke-RestMethod -Uri "$($Using:Server.Server)/api/login" -Method Post -Body $Credential -ContentType "application/json; charset=utf-8" -SessionVariable myWebSession -SkipCertificateCheck
                    if ($Login.meta.rc -notlike 'ok') {
                        throw
                    }
                }
                catch {
                    return
                }

                New-Event -SourceIdentifier CommonEvent -MessageData "Firmware Rollout on server $($Using:Server.Server) started"
                Start-Sleep -Seconds 30

                New-Event -SourceIdentifier InfoEvent -MessageData "Starting Upgrade for $($Device.name) on site $($Site.SiteName) on server $($Site.Server)"

                foreach ($Site in $UData) {
                    foreach ($Device in ($Site.Devices.data) | Where-Object -Property upgradable -like 'true') {       
                        
                        $DeviceStatus = (Invoke-RestMethod -Uri "$($Site.Server)/api/s/$($Site.SiteURL)/stat/device" -WebSession $myWebSession -SkipCertificateCheck).data | Where-Object -Property mac -like $Device.mac
                        if ($DeviceStatus.state -like 1) {
                            New-Event -SourceIdentifier InfoEvent -MessageData "Starting Upgrade for $($Device.name) on site $($Site.SiteName) on server $($Site.Server)"
            
                            $Json = @{
                                cmd = 'upgrade'
                                mac = "$($Device.mac)"
                            } | ConvertTo-Json
            
                            Invoke-RestMethod -Uri "$($Site.Server)/api/s/$($Site.SiteURL)/cmd/devmgr" -WebSession $myWebSession -SkipCertificateCheck -Body $Json -Method Post | Out-Null           
                            $DeviceStatus = (Invoke-RestMethod -Uri "$($Site.Server)/api/s/$($Site.SiteURL)/stat/device" -WebSession $myWebSession -SkipCertificateCheck).data | Where-Object -Property mac -like $Device.mac
            
                            $TimeOut = 0
                            while (($DeviceStatus.state -notlike 1) -and ($TimeOut -le 15)) {
                                Start-Sleep 30
            
                                $DeviceStatus = (Invoke-RestMethod -Uri "$($Site.Server)/api/s/$($Site.SiteURL)/stat/device" -WebSession $myWebSession -SkipCertificateCheck).data | Where-Object -Property mac -like $Device.mac
            
                                $TimeOut += 1
                                if ($TimeOut -gt 15) {
                                    New-Event -SourceIdentifier ErrorEvent -MessageData "Upgrade for $($Device.name) on site $($Site.SiteName) on server $($Site.Server) failed"
                                }
                            }
                            if ($TimeOut -le 15) {
                                New-Event -SourceIdentifier SuccessEvent -MessageData "Upgrade for $($Device.name) on site $($Site.SiteName) on server $($Site.Server) successfully"
                            }            
                        }
                    }
                }
                Invoke-RestMethod -Uri "$($Using:Server.Server)/api/logout" -Method Post -ContentType "application/json; charset=utf-8" -SessionVariable myWebSession -SkipCertificateCheck | Out-Null
                New-Event -SourceIdentifier CommonEvent -MessageData "Firmware Rollout on server $($Using:Server.Server) finished"
            } | Out-Null
        }

        Register-EngineEvent -SourceIdentifier SuccessEvent -Action {
            Write-Host $Event.MessageData -ForegroundColor Green
        } | Out-Null
        Register-EngineEvent -SourceIdentifier InfoEvent -Action {
            Write-Host $Event.MessageData -ForegroundColor Yellow
        } | Out-Null
        Register-EngineEvent -SourceIdentifier ErrorEvent -Action {
            Write-Host $Event.MessageData -ForegroundColor Red
        } | Out-Null

        Register-EngineEvent -SourceIdentifier CommonEvent -Action {
            Write-Host $Event.MessageData -ForegroundColor Gray
        } | Out-Null

        Remove-Variable UData, Sites -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 10
        [System.GC]::Collect()
        Write-Host 'Site parsing completed, firmware rollout will start soon'
        
        while ((Get-Job | Where-Object -Property Location -Like 'localhost').State -like 'Running') {
        }
    }
    finally {
        Get-Job | Stop-Job
        Get-Job | Remove-Job -Force
        Remove-Variable * -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 5
        [System.GC]::Collect()
    }
}

Function Export-USiteXLSX {
    param(
        [switch]$Live
    ) 
    try {
        if ($Live) {
            $UData = Import-UData -Live
        }
        else {
            $UData = Import-UData 
        }
        if ($UData -like 'Error') {
            return
        }

        foreach ($Site in $UData.Sites) {
            $ObjectListXML += @([PSCustomObject]@{
                    Host   = $Site.Server
                    Client = $Site.SiteName
                    URL    = "$($Site.Server)/$($Site.SiteURL)/dashboard"
                })
        }

        Export-XLSX -Path (Join-Path -Path $Env:LOCALAPPDATA -ChildPath 'Unifi\Site.xlsx') -InputObject $ObjectListXML -Force
    }
    finally {
        Remove-Variable * -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 5
        [System.GC]::Collect()
    }
}

Function Get-UInformSite {
    param(
        [parameter(Mandatory = $true, Position = 0)]
        [ValidatePattern("^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", ErrorMessage = 'Insert correct form of an MAC **:**:**:**:**:**')]
        [string]$MAC,
        [switch]$Live
    ) 
    try {
        if ($Live) {
            $UData = Import-UData -Full -Live
        }
        else {
            $UData = Import-UData -Full
        }
        if ($UData -like 'Error') {
            return
        }
        foreach ($Site in $UData.Sites) {
            foreach ($Device in $Site.Devices.data | Where-Object -Property mac -like $MAC) {
                $Site | Select-Object -Property Server, SiteName
            }
        }
    }
    finally {
        Remove-Variable * -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 5
        [System.GC]::Collect()
    }
}

Function Update-UWebDriver {
    param(
        [switch]$MSEdge,
        [switch]$Chrome,
        [switch]$Firefox
    )
    try {
        [string]$SeleniumVersion = (Get-InstalledModule -Name Selenium).Version

        if ($MSEdge) {

            [version]$InstalledEdgeVersion = (Get-Item (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe').'(Default)').VersionInfo.ProductVersion
            [version]$InstalledEdgeWebDriverVersion = (Get-Item "$env:USERPROFILE\Documents\PowerShell\Modules\Selenium\$SeleniumVersion\assemblies\msedgedriver.exe").VersionInfo.ProductVersion

            foreach ($EdgeWebDrive in (Get-Item (Join-Path -Path $Env:LOCALAPPDATA -ChildPath 'Unifi\Selenium\msedgedriver*')).VersionInfo) {
                $AvailableEdgeWebDrive += @(New-Object PSObject -Property @{ 
                        ProductName    = $EdgeWebDrive.OriginalFilename
                        ProductVersion = [version]$EdgeWebDrive.ProductVersion
                        FullName       = $EdgeWebDrive.FileName
                    })
            }

            $MatchingEdgeWebDriver = $AvailableEdgeWebDrive | Where-Object { $_.ProductVersion.Major -like $InstalledEdgeVersion.Major }

            if (($MatchingEdgeWebDriver.ProductVersion -gt $InstalledEdgeWebDriverVersion) -and ($MatchingEdgeWebDriver)) {
    
                $HighestVersion = $MatchingEdgeWebDriver | Where-Object { $_.ProductVersion -eq ($MatchingEdgeWebDriver | Measure-Object -Property ProductVersion -Maximum).Maximum }
                try {
                    Get-Process -Name 'msedgedriver' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
                    Copy-Item -Path $HighestVersion.FullName -Destination "$env:USERPROFILE\Documents\PowerShell\Modules\Selenium\$SeleniumVersion\assemblies\chromedriver.exe" -Force -ErrorAction Stop
                    Write-Warning "$($HighestVersion.ProductName) version $($HighestVersion.ProductVersion) for MSEdge has been installed"
                }
                catch {
                    Write-Warning 'Could not update MSEdge Web Driver'
                }    
            }
            else {
                Write-Warning 'Most recent MSEdge Web Driver is allready installed'
            }
        }

        if ($Chrome) {

            [version]$InstalledChromeVersion = (Get-Item (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe').'(Default)').VersionInfo.ProductVersion
            [version]$InstalledChromeWebDriverVersion = (Get-Item "$env:USERPROFILE\Documents\PowerShell\Modules\Selenium\$SeleniumVersion\assemblies\chromedriver.exe").VersionInfo.ProductVersion

            foreach ($ChromeWebDrive in (Get-Item (Join-Path -Path $Env:LOCALAPPDATA -ChildPath 'Unifi\Selenium\chromedriver*')).VersionInfo) {
                $AvailableChromeWebDrive += @(New-Object PSObject -Property @{ 
                        ProductName    = $ChromeWebDrive.OriginalFilename
                        ProductVersion = [version]$ChromeWebDrive.ProductVersion
                        FullName       = $ChromeWebDrive.FileName
                    })
            }

            $MatchingChromeWebDriver = $AvailableChromeWebDrive | Where-Object { $_.ProductVersion.Major -like $InstalledChromeVersion.Major }

            if (($MatchingChromeWebDriver.ProductVersion -gt $InstalledChromeWebDriverVersion) -and ($MatchingChromeWebDriver)) {
    
                $HighestVersion = $MatchingChromeWebDriver | Where-Object { $_.ProductVersion -eq ($MatchingChromeWebDriver | Measure-Object -Property ProductVersion -Maximum).Maximum }
                try {
                    Get-Process -Name 'chromedriver' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
                    Copy-Item -Path $HighestVersion.FullName -Destination "$env:USERPROFILE\Documents\PowerShell\Modules\Selenium\$SeleniumVersion\assemblies\chromedriver.exe" -Force -ErrorAction Stop
                    Write-Warning "$($HighestVersion.ProductName) version $($HighestVersion.ProductVersion) for Chrome has been installed"
                }
                catch {
                    Write-Warning 'Could not update Chrome Web Driver'
                }    
            }
            else {
                Write-Warning 'Most recent Chrome Web Driver is allready installed'
            }
        }
        if ($Firefox) {

            [version]$InstalledFirefoxVersion = (Get-Item (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe').'(Default)').VersionInfo.ProductVersion
            [version]$InstalledFirefoxWebDriverVersion = (Get-Item "$env:USERPROFILE\Documents\PowerShell\Modules\Selenium\$SeleniumVersion\assemblies\geckodriver.exe").VersionInfo.ProductVersion

            foreach ($FirefoxWebDrive in (Get-Item (Join-Path -Path $Env:LOCALAPPDATA -ChildPath 'Unifi\Selenium\geckodriver*')).VersionInfo) {
                $AvailableFirefoxWebDrive += @(New-Object PSObject -Property @{ 
                        ProductName    = $FirefoxWebDrive.OriginalFilename
                        ProductVersion = [version]$FirefoxWebDrive.ProductVersion
                        FullName       = $FirefoxWebDrive.FileName
                    })
            }

            if (($AvailableFirefoxWebDrive.ProductVersion -gt $InstalledFirefoxWebDriverVersion) -and ($AvailableFirefoxWebDrive)) {
    
                $HighestVersion = $AvailableFirefoxWebDrive | Where-Object { $_.ProductVersion -eq ($AvailableFirefoxWebDrive | Measure-Object -Property ProductVersion -Maximum).Maximum }
                try {
                    Get-Process -Name 'geckodriver' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
                    Copy-Item -Path $HighestVersion.FullName -Destination "$env:USERPROFILE\Documents\PowerShell\Modules\Selenium\$SeleniumVersion\assemblies\geckodriver.exe" -Force -ErrorAction Stop
                    Write-Warning "$($HighestVersion.ProductName) version $($HighestVersion.ProductVersion) for Firefox has been installed"
                }
                catch {
                    Write-Warning 'Could not update Firefox Web Driver'
                }    
            }
            else {
                Write-Warning 'Most recent Firefox Web Driver is allready installed'
            }
        }
    }
    finally {
        Remove-Variable * -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 5
        [System.GC]::Collect()
    }
}

#Helper Functions
Function Import-UData {
    param(
        [switch]$Full,
        [switch]$Live,
        [switch]$OnlySite,
        [switch]$WithoutSite
    )

    if (!($OnlySite)) {
        #retriving server data
        try {
            if (Test-Path -Path (Join-Path -Path $Env:LOCALAPPDATA -ChildPath 'Unifi\Server.xml')) {
                $Servers = Import-CliXml -Path (Join-Path -Path $Env:LOCALAPPDATA -ChildPath 'Unifi\Server.xml')
            }
            else {
                throw
            }
        }
        catch {
            Write-Warning "$env:LOCALAPPDATA\Unifi\Server.xml not found"
            Write-Warning "Run Add-UServerFile first"
            return
        }
    }

    if (!($WithoutSite)) {
        #retriving site data
        if (($Live) -and ($Full)) {
            $Sites = Get-USiteInformation -Server $Servers -Full
            if ($Sites -like 'Error') {
                return 'Error'
            }
        }
        elseif ($Live) {
            $Sites = Get-USiteInformation -Server $Servers
            if ($Sites -like 'Error') {
                return 'Error'
            }
        }
        else {
            try {
                if ($Full) {
                    $Sites = Import-Clixml "$env:LOCALAPPDATA\Unifi\SitesFull.xml"
                }
                else {
                    $Sites = Import-Clixml "$env:LOCALAPPDATA\Unifi\Sites.xml"
                }
            }
            catch {
                Write-Warning "$env:LOCALAPPDATA\Unifi\Sites.xml or $env:LOCALAPPDATA\Unifi\SitesFull.xml not found"
                Write-Warning "Run Add-USiteFile -Full first"
                return 'Error'
            }
        }
    }
    return (@([PSCustomObject]@{
                Sites  = $Sites
                Server = $Servers
            }))          
} 

Function Get-USiteInformation {
    param (
        [parameter(Mandatory = $true, Position = 0)]
        [array]$Server,
        [switch]$Full
    )

    Write-Host 'Parsing all Sites - Please Wait'
    foreach ($Item in $Server) {
        try {
            $Reachable = Test-NetConnection -ComputerName $Item.Host -Port $Item.Port -InformationLevel Quiet -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            if (!($Reachable)) {
                throw
            }
            $Credential = @{
                username = $Item.UserName
                password = ([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Item.Password)))
            } | ConvertTo-Json
            $Login = $null
            $Login = Invoke-RestMethod -Uri "$($Item.Server)/api/login" -Method Post -Body $Credential -ContentType "application/json; charset=utf-8" -SessionVariable myWebSession -SkipCertificateCheck
            if ($Login.meta.rc -notlike 'ok') {
                throw
            }
        }
        catch {
            Write-Warning -Message "Login to $($Item.Server) failed"
            return 'Error'
        }
        foreach ($Site in (Invoke-RestMethod -Uri "$($Item.Server)/api/stat/sites" -WebSession $myWebSession -SkipCertificateCheck).data) {
            if ($Full) {
                $Sites += @([PSCustomObject]@{
                        Server   = $Item.Server
                        SiteID   = $Site._id
                        SiteURL  = $Site.name
                        SiteName = $Site.desc
                        Health   = $Site.health
                        Alarms   = $Site.num_new_alarms
                        Devices  = Invoke-RestMethod -Uri "$($Item.Server)/api/s/$($Site.Name)/stat/device" -WebSession $myWebSession -SkipCertificateCheck
                    })
            }
            else {
                $Sites += @([PSCustomObject]@{
                        Server   = $Item.Server
                        SiteID   = $Site._id
                        SiteURL  = $Site.name
                        SiteName = $Site.desc
                        Alarms   = $Site.num_new_alarms
                    })
            }
        }
        Invoke-RestMethod -Uri "$($Item.Server)/api/logout" -Method Post -ContentType "application/json; charset=utf-8" -SessionVariable myWebSession -SkipCertificateCheck | Out-Null
    }
    return $Sites
}

Function Search-USite {
    param (
        [parameter(Mandatory = $true, Position = 0)]
        [psobject]$UData
    )

    do {
        do {
            $SelectionSite = $UData.Sites | Where-Object -Property SiteName -match (Read-Host -Prompt 'Search for Site Name / Customer ID (Enter for a list of all Sites)') -ErrorAction SilentlyContinue
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
        $Switch += "`n`t$i {return '$($SelectionSite[$i-1].Server)/manage/site/$($SelectionSite[$i-1].SiteURL)/devices/1/100'}"
    }
    $Switch += "`n}"
    Invoke-Expression $Switch
}
