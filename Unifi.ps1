if (!(Test-Path -Path (Join-Path -Path $Env:LOCALAPPDATA -ChildPath 'Unifi'))) {
    New-Item -Path $Env:LOCALAPPDATA -Name 'Unifi' -ItemType Directory | Out-Null
}
Function Add-UServerFile {
    param(
        [parameter(Mandatory = $true, Position = 0)]
        [ValidatePattern("^(?:http(s)?:*)", ErrorMessage = 'Insert correct form of an URL <http|https://<server>:<port>>')]
        [ValidateScript( { [uri]::TryCreate($_, [System.UriKind]::Absolute, [ref]$null) }, ErrorMessage = 'Insert correct form of an URL <http|https://<server>:<port>>')]
        [array]$Server
    )

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
                $Reachable = Test-NetConnection -ComputerName $URISplit.Host -Port $URISplit.Port -InformationLevel Quiet
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
                Protocol = $URISplit.Scheme
                Host     = $URISplit.Host
                Port     = $URISplit.Port
                Server   = "$($URISplit.Scheme)://$($URISplit.Authority)"
                Exclude  = $false
                UserName = $Credential.UserName
                Password = $Credential.Password
            })
    }
    $Servers | Export-CliXml -Path (Join-Path -Path $Env:LOCALAPPDATA -ChildPath 'Unifi\Server.xml') -Force | Out-Null
}

Function Set-UServerFile {
    param(
        [array]$Exlude,
        [array]$Include
    )
    $Servers = (Import-UData -WithoutSite).Host
    foreach ($Item in $Exlude) {
        $Servers[(($Servers.Host).IndexOf($Item))].Exlude = $true
    }
    foreach ($Item in $Include) {
        $Servers[(($Servers.Host).IndexOf($Item))].Exlude = $false
    }
    $Servers | Export-CliXml -Path (Join-Path -Path $Env:LOCALAPPDATA -ChildPath 'Unifi\Server.xml') -Force | Out-Null
}

Function Add-USiteFile {
    param(
        [switch]$Full
    )

    $UData = Import-UData -WithoutSite

    if ($Full) {
        $Sites = Get-USiteInformation -Server $UData.Host -Full
        $Sites | Export-CliXml -Path (Join-Path -Path $Env:LOCALAPPDATA -ChildPath 'Unifi\SitesFull.xml') -Force | Out-Null
    }
    else {
        $Sites = Get-USiteInformation -Server $UData.Host
        $Sites | Export-CliXml -Path (Join-Path -Path $Env:LOCALAPPDATA -ChildPath 'Unifi\Sites.xml') -Force | Out-Null
    }
}

Function Open-USite {
    param(
        [switch]$Chrome,
        [switch]$Firefox,
        [switch]$Live
    )

    if ($Live) {
        $UData = Import-UData -Live
    }
    else {
        $UData = Import-UData
    }
    $URL = Search-USite -UData $UData

    try {
        $URISplit = $null
        [uri]::TryCreate($URL, [System.UriKind]::Absolute, [ref]$URISplit) | Out-Null
        $Reachable = Test-NetConnection -ComputerName $URISplit.Host -Port $URISplit.Port -InformationLevel Quiet
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
        if ($Reachable) {
            Write-Warning -Message "Login to $($URISplit.Host):$($URISplit.Port) failed"
        }
        exit
    }
    Invoke-RestMethod -Uri "$($URISplit.Scheme)://$($URISplit.Authority)/api/logout" -Method Post -ContentType "application/json; charset=utf-8" -SessionVariable myWebSession -SkipCertificateCheck | Out-Null
    $DefaultBrowserName = (Get-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice' | Get-ItemProperty).ProgId

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
            $Driver = Start-SeFirefox -StartURL $URL -Maximized -Quiet -Arguments '-profile', "$env:LOCALAPPDATA\Unifi\Firefox\Unifi"
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

Function Add-UProfile {
    param(
        [switch]$Chrome,
        [switch]$Firefox,
        [switch]$Refresh
    )

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

Function Get-USiteURL {
    param(
        [switch]$Live
    )

    if ($Live) {
        $UData = Import-UData -Live
    }
    else {
        $UData = Import-UData
    }

    $URL = Search-USite -UData $UData
    Write-Host -Object $URL
}

Function Get-UServerStats {
    param(
        [switch]$Device,
        [switch]$Distribution,
        [switch]$Live
    ) 

    if ($Live) {
        $UData = Import-UData -Live -Full
    }
    else {
        $UData = Import-UData -Full 
    }

    if ($Device) {
        $DeviceStats = [PSCustomObject]@{
            PendingUpdates = ($UData.Sites.Devices.data | Where-Object -Property upgradable -eq $true).Count
            Unsupported    = ($UData.Sites.Devices.data | Where-Object -Property unsupported -eq $true).Count
            Incompatible   = ($UData.Sites.Devices.data | Where-Object -Property model_incompatible -eq $true).Count
            Mesh           = ($UData.Sites.Devices.data | Where-Object -Property mesh_sta_vap_enabled -eq $true).Count
            Locating       = ($UData.Sites.Devices.data | Where-Object -Property locating -eq $true).Count
            Overheating    = ($UData.Sites.Devices.data | Where-Object -Property overheating -eq $true).Count
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
        $ServerStats = [PSCustomObject]@{
            Sites               = $UData.Sites.Count
            DevicesAdopted      = ($UData.Sites.health.num_adopted | Measure-Object -sum).sum
            DevicesOnline       = (($UData.Sites.health.num_ap | Measure-Object -sum).sum) + (($UData.Sites.health.num_sw | Measure-Object -sum).sum)
            DevicesDisconnected = ($UData.Sites.health.num_disconnected | Measure-Object -sum).sum
            Clients             = ($UData.Sites.health.num_user | Measure-Object -sum).sum  
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
            exit
        }
    }

    if (!($WithoutSite)) {
        #retriving site data
        if (($Live) -and ($Full)) {
            $Sites = Get-USiteInformation -Server $Servers -Credential $Credential -Full
        }
        elseif ($Live) {
            $Sites = Get-USiteInformation -Server $Servers -Credential $Credential
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
                exit
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
            $URL = "$($Item.Protocol)://$($Item.Server):$($Item.Port)"
            $Reachable = Test-NetConnection -ComputerName $Item.Server -Port $Item.Port -InformationLevel Quiet
            if (!($Reachable)) {
                throw
            }
            $Credential = @{
                username = $Item.UserName
                password = ([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Item.Password)))
            } | ConvertTo-Json
            $Login = $null
            $Login = Invoke-RestMethod -Uri "$URL/api/login" -Method Post -Body $Credential -ContentType "application/json; charset=utf-8" -SessionVariable myWebSession -SkipCertificateCheck
            if ($Login.meta.rc -notlike 'ok') {
                throw
            }
        }
        catch {
            if ($Reachable) {
                Write-Warning -Message "Login to $($Item.Server):$($Item.Port) failed"
            }
            exit
        }

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
    return $Sites
}

Function Search-USite {
    param (
        [parameter(Mandatory = $true, Position = 0)]
        [psobject]$UData,
        [switch]$URL
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