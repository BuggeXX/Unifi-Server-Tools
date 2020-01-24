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
        Remove-Variable 'Server', 'Servers', 'Item'
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
        Remove-Variable 'Credential'
    }

}

Function Add-USiteFile {
    param(
        [parameter(Mandatory = $false, Position = 0)]
        [array]$Server,
        [parameter(Mandatory = $false, Position = 1)]
        [psobject]$Credential
    )

    begin {
        if (!(Test-Path -Path (Join-Path -Path $Env:LOCALAPPDATA -ChildPath 'Unifi'))) {
            New-Item -Path $Env:LOCALAPPDATA -Name 'Unifi' -ItemType Directory | Out-Null
        }
        
        Write-Host 'Parsing all Sites - Please Wait'

        $Credential = Get-CredentialsAsJson

        if ((Test-Path -Path (Join-Path -Path $Env:LOCALAPPDATA -ChildPath 'Unifi\Server.xml')) -and (!($Server))) {
            $Server = Import-CliXml -Path (Join-Path -Path $Env:LOCALAPPDATA -ChildPath 'Unifi\Server.xml') -PipelineVariable 'Server'
        }
        elseif (!($Server)) {
            $Server = Read-Host -Prompt 'Enter Server' -PipelineVariable 'Server'
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

                        $Sites += @([PSCustomObject]@{

                                Server   = $URL
                                SiteID   = $Site._id
                                SiteURL  = $Site.name
                                SiteName = $Site.desc
                            })

                    }
                    Invoke-RestMethod -Uri "$URL/api/logout" -Method Post -ContentType "application/json; charset=utf-8" -SessionVariable myWebSession -SkipCertificateCheck | Out-Null
                }

            }

        }

    }

    end {
        $Sites | Export-CliXml -Path (Join-Path -Path $Env:LOCALAPPDATA -ChildPath 'Unifi\Sites.xml') -Force | Out-Null
        Remove-Variable 'Credential', 'URL', 'Sites', 'Site', 'Item', 'Server'
    }

}

Function Open-USite {
    param(
        [Parameter(Position = 0)]
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
                $Sites = Import-Clixml "$env:LOCALAPPDATA\Unifi\Sites.xml"
            }
            catch {
                Write-Warning "$env:LOCALAPPDATA\Unifi\Sites.xml not found"
                Write-Warning "Run Add-USiteFile or choice the file manually with -Sites <Path>"
                exit
            }

        }
        if ($Credential) {
            $Credential = Get-CredentialsAsJson -Credential $Credential
        }
        else {
            $Credential = Get-CredentialsAsJson
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
            $Switch += "`n`t$i { Set-Variable -Name URL -Value '$($SelectionSite[$i-1].Server)/manage/site/$($SelectionSite[$i-1].SiteURL)/dashboard';  break }"
        }
        $Switch += "`n}"
        Invoke-Expression $Switch

        if (($DefaultBrowserName -like 'ChromeHTML') -or ($Chrome)) {
            $Driver = Start-SeChrome -StartURL $URL -Maximized
            while ($Driver.Url -notmatch 'unifi.telmekom.net:8443') { }
        }
        elseif (($DefaultBrowserName -like 'FirefoxURL-308046B0AF4A39CB') -or ($Firefox)) {
            $Driver = Start-SeFirefox -StartURL $URL -Maximized
            while ($Driver.Url -notmatch 'unifi.telmekom.net:8443') { }
        }
        else {
            $Driver = Start-SeNewEdge
            Enter-SeUrl $URL -Driver $Driver
            while ($Driver.Url -notmatch 'unifi.telmekom.net:8443') { }
        }
        
        $ElementUsername = Find-SeElement -Driver $Driver -Name 'username' -Wait -Timeout 10
        $ElementPassword = Find-SeElement -Driver $Driver -Name 'password' -Wait -Timeout 10
        $ElementLogin = Find-SeElement -Driver $Driver -Id 'loginButton' -Wait -Timeout 10
        
        Send-SeKeys -Element $ElementUsername -Keys 'admin'
        Send-SeKeys -Element $ElementPassword -Keys '20Telmekom20!.'
        
        Invoke-SeClick -Element $ElementLogin
        
        Start-Sleep 5
        while ($Driver.Url -contains 'login?redirect') { }
        Enter-SeUrl $URL -Driver $Driver
    }

    end {
        Remove-Variable 'Sites', 'Credential', 'Switch', 'SelectionSite', 'i', 'DefaultBrowserName'
    }

}

Function Get-CredentialsAsJson {
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


#Open-USite


