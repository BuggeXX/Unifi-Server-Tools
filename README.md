# Unifi Controller PowerShell Module

- Reading all kind of informations from Unifi Controllers
- Invoking different task such as updating devices over all sites
- Automated browsing to a site will require https://github.com/adamdriscoll/selenium-powershell to be installed

# Usage
Note: it will create a directory under '%localappdata%\Unifi\' and read/write configurations from there

## Adding a Credential File
```powershell
Add-UCredentialFile
Add-UCredentialFile -Credential (Get-Credential)
```

## Adding a Server Source File
```powershell
Add-UServerFile -Server 'server01:8443', 'server02:8443', 'server03:8443'
```

## Adding a Site Source File
```powershell
Add-USiteFile -Server 'server01:8443', 'server02:8443', 'server03:8443' -Credential (Get-Credential)
Add-USiteFile -Server 'server01:8443', 'server02:8443', 'server03:8443' # will read the credential file
Add-USiteFile # will read the credential and server file
Add-USiteFile -Full # will create a Site File including Devices
```

## Open a Unifi Site
```powershell
Open-USite # will use the default browser, if non supported one is installed it will open Edge
Open-USite -Chrome # will force Chrome
```

## Add a Unifi Profile for Chrome
```powershell
Add-UProfile -Chrome # will add a Chrome(Edge Chromium) profile under %localappdata%\Unifi\ which is used to safe browser settings
```

# Maintainers 

- [Elmar Niederkofler](https://github.com/BuggeXX)
