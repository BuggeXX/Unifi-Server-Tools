# Unifi Controller PowerShell Module
- Work in progress, not all features are available yet
- Reading all kind of informations from Unifi Controllers
- Invoking different task such as updating devices over all sites
- Automated browsing to a site will require https://github.com/adamdriscoll/selenium-powershell to be installed

# Usage
Note: It will create a directory under '%localappdata%\Unifi\' and read/write configurations from there

## Adding a Credential File
```powershell
#export credentials as secure xml
Add-UCredentialFile
Add-UCredentialFile -Credential (Get-Credential)
```

## Adding a Server source file
```powershell
#export server as xml
Add-UServerFile -Server 'server01:8443', 'server02:8443', 'server03:8443'
```

## Adding a Site source file
```powershell
#export site xml, including health and device informations with parameter -Full (large file)
Add-USiteFile 
Add-USiteFile -Full
```

## Adding a Browser profile directory
```powershell
#-Refresh is not yet implemented, will be used to recreate the profile if there are problems with it

#creating a browser profile to keep site settings for each browsing
Add-UProfile -Chrome
```

### Note: each following function will read correspondenting data xml file

## Open a Unifi Site
```powershell
#avoid using -Live, it will put the servers under stress

#will provide a search for a site name and open it with the default browser (-Chrome or -Firefox will force the named browser)
#EdgeChromium or Edge will be used as default if neither Chrome or Firefox is installed
#parameter -Live will ignore the site.xml file and live parse the servers
#chrome and EdgeChromium are the most performant and will use the same profile
Open-USite
Open-USite -Chrome -Live
```

## Searching a site URL
```powershell
#simply search for the sites server
#-Live is supported
Get-USiteURL
```

## Getting different stats from the servers
```powershell
#this function needs (Add-USiteFile -Full) to be run before or us the -Live parameter
#avoid using -Live, it will put the servers under stress

#default without parameters will get a total overview from all servers
#-Distribution will create stats for each server (like how many sites and devices are on any single server)
#-Device total overview for device stats (like how many are unsupported or incompatible)
#-Live is supported
Get-UServerStats
```

# Maintainers 
- [Elmar Niederkofler](https://github.com/BuggeXX)
