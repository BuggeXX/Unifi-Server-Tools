# Unifi Controller PowerShell Module
- Work in progress, not all features are available yet
- Reading all kind of informations from Unifi Controllers
- Invoking different task such as updating devices over all sites
- Some functions will require https://github.com/adamdriscoll/selenium-powershell to be installed

# Usage
Note: It will create a directory under '%localappdata%\Unifi\' and read/write configurations from there

## Adding a Server source file
```powershell
#CAUTION: it is necessary to have a valid ssl certificate for all servers
#I will work on either a function to generate a certificate or to be able to ignore any ssl warning

#create server.xml file
#will tests connectivity to the server on <port> and try to login
#for each server it will ask for it credential, which are stored as secure strings in the xml
#inform Url and Port will be automatically detected
#each server will be added with the attribute <Exclude = $False>
#each server will be added with the attribute <Migrate = $False>
#each server will be added with the attribute <MigrateAble = $False>
Add-UServerFile -Server 'https://server01:8443', 'https://server02:8443', 'https://server03:8443'
```

## Change the Server source file
```powershell
#will change the attribute <Exclude = $true>
#servers with the attribute <Exclude = $true> will be exluded for a few functions
Set-UServerFile -Exlude 'https://server03:8443'
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

## Searching a MAC 
```powershell
#simple function to search a mac address from a device on all servers, helpfull if you forgot under which site the inform was done
#-Live is supported
Get-UInformSite
```

## Exporting a Site/Host Excel file
```powershell
#simple export a excel file under '%localappdata%\Unifi\'
#-Live is supported
Export-USiteXLSX
```

## Automatic Upgrade Devices over all Servers
```powershell
#will upgrade any device on all servers, if a device wont come to state 1 (Connected) after 7min it will stop proccess more devices
#there is not yet a proper handler for Mesh Devices, it can happen that Mesh Devices arnt updated as the downlink ap needs to be updated first
Invoke-UAutoUpgrade -Live
```

## Automatic Migrate Sites to other Servers
```powershell
#CAUTION: the function will set a few site settings on the new host, will enable advanced functions, and disable automatic upgrade and email alerts | switch parameters needs to be added
#the function offten crash cause it cant find elements with Get-SeElement

#will create a object with all necessary informations which site can be migrated
#the functions checks 2 properties in the server.xml, 
#migrate means all sites on this server will be migrated to others
#migrateable means this server is a destination host, if more servers with this propertie are enabled, it will rotate using allways the server with the less adopted devices
#there is a debug parameter -Show, it will launch the browsers without headless
#parameter -exclude will exclude the array of sites from migrating (needs to match the site name)
Invoke-UAutoMigrate
```

## Getting different stats from the servers
```powershell
#this function needs (Add-USiteFile -Full) to be run before or us the -Live parameter
#avoid using -Live, it will put the servers under stress
#servers with parameter <Exluded = $true> will be ignored

#default without parameters will get a total overview from all servers
#-Distribution will create stats for each server (like how many sites and devices are on any single server)
#-Device total overview for device stats (like how many are unsupported or incompatible)
#-Live is supported
Get-UServerStats
```

# Maintainers 
- [Elmar Niederkofler](https://github.com/BuggeXX)
