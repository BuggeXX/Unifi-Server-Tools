Remove-Variable * -ErrorAction SilentlyContinue

Function Get-ControllerStats {

    $Credential = "`{`"username`":`"administrator`",`"password`":`"nET#tel!12.`"`}"
    $BaseURI = "https://10.81.16.49:8443"
    $Login = Invoke-RestMethod -Uri "$BaseURI/api/login" -Method Post -Body $Credential -ContentType "application/json; charset=utf-8" -SessionVariable myWebSession -SkipCertificateCheck

    foreach ($Site in (Invoke-RestMethod -Uri "$BaseURI/api/stat/sites" -WebSession $myWebSession -SkipCertificateCheck).data) {

        $Sites += @([PSCustomObject]@{
        
                Server   = $BaseURI
                SiteID   = $Site._id
                SiteURL  = $Site.name
                SiteName = $Site.desc
                Health   = $Site.health
            })

    }


    $Stats += [PSCustomObject]@{

        SitesCount               = $Sites.Count
        DevicesOnlineCount       = ($Sites.health.num_ap | Measure-Object -sum).sum
        DevicesAdoptedCount      = ($Sites.health.num_adopted | Measure-Object -sum).sum
        DevicesDisconnectedCount = ($Sites.health.num_disconnected | Measure-Object -sum).sum
        ClientsCount             = ($Sites.health.num_user | Measure-Object -sum).sum

    }

    $Stats
}

Function Get-SiteInfo {

    $Credential = "`{`"username`":`"administrator`",`"password`":`"nET#tel!12.`"`}"
    $BaseURI = "https://10.81.16.49:8443"
    $Login = Invoke-RestMethod -Uri "$BaseURI/api/login" -Method Post -Body $Credential -ContentType "application/json; charset=utf-8" -SessionVariable myWebSession -SkipCertificateCheck

    foreach ($Site in (Invoke-RestMethod -Uri "$BaseURI/api/stat/sites" -WebSession $myWebSession -SkipCertificateCheck).data) {

        $Sites += @([PSCustomObject]@{
        
                Server   = $BaseURI
                SiteID   = $Site._id
                SiteURL  = $Site.name
                SiteName = $Site.desc
                Health   = $Site.health
            })

    }

    $SelectionSite = $Sites | Where-Object -Property SiteName -Match '6119 - Saltus GmbH Tschögglbergerhof'
    $Login = Invoke-RestMethod -Uri "$($SelectionSite.Server)/api/login" -Method Post -Body $Credential -ContentType "application/json; charset=utf-8" -SessionVariable myWebSession -SkipCertificateCheck
    $SiteInfo = Invoke-RestMethod -Uri "$($SelectionSite.Server)/api/s/$($SelectionSite.SiteURL)/stat/device" -WebSession $myWebSession -SkipCertificateCheck
    
    $SelectionDevice = $SiteInfo.Data | Where-Object -Property name -Match 'SW05 - Rack D Altbau'
    
    $SelectionDevice

}

Function Get-SiteUpgrade {

    $ServerList = '1.unifi.telmekom.net:8443', '2.unifi.telmekom.net:8443', '3.unifi.telmekom.net:8443', '4.unifi.telmekom.net:8443', '5.unifi.telmekom.net:8443'

    foreach ($Server in $ServerList) {

        $BaseURI = "https://$Server"
        $Credential = "`{`"username`":`"UnifiTelmekom`",`"password`":`"ys=a*eGv@cvA]P@upvn&DbTd`"`}"

        $Login = Invoke-RestMethod -Uri "$BaseURI/api/login" -Method Post -Body $Credential -ContentType "application/json; charset=utf-8" -SessionVariable myWebSession -SkipCertificateCheck

        foreach ($Site in (Invoke-RestMethod -Uri "$BaseURI/api/stat/sites" -WebSession $myWebSession -SkipCertificateCheck).data) {

            $Sites += @([PSCustomObject]@{
            
                    Server   = $BaseURI
                    SiteID   = $Site._id
                    SiteURL  = $Site.name
                    SiteName = $Site.desc
                    Health   = $Site.health
                    Devices  = Invoke-RestMethod -Uri "$BaseURI/api/s/$($Site.name)/stat/device" -WebSession $myWebSession -SkipCertificateCheck
                })

        }

        $Logout = Invoke-RestMethod -Uri "$BaseURI/api/logout" -Method Post -Body $Credential -ContentType "application/json; charset=utf-8" -SessionVariable myWebSession -SkipCertificateCheck
        
    }




    foreach ($Site in $Sites) {

        if ($Site.SiteName -like '6546 - Villa Verde') {

            foreach ($Device in $Site.Devices.data) {

                if (($Device.type -notlike 'usw') -and ($Device.upgradable -like 'true')) {

                    $Json = @{
                        cmd = 'upgrade'
                        mac = "$($Device.mac)"
                    } | ConvertTo-Json

                    $Login = Invoke-RestMethod -Uri "$($Site.Server)/api/login" -Method Post -Body $Credential -ContentType "application/json; charset=utf-8" -SessionVariable myWebSession -SkipCertificateCheck
                    Invoke-RestMethod -Uri "$($Site.Server)/api/s/$($Site.SiteURL)/cmd/devmgr" -WebSession $myWebSession -SkipCertificateCheck -Body $Json -Method Post

                    while ((((Invoke-RestMethod -Uri "$($Site.Server)/api/s/$($Site.SiteURL)/stat/device" -WebSession $myWebSession -SkipCertificateCheck).upgradable) -like 'true') -and (((Invoke-RestMethod -Uri "$($Site.Server)/api/s/$($Site.SiteURL)/stat/device" -WebSession $myWebSession -SkipCertificateCheck).mac) -like $Device.mac)) {

                        Start-Sleep 30

                    }

                }

            }

        }

    }




    $Json = @{
        cmd = 'upgrade'
        mac = 'fc:ec:da:34:b7:21'
    } | ConvertTo-Json


    Invoke-RestMethod -Uri "$($Selection.Server)/api/s/$($Selection.SiteURL)/cmd/devmgr" -WebSession $myWebSession -SkipCertificateCheck -Body $json -Method Post







    $Login = Invoke-RestMethod -Uri "$($Selection.Server)/api/login" -Method Post -Body $Credential -ContentType "application/json; charset=utf-8" -SessionVariable myWebSession -SkipCertificateCheck

    $SiteInfo = Invoke-RestMethod -Uri "$($Selection.Server)/api/s/$($Selection.SiteURL)/rest/setting" -WebSession $myWebSession -SkipCertificateCheck
    $SiteInfo1 = Invoke-RestMethod -Uri "$($Selection.Server)/api/s/$($Selection.SiteURL)/stat/device" -WebSession $myWebSession -SkipCertificateCheck

    Invoke-RestMethod -Uri "$($Selection.Server)/api/s/$($Selection.SiteURL)/cmd/devmgr/upgrade{mac: fc:ec:da:34:b7:21, upgrade_to_firmware: 4.0.69.10871, cmd: upgrade}" -WebSession $myWebSession -SkipCertificateCheck
    #$SiteInfo2 = Invoke-RestMethod -Uri "$($Selection.Server)/api/s/$($Selection.SiteURL)/rest/setting" -WebSession $myWebSession -SkipCertificateCheck

    $SiteInfo
}

Function Get-SiteUpgradeAviable {

    $ServerList = '0.unifi.telmekom.net:8443', '1.unifi.telmekom.net:8443', '2.unifi.telmekom.net:8443', '3.unifi.telmekom.net:8443', '4.unifi.telmekom.net:8443', '5.unifi.telmekom.net:8443'

    foreach ($Server in $ServerList) {

        $BaseURI = "https://$Server"
        $Credential = "`{`"username`":`"UnifiTelmekom`",`"password`":`"ys=a*eGv@cvA]P@upvn&DbTd`"`}"

        $Login = Invoke-RestMethod -Uri "$BaseURI/api/login" -Method Post -Body $Credential -ContentType "application/json; charset=utf-8" -SessionVariable myWebSession -SkipCertificateCheck

        foreach ($Site in (Invoke-RestMethod -Uri "$BaseURI/api/stat/sites" -WebSession $myWebSession -SkipCertificateCheck).data) {

            $Sites += @([PSCustomObject]@{
            
                    Server   = $BaseURI
                    SiteID   = $Site._id
                    SiteURL  = $Site.name
                    SiteName = $Site.desc
                    Health   = $Site.health
                    Devices  = Invoke-RestMethod -Uri "$BaseURI/api/s/$($Site.name)/stat/device" -WebSession $myWebSession -SkipCertificateCheck
                })

        }

        $Logout = Invoke-RestMethod -Uri "$BaseURI/api/logout" -Method Post -Body $Credential -ContentType "application/json; charset=utf-8" -SessionVariable myWebSession -SkipCertificateCheck
        
    }

    (($Sites | Where-Object -Property Devices. -in ($Sites.Devices.data | Where-Object -Property upgradable -eq $true).site_id).Server) | Sort-Object -Unique

    $Upgradeable = [PSCustomObject]@{

        SiteName = ($Sites | Where-Object -Property SiteID -in ($Sites.Devices.data | Where-Object -Property upgradable -eq $true).site_id).SiteName | Sort-Object -Unique
        SiteServer = ($Sites | Where-Object -Property SiteID -in ($Sites.Devices.data | Where-Object -Property upgradable -eq $true).site_id).Server | Sort-Object -Unique
    }

    $Upgradeable

}

Function Get-OldVersion {

    $Sites = Import-Clixml C:\Users\elmar.niederkofler\Desktop\s.xml

    $Sites | Where-Object -Property SiteID -in (($Sites.Devices.data | Where-Object -Property version -like '3*').site_id | Sort-Object -Unique)
}

Get-OldVersion
#Get-SiteUpgradeAviable  

