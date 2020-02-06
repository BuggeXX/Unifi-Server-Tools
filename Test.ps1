
    $DiscoveryPort = 10001
    $DiscoveryPacket = 01, 00, 00, 00
    $encodebytes = New-Object System.Text.ASCIIEncoding

    # Device Discovery
    
    # Create socket and endpoints for broadcast receive and transmit
        
    $localmachineAddr = [System.Net.Dns]::Resolve([System.Net.DNS]::GetHostName()).AddressList[2]
    $localmachineendpoint = new-object System.Net.IPEndPoint($localmachineaddr, 0)
    $mchpdiscoveryconnection = New-Object System.Net.Sockets.UDPClient($localmachineendpoint)
    $mchpdiscoveryremoteaddress = New-Object System.Net.IPEndpoint([System.Net.IPAddress]::Any, 0)
    $mchpdiscoverybroadcastaddress = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Broadcast, $DiscoveryPort)


    <#$mchpdiscoveryconnection = New-Object System.Net.Sockets.UDPClient($DiscoveryPort)
    $mchpdiscoveryremoteaddress = New-Object System.Net.IPEndpoint([System.Net.IPAddress]::Any, 0)
    $mchpdiscoverybroadcastaddress = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Broadcast, $DiscoveryPort)#>


    # Set receive and send timeout and enable broadcast
        
    #$mchpdiscoveryconnection.Client.ReceiveTimeout = 10000  # 30 seconds
    #$mchpdiscoveryconnection.Client.SendTimeout = 10000   # 10 seconds
    #$mchpdiscoveryconnection.Client.EnableBroadcast = $true
    
    # Send discovery packet
        
        
        
    # Wait for response - 30 seconds (receivetimer / 2) 
    try {
        $receivetimeout = 30
        $receivedelay = 0.5
        $receivecount = [int]$receivetimeout / $receivedelay
        $receivedataflag = $false
        while ($true) {

            $mchpsendstatus = $mchpdiscoveryconnection.Send($DiscoveryPacket, $DiscoveryPacket.Length, $mchpdiscoverybroadcastaddress)

            if ($mchpdiscoveryconnection.Available -gt 0) {

                $discoveryresultsreceivebuffer = $mchpdiscoveryconnection.Receive([ref]$mchpdiscoveryremoteaddress)      
                $mchpaddress = $mchpdiscoveryremoteaddress.Address.IPAddressToString
                $discoveryresults = $encodebytes.GetString($discoveryresultsreceivebuffer) -split "`n"
                $mchpaddress
            }
            else {
                $receivecount--
                Start-Sleep $receivedelay
            }
        }
    }
    catch {
        Write-Error "Socket connection error: $_"
    }
            
    if ($receivedataflag) {
        
        $discoveryresultsreceivebuffer = $mchpdiscoveryconnection.Receive([ref]$mchpdiscoveryremoteaddress)
            
        $mchpaddress = $mchpdiscoveryremoteaddress.Address.IPAddressToString
        $discoveryresults = $encodebytes.GetString($discoveryresultsreceivebuffer) -split "`n"
            
        if ($discoveryresults -ne $null) {
            $mchpnode = New-Object PSObject -Property @{
                IPAddress   = $mchpaddress 
                HostName    = $discoveryresults[0] 
                MACaddr     = $discoveryresults[1] 
                ResetReason = $discoveryresults[2] 
            } 
            write-output $mchpnode
        }
    }	
    $mchpdiscoveryconnection.Close() | Out-Null
    return
