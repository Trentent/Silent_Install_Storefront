<#
.SYNOPSIS
    Silent Install Script for StoreFront.  Tested on Storefront 1811/1903 as of 2019-04-12.
.DESCRIPTION
    This is a fully automated silent install script for Storefront on Server 2019.  This script was written to
    do a full install of Storefront or have Storefront join a server group.  This is determined by the
    -slaveServer switch.  If that switch is present then the Server will attempt to join the server group
    of the MasterServer.  If the swich is NOT present then a new Storefront server will be fully configured
    complete with Stores, Netscaler configurations, all customizations, etc.  
    
    The goal of this script is to make upgrading Storefront easier.  
    
    The thought process is we can create a whole new, clean, server and then install Storefront, 
    replacing Storefront.exe with the newest version of the exe.  Once that is complete, create new 
    servers with the slaves, have them join the master server group.  Once is all done, update the 
    VIP of the front end to point to the new servers.  In this way, any issues encountered can allow 
    for easy fallback by switching the VIP to the old servers.
.PARAMETER MasterServer
    The server name of the master server.
.PARAMETER SlaveServer
    A switch parameter that, if present, indicates this is a slave server.  If this switch is NOT present
    then it is assumed this is a master server, the first in the server group.
.PARAMETER RequestWebCertificate
    Prompts for credentials to 
.EXAMPLE
    .\Silent_Installer.ps1 -MasterServer SF01 -SlaveServer
    Sets this server as a slave and to join the servergroup owned by "SF01"

    .\Silent_Installer.ps1 -MasterServer SF01
    Sets this server as the first server

    .\Silent_Installer.ps1 -MasterServer SF01 -RequestWebCertificate
    Sets this server as the first server and requests a web server certificate (if allowed) and automatically binds it to Storefront.
.NOTES
    Author: Trentent Tye
    Date:   March 22, 2018    
#>

param(
  [parameter(Mandatory=$false)] [string]$MasterServer,
  [parameter(Mandatory=$false)] [switch]$SlaveServer,
  [parameter(Mandatory=$false)] [switch]$RequestWebCertificate
  )

if ($RequestWebCertificate) {
    $creds = Get-Credential
}
# Any failure is a terminating failure.
$ErrorActionPreference = 'Stop'
$ReportErrorShowStackTrace = $true
$ReportErrorShowInnerException = $true

push-location $PSScriptRoot
$CitrixVersion = "1903"
$PSScriptRoot = "$PSScriptRoot\$CitrixVersion"
$ScriptPath = $PSScriptRoot
Write-Host -ForegroundColor Cyan "$((Get-Date).ToLongTimeString()) : Script Path: $($scriptPath)"


# Add required Windows Features
#==============================
Write-Host -ForegroundColor Yellow "$((Get-Date).ToLongTimeString()) : Installing Windows Features"
Import-Module ServerManager
$Features = "Web-Net-Ext45","Web-AppInit","Web-ASP-Net45","Web-ISAPI-Ext","Web-ISAPI-Filter","Web-Default-Doc","Web-HTTP-Errors","Web-Static-Content","Web-HTTP-Redirect","Web-HTTP-Logging","Web-Filtering","Web-Windows-Auth","Net-Wcf-Tcp-PortSharing45","Web-Basic-Auth","Web-Scripting-Tools","NET-Framework-Core","Web-Asp-Net"

<#Index : 1
Name : Windows Server 2016 Standard

Index : 2
Name : Windows Server 2016 Standard (Desktop Experience)

Index : 3
Name : Windows Server 2016 Datacenter

Index : 4
Name : Windows Server 2016 Datacenter (Desktop Experience)
#>
#Add-WindowsFeature Web-Net-Ext45,Web-AppInit,Web-ASP-Net45,Web-ISAPI-Ext,Web-ISAPI-Filter,Web-Default-Doc,Web-HTTP-Errors,Web-Static-Content,Web-HTTP-Redirect,Web-HTTP-Logging,Web-Filtering,Web-Windows-Auth,Net-Wcf-Tcp-PortSharing45,Web-Basic-Auth,Web-Scripting-Tools,Web-Asp-Net -Source wim:\\ds1813.bottheory.local\fileshare\_ISO\Microsoft\OS\Win2K16\1607\en_windows_server_2016_x64_dvd_9718492\sources\install.wim:4 -ErrorAction Stop
foreach ($feature in $features) {
    $InstallState = (Get-WindowsFeature $feature).InstallState
    Write-Host -ForegroundColor Yellow "$((Get-Date).ToLongTimeString()) :  $Feature is $InstallState"
    if ($InstallState -ne "Installed") {
        if ($InstallState -eq "Removed") {
            Write-Host -ForegroundColor Yellow "$((Get-Date).ToLongTimeString()) : Installing Feature from network source: $Feature"
            if ($feature -eq "NET-Framework-Core") { 
                $Source = "\\ds1813.bottheory.local\FileShare\OS\Win2K19\sources\SxS"
                Write-Host -ForegroundColor Yellow "$((Get-Date).ToLongTimeString()) : Setting Source to: $Source"
                . dism /online /enable-feature /featurename:NetFX3 /source:$Source /all
            } else {
                $Source = "wim:\\ds1813.bottheory.local\FileShare\OS\Win2K19\sources\install.wim:2"
                Write-Host -ForegroundColor Yellow "$((Get-Date).ToLongTimeString()) : Setting Source to: $Source"
                Add-WindowsFeature $feature -ErrorAction Stop -Source $Source
            }
            
        } else {
        Write-Host -ForegroundColor Yellow "$((Get-Date).ToLongTimeString()) : Installing Feature from local source: $Feature"
        Add-WindowsFeature $feature -ErrorAction Stop
        }
    }
}


# Install Citrix StoreFront
#==========================
Write-Host -ForegroundColor Yellow "$((Get-Date).ToLongTimeString()) : Installing Citrix Storefront"
$Process="$ScriptPath\x64\Storefront\CitrixStoreFront-x64.exe"
$Arguments='-silent'

Unblock-File $process
Start-Process $Process -ArgumentList $arguments -wait -ErrorAction Stop

# Import Citrix Storefront Powershell SDK modules
#================================================
Write-Host -ForegroundColor Yellow "$((Get-Date).ToLongTimeString()) : Setting Up Citrix Powershell"

$env:PSModulePath = $env:PSModulePath + ";C:\Program Files\Citrix\Receiver StoreFront\PowerShellSDK\Modules"
foreach ($dir in (dir "C:\Program Files\Citrix\Receiver StoreFront\PowerShellSDK\Modules")) {
    ipmo $dir.name
}
#. "C:\Program Files\Citrix\Receiver StoreFront\Scripts\ImportModules.ps1"  ## Needed for Installing Desktop Appliance Site


 # Citrix Parameters
    #==================
    $HostBaseURL               = "https://storefront.bottheory.local" # FQDN of the required Storefront URL. In case of cluster, use cluster URL
    $Farmname                  = "BOTTHEORY" 
    $Port                      = "80" # XML port
    $TransportType             = "HTTP" # XML transport type
    $sslRelayPort              = "443"  #needs to be set even if not used
    $FarmServers               = @("ddc1.bottheory.local","ddc2.bottheory.local") # List of XML servers (FQDN)
    $LoadBalance               = $false
    $StoreVirtualPath          = "/Citrix/Store"
    #$VDIDesktopAppliancePath   = "/Citrix/DesktopAppliance"
    $FarmType                  = "XenDesktop" # XenDesktop or XenApp
    $SiteId                    = 1
    $WebServerTemplate         = "BottheoryWebServer"

    #$InternalBeacon = "https://storefront.ctxlab.com"
    [Array]$ExternalBeacons    = @("http://ping.citrix.com","https://www.google.ca")

    # Determine the Authentication and Receiver virtual path to use based of the Store
    $authenticationVirtualPath = "$($StoreVirtualPath.TrimEnd('/'))Auth"
    $receiverVirtualPath       = "$($StoreVirtualPath.TrimEnd('/'))Web"

    $GatewayName               = "External"
    $GatewayUrl                = "https://trentent.synology.me/"
    $GatewayCallbackUrl        = "https://trentent.synology.me"
    $GatewaySTAUrls            = @("http://ddc1.bottheory.local","http://ddc2.bottheory.local")
    $GatewaySubnetIP           = "192.168.1.162"


###############################################################################################################################
#region MasterServer
###############################################################################################################################

# Install Master Server
#======================
if (-not($SlaveServer)) {

    # Setup Initial Configuration
    #============================
    Write-Host -ForegroundColor Yellow "$((Get-Date).ToLongTimeString()) : Configuring First Site"

    # Determine if the deployment already exists
    $existingDeployment = Get-STFDeployment
    if(-not $existingDeployment) {
        # Install the required StoreFront components
        Add-STFDeployment -HostBaseUrl $HostbaseUrl -SiteId $SiteId -Confirm:$false
    } elseif($existingDeployment.HostbaseUrl -eq $HostbaseUrl) {
        # The deployment exists but it is configured to the desired hostbase url
        Write-Output "A deployment has already been created with the specified hostbase url on this server and will be used."
    } else {
        Write-Error "A deployment has already been created on this server with a different host base url."
    }

    # Determine if the authentication service at the specified virtual path exists
    $authentication = Get-STFAuthenticationService -VirtualPath $authenticationVirtualPath
    if(-not $authentication) {
        # Add an Authentication service using the IIS path of the Store appended with Auth
        $authentication = Add-STFAuthenticationService $authenticationVirtualPath
    } else {
        Write-Output "An Authentication service already exists at the specified virtual path and will be used."
    }

    # Determine if the store service at the specified virtual path exists
    $store = Get-STFStoreService -VirtualPath $StoreVirtualPath
    if(-not $store) {
        # Add a Store that uses the new Authentication service configured to publish resources from the supplied servers
        Write-Host -ForegroundColor Yellow "$((Get-Date).ToLongTimeString()) : Adding Store Service"
        $store = Add-STFStoreService -VirtualPath $StoreVirtualPath -AuthenticationService $authentication -FarmName $Farmtype -FarmType $Farmtype -Servers $FarmServers -LoadBalance $Loadbalance -Port $Port -SSLRelayPort $SSLRelayPort -TransportType $TransportType
    }

    # Determine if the receiver service at the specified virtual path exists
    $receiver = Get-STFWebReceiverService -VirtualPath $receiverVirtualPath
    if(-not $receiver) {
        # Add a Receiver for Web site so users can access the applications and desktops in the published in the Store
        $receiver = Add-STFWebReceiverService -VirtualPath $receiverVirtualPath -StoreService $store
    } else {
        Write-Output "A Web Receiver service already exists at the specified virtual path and will be used."
    }

    # Determine if PNA is configured for the Store service
    $storePnaSettings = Get-STFStorePna -StoreService $store
    if(-not $storePnaSettings.PnaEnabled) {
        Write-Host -ForegroundColor Yellow "$((Get-Date).ToLongTimeString()) : Enabling PNA for Store"
         # Enable XenApp services on the store and make it the default for this server
         Enable-STFStorePna -StoreService $store -AllowUserPasswordChange -DefaultPnaService
    }



    #Set-DSInitialConfiguration -hostBaseUrl $HostBaseURL -farmName $Farmname -port $Port -transportType $TransportType -servers $Servers -sslRelayPort $sslRelayPort -loadBalance $LoadBalance -farmType $FarmType -ErrorAction Stop

    # Config Internal Beacon
    #========================
    #Set-DSGlobalInternalBeacon -BeaconAddress $InternalBeacon 

    # Set Netscaler Gateway
    #======================
    Write-Host -ForegroundColor Yellow "$((Get-Date).ToLongTimeString()) : Configuring Netscaler Gateway"
    #Add-DSGlobalV10Gateway -Address https://external-url/ -Id 1 -Logon Domain -Name MyApp-Test -CallbackUrl https://callback-url -IsDefault $True -RequestTicketTwoSTA $False -SecureTicketAuthorityUrls http://192.168.3.1 -AreStaServersLoadBalanced $false -SessionReliability $true -IPAddress 192.168.1.162

    # Enable Remote Access to the store
    #==================================
    Write-Host -ForegroundColor Yellow "$((Get-Date).ToLongTimeString()) : Enabling Remote Access"

    # Get the Citrix Receiver for Web CitrixAGBasic and ExplicitForms authentication method from the supported protocols
    # Included for demonstration purposes as the protocol name can be used directly if known
    $receiverForWeb = Get-STFWebReceiverService -StoreService $store
    $receiverMethods = Get-STFWebReceiverAuthenticationMethodsAvailable | Where-Object { $_ -match "Explicit" -or $_ -match "CitrixAG" }
    # Enable CitrixAGBasic in the Authentication service (required for remote access)
    Set-STFWebReceiverAuthenticationMethods -WebReceiverService $receiverForWeb -AuthenticationMethods $receiverMethods

    # Get the CitrixAGBasic authentication method from the protocols installed.
    # Included for demonstration purposes as the protocol name can be used directly if known
    $citrixAGBasic = Get-STFAuthenticationProtocolsAvailable | Where-Object { $_ -match "CitrixAGBasic" }
    # Enable CitrixAGBasic in the Authentication service (required for remote access)
    $authenticationService = Get-STFAuthenticationService
    Enable-STFAuthenticationServiceProtocol -AuthenticationService $authenticationService -Name $citrixAGBasic


    #Set-DSStoreRemoteAccess -RemoteAccessType FullVPN -SiteId 1 -VirtualPath /Citrix/Store

    # Set Netscaler Gateway to the store
    #===================================
    Write-Host -ForegroundColor Yellow "$((Get-Date).ToLongTimeString()) : Applying Netscaler Gateway to the store"
    # Add a new Gateway used to access the new store remotely
    if (-not(Get-STFRoamingGateway -Name $GatewayName)) {
        Add-STFRoamingGateway -Name $GatewayName -LogonType Domain -Version Version10_0_69_4 -GatewayUrl $GatewayUrl -CallbackUrl $GatewayCallbackUrl -SecureTicketAuthorityUrls $GatewaySTAUrls
        # Get the new Gateway from the configuration (Add-STFRoamingGateway will return the new Gateway if -PassThru is supplied as a parameter)
        $gateway = Get-STFRoamingGateway -Name $GatewayName
        # If the gateway subnet was provided then set it on the gateway object
        if($GatewaySubnetIP) {
            Set-STFRoamingGateway -Gateway $gateway -SubnetIPAddress $GatewaySubnetIP -SessionReliability $true
        }
    }

    # Register the Gateway with the new Store
    Register-STFStoreGateway -Gateway $gateway -StoreService $store -DefaultGateway

    # Config External Beacon
    #=======================
    #Needed?  Or is it added automatically?  --> done automatically
    #write-host "Getting External Beacons"
    #Get-DSGlobalExternalBeacon
    #Add-DSGlobalExternalBeacon -BeaconAddress $ExternalBeacons[0] -BeaconId 1
    #Add-DSGlobalExternalBeacon -BeaconAddress $ExternalBeacons[1] -BeaconId 2

    # Add authentication methods Domain and Netscaler
    #================================================
    Write-Host -ForegroundColor Yellow "$((Get-Date).ToLongTimeString()) : Adding Authentication Methods"
    $authenticationService = Get-STFAuthenticationService
    Add-STFAuthenticationServiceProtocol -Name CitrixAGBasic -AuthenticationService $authenticationService
    Add-STFAuthenticationServiceProtocol -Name IntegratedWindows -AuthenticationService $authenticationService
    #Add-STFAuthenticationServiceProtocol -Name HTTPBasic -AuthenticationService $authenticationService
    #Enable-STFAuthenticationServiceProtocol -AuthenticationService $authenticationService -Name HTTPBasic

    # Configure Explicit authentication
    #==================================
    Write-Host -ForegroundColor Yellow "$((Get-Date).ToLongTimeString()) : Configuring Explicit Authentication Method"
    Set-STFExplicitCommonOptions -authenticationService $authenticationService -Domains @("BOTTHEORY","BOTTHEORY.LOCAL") -DefaultDomain "BOTTHEORY" -HideDomainField $true -AllowUserPasswordChange Always -ShowPasswordExpiryWarning Never  -PasswordExpiryWarningPeriod 10

    # Enable Receiver for Web authentication Methods
    #===============================================
    Write-Host -ForegroundColor Yellow "$((Get-Date).ToLongTimeString()) : Enable the Authentication Methods for Receiver for Web"
    $webReceiver = Get-STFWebReceiverService
    Set-STFWebReceiverAuthenticationMethods -WebReceiverService $webReceiver -AuthenticationMethods @("ExplicitForms","CitrixAGBasic","IntegratedWindows")

    # Configure default Workspace Control values
    #===========================================
    Write-Host -ForegroundColor Yellow "$((Get-Date).ToLongTimeString()) : Configure default Workspace Control options"
    Set-STFWebReceiverUserInterface -WebReceiverService $webReceiver -AutoLaunchDesktop $true -WorkspaceControlEnabled $true -WorkspaceControlAutoReconnectAtLogon $true -WorkspaceControlShowReconnectButton $true -WorkspaceControlShowDisconnectButton $true -WorkspaceControlLogoffAction Disconnect -AppShortcutsAllowSessionReconnect $true

    # Configure Session Timeout for Reciever for Web to 10 Hours
    #===========================================================
    Write-Host -ForegroundColor Yellow "$((Get-Date).ToLongTimeString()) : Setting Session Timeout to 10 hours"
    Set-STFWebReceiverService -WebReceiverService $webReceiver -SessionStateTimeout 600

    # Enable loopback communication (required for Netscaler and accessing URL directly)
    #===========================================================
    Set-STFWebReceiverCommunication -WebReceiverService $webReceiver -Loopback OnUsingHttp

    # Enable HTML5 Receiver is no Receiver detected
    #==============================================
    Write-Host -ForegroundColor Yellow "$((Get-Date).ToLongTimeString()) : Enabling HTML5 Receiver"
    Set-STFWebReceiverPluginAssistant -WebReceiverService $webReceiver -HTML5Enabled Fallback 

    # Install Desktop Appliance Site
    #==============================================
    #Write-Host -ForegroundColor Yellow "$((Get-Date).ToLongTimeString()) : Install Desktop Appliance Site"
    #Add-STFDesktopApplianceService -VirtualPath $VDIDesktopAppliancePath -SiteId $SiteId -StoreService $vdiStore -FriendlyName "VDI" -EnableExplicit
    #Install-DSDesktopAppliance -FriendlyName "VDI" -SiteId $SiteId -VirtualPath $VDIDesktopAppliancePath -UseHttps $False -StoreUrl "$hostBaseURL$($VDIStoreVirtualPath)" -EnableMultiDesktop $False -EnableExplicit $True

    # Set Additional Farms to Storefront
    #=====================================================
    $service = Get-STFStoreService -VirtualPath $StoreVirtualPath
    <#
    Write-Host -ForegroundColor Yellow "$((Get-Date).ToLongTimeString()) : Adding additional farms"
    
    $Servers = "192.168.3.1","192.168.3.2"  # VPIS for XA65 ZDCs
    Write-Host -ForegroundColor Yellow "$((Get-Date).ToLongTimeString()) : XA65"
    add-stfstorefarm -farmname "XA65" -FarmType XenApp -port 28001 -transporttype http -loadbalance $false -servers $servers -storeservice $service

    Write-Host -ForegroundColor Yellow "$((Get-Date).ToLongTimeString()) : XA5"
    $Servers = "XA5.bottheory.local"
    add-stfstorefarm -farmname "XA5" -FarmType XenApp -port 28001 -transporttype http -loadbalance $false -servers $servers -storeservice $service

    <#
    Write-Host -ForegroundColor Yellow "$((Get-Date).ToLongTimeString()) : XA45"
    $Servers = "10.10.10.10"
    add-stfstorefarm -farmname "XA45" -FarmType XenApp -port 80 -transporttype http -loadbalance $false -servers $servers -storeservice $service
    #>
    #>

    # Filter Netcare applications from being seen by named users
    #=====================================================
    Set-STFStoreEnumerationOptions -StoreService $service -FilterByKeywordsExclude @("Hidden")
    #Set-DSResourceFilterKeyword -SiteId 1 -VirtualPath "/Citrix/Store" -ExcludeKeywords @("Hidden")


    # Setup PowerShell Remoting permissions for the first Storefront server in the group -- SID is a group containing the machine account
    #===================================================================================
    Enable-PSRemoting -Force

    Set-PSSessionConfiguration Microsoft.Powershell   -SecurityDescriptorSDDL "O:NSG:BAD:P(A;;GA;;;BA)(A;;GX;;;S-1-5-21-4258912900-4021826306-2389244138-22612)S:P(AU;FA;GA;;;WD)(AU;SA;GXGW;;;WD)" #this SID, "S-1-5-21-4258912900-4021826306-2389244138-22612" is a AD group containing all the storefront servers
    Set-PSSessionConfiguration Microsoft.Powershell32 -SecurityDescriptorSDDL "O:NSG:BAD:P(A;;GA;;;BA)(A;;GX;;;S-1-5-21-4258912900-4021826306-2389244138-22612)S:P(AU;FA;GA;;;WD)(AU;SA;GXGW;;;WD)" #this SID, "S-1-5-21-4258912900-4021826306-2389244138-22612" is a AD group containing all the storefront servers

}
###############################################################################################################################
#endregion MasterServer
###############################################################################################################################

###############################################################################################################################
#region SlaveServer
###############################################################################################################################

# Setup ServerGroup 
#=====================================================
if ($SlaveServer) {
    #start master server with authorization passcode
    #We need to use Desired State Configuration (DSC) because it runs with an elevated token on the remote system
    #creating and using a scheduled task on the remote system would accomplish the same thing but we can capture the output using DSC
    $b =  Invoke-Command -ComputerName "$masterServer.bottheory.local" -ScriptBlock {
    configuration DeployBat
    {
        # DSC throws weird errors when run in strict mode. Make sure it is turned off.
        Set-StrictMode -Off

        # We have to specify what computers/nodes to run on.
        Node localhost 
        {
            Script 'Deploy.bat'
            {
                # Code you want to run goes in this script block
                SetScript = { 
                    <#
                    $env:PSModulePath = $env:PSModulePath + ";C:\Program Files\Citrix\Receiver StoreFront\PowerShellSDK\Modules"
                    foreach ($dir in (dir "C:\Program Files\Citrix\Receiver StoreFront\PowerShellSDK\Modules")) {
                        ipmo $dir.name | out-null
            
                    }
                    #>
                    Write-Verbose "Stopping any exisiting STFServerGroupJoin"
                    Stop-STFServerGroupJoin -Confirm:$false
                    Write-Verbose "Starting STFServerGroupJoin"
                    $result = Start-STFServerGroupJoin -IsAuthorizingServer -Confirm:$false -Verbose
                    Write-Verbose "__Passcode;$($result.Passcode)"
                    Write-Verbose "__Status;$($result.Status)"
                    Write-Verbose "__StatusMessage;$($result.StatusMessage)"
                    # DSC doesn't show STDOUT, so pipe it to the verbose stream
                }

                # Return $false otherwise SetScript block won't run.
                TestScript = { return $false }

                # This must returns a hashtable with a 'Result' key/value.
                GetScript = { return @{ 'Result' = 'RUN' } }
            }
        }
    }

    # Create the configuration .mof files to run, which are output to
    # 'DeployBot\NODE_NAME.mof' directory/files in the current directory. The default 
    # directory when remoting is C:\Users\USERNAME\Documents.
    DeployBat

    # Run the configuration we just created. They are run against each NODE. Using the 
    # -Verbose switch because DSC doesn't show STDOUT so our resources pipes it to the 
    # verbose stream.
    Start-DscConfiguration -Wait -Path .\DeployBat -Force -Verbose 4>&1
    }

    $passcode = ($b | select-String "__Passcode;").ToString().split(";")[1]
    $status = ($b | select-String "__Status;").ToString().split(";")[1]
    $statusMessage = ($b | select-String "__StatusMessage;").ToString().split(";")[1]

    Write-Host "Results of initiating Server Group Join:"
    Write-Host "$passcode"
    Write-Host "$status"
    Write-Host "$statusMessage"

    Start-STFServerGroupJoin -AuthorizerHostName "$masterServer.bottheory.local" -Passcode $passcode -Confirm:$false -ErrorAction Stop

    # Wait until we've completed joining the server group
    #====================================================
    Do {
        sleep 2
        $updatedMessage = Get-STFServerGroupJoinState
        if ($updatedMessage.statusMessage -ne $currentMessage) {
            $currentMessage = $updatedMessage.statusMessage
            Write-Host -ForegroundColor Cyan "$((Get-Date).ToLongTimeString()) : $currentMessage"
        }
    } until ($updatedMessage.Status -eq "Success")

    Write-Host -ForegroundColor Yellow "$((Get-Date).ToLongTimeString()) : Syncing changes from $MasterServer"
    Invoke-Command -ComputerName $MasterServer -ScriptBlock { Publish-STFServerGroupConfiguration -Confirm:$false }

    $webReceiver = Get-STFWebReceiverService -ErrorAction Stop
}
###############################################################################################################################
#endregion SlaveServer
###############################################################################################################################



# Disable check publisher's certificate revocation (to speed up console start-up)
#================================================================================
Write-Host -ForegroundColor Yellow "$((Get-Date).ToLongTimeString()) : Disable check publisher certificate revocation"
set-ItemProperty -path "REGISTRY::\HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing\" -name State -value 146944

# Disable Citrix CEIP
#====================
Write-Host -ForegroundColor Yellow "$((Get-Date).ToLongTimeString()) : Disable Citrix CEIP"
New-ItemProperty -path "REGISTRY::\HKEY_LOCAL_MACHINE\Software\Citrix\Telemetry\CEIP" -name Enabled -value 0 -PropertyType DWORD -Force | Out-Null

# Enable SF-ServerName customization
#===================================
if (-not((Get-WebConfigurationProperty -PSPath MACHINE/WEBROOT/APPHOST -Name . -Filter system.webServer/httpProtocol/customHeaders).Collection.name).Contains("SF-ServerName")) {
    Write-Host -ForegroundColor Yellow "$((Get-Date).ToLongTimeString()) : Enable SF-ServerName customization"
    Add-WebConfigurationProperty -PSPath MACHINE/WEBROOT/APPHOST -Name . -Filter system.webServer/httpProtocol/customHeaders -AtElement @{name = "SF-ServerName" ; value=$env:COMPUTERNAME.ToUpper()}

$FooterCSS = '

.customAuthFooter
{
 font-size:12px;
 color:Black;
 bottom:10px;
 text-align: center;
}

#customBottom
{
 text-align:center;
 font-size:12px;
 color:Black;
 padding:10px;
 position:static;
}'

$FooterJavaScript = @"

var req = new XMLHttpRequest();
req.open('GET', document.location, false);
req.send(null);

var servername = req.getResponseHeader('SF-ServerName');

`$('.customAuthFooter').html(servername);
`$('#customBottom').html(servername);
"@

    $FooterCSS        | Out-file -FilePath "C:\inetpub\wwwroot\Citrix\StoreWeb\custom\style.css" -Append -Encoding ascii
    $FooterJavaScript | Out-File -FilePath "C:\inetpub\wwwroot\Citrix\StoreWeb\custom\script.js" -Append -Encoding ascii
}

# Set Default Web Page Redirect
#==============================
Write-Host -ForegroundColor Yellow "$((Get-Date).ToLongTimeString()) : Set Default Web Page Redirect to StoreWeb"
#.\appcmd set config /section:httpRedirect /enabled:true /destination:"$HostBaseURL$receiverVirtualPath" /childOnly:true /exactDestination:false /httpResponseStatus:Permanent
#.\appcmd set site "Default Web Site" /section:httpRedirect /enabled:true /destination:"$HostBaseURL$receiverVirtualPath" /childOnly:true /exactDestination:false /httpResponseStatus:Permanent
. $env:SystemRoot\System32\inetsrv\appcmd.exe set config "Default Web Site" /section:httpRedirect /enabled:true /destination:"$HostBaseURL$receiverVirtualPath" /childOnly:true /exactDestination:false /httpResponseStatus:Permanent

if ($RequestWebCertificate) {
    #requests and installs the certificate
    $cert = Get-Certificate -URL "ldap:///CN=2019CA" -Template $WebServerTemplate -CertStoreLocation Cert:\LocalMachine\My -DnsName $HostBaseURL.Replace("https://","").Replace("http://",""),"$($env:computername).$($env:USERDNSDOMAIN)"
    Write-Host "Certificate was: " -NoNewline
    $cert.Status


    Write-Host "Binding Certificate to 443" -NoNewline
    New-WebBinding -Name "Default Web Site" -IP "*" -Port 443 -Protocol https
    $Binding = Get-WebBinding -Name "Default Web Site"
    $binding.AddSslCertificate($cert.Certificate.Thumbprint, "my")
}
