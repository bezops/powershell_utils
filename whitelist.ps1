<#
.SYNOPSIS
Interfaces with Cisco ISE 3.2 API Service based on OpenAPI

.DESCRIPTION
Script to update a statically defined Endpoint Identity Group in Cisco ISE to allow a PXE Endpoint bypass the guest portal.

Based on original concept by Adam Gross:
https://www.asquaredozen.com/2018/09/29/configuring-802-1x-authentication-for-windows-deployment-part-5-dynamic-whitelisting-using-the-cisco-ise-external-restful-service/
https://github.com/AdamGrossTX/CiscoISE

Legacy script is written for ISE2.2 with deprecated API calls, rewritten to support ISE3.0+.

Resources:
https://developer.cisco.com/docs/identity-services-engine/latest/using-change-of-authorization-rest-apis/
https://developer.cisco.com/docs/identity-services-engine/latest/get-endpoint-by-id-or-mac/

#>

# Define parameters
param (
    [Parameter(Mandatory=$true)]
    [string]$Username,

    [Parameter(Mandatory=$true)]
    [string]$Password,

    [Parameter(Mandatory=$true)]
    [string]$ServerName
)

# Configuration Section
$version = '2.2.2'
$EndpointGroupId = '5e3ea0d0-7db7-11e8-8958-005056b76b94'
$Url = "https://$($ServerName):443/api/v1/endpoint/"
$Base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $Username, $Password)))

$timestamp = Get-Date -Format "yyyyMMddHHmmss"
$Script:LogFileName = "$PSScriptRoot\whitelist_$timestamp.txt"
$DelayTime = 10

# Set TLS version - Uncomment if required.
#[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#Disable SSL Verification - Uncomment if required.
#[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

# Load the System.Web assembly to convert MAC address to UrlEncode
Add-Type -AssemblyName System.Web

# API Base Headers
$Script:headers = @{
    "accept" = "application/json"
    "Authorization" = "Basic $base64AuthInfo"
}

# Banner
$Banner = @"
__      ___    _ _       _ _    _   
\ \    / / |_ (_) |_ ___| (_)__| |_ 
 \ \/\/ /| ' \| |  _/ -_) | (_-<  _|
  \_/\_/ |_||_|_|\__\___|_|_/__/\__| Ver: $version

"@

# Function to log to file
function Log-Info {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Info,

        [Parameter(Mandatory=$true)]
        [string]$LogFileName
    )
    $Info | Out-File -FilePath $LogFileName -Append
}

# Function to format MAC Address
Function Format-MacAddress {
    param (
        $UnformattedMac
    )
    $MacAddress = $UnformattedMac -replace "[^0-9a-fA-F]", "" # Remove all non-hexadecimal characters
    $FormattedMac = $MacAddress -replace "(..)(?!$)", '$1:' # Insert ':' after every two characters
    return $FormattedMac
}

Function Get-ActiveIPv4Adapter {
    param (
        [int]$maxRetries = 3
    )
    try {
        for ($retry = 1; $retry -le $maxRetries; $retry++) {
            $activeIPv4Adapter = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object {
                $_.IPEnabled -eq $true -and
                $_.DHCPEnabled -eq $true
            } | Select-Object Description, IPAddress,
            @{name = 'IPv4DefaultGateway'; expr = {($_.DefaultIPGateway) -join ', '}},
            @{name = 'DNSServer'; expr = {($_.DNSServerSearchOrder) -join ', '}},
            @{name = 'MacAddress'; expr = {$_.MACAddress}}

            # Check if IPAddress or DNSServer is null or empty
            if (-not $activeIPv4Adapter.IPAddress -or -not $activeIPv4Adapter.DNSServer) {
                Write-Host "Retrying (Attempt $retry of $maxRetries)..."
                Start-Sleep -Seconds $DelayTime
            }
            else {
                # All values are present, exit the loop
                break
            }
        }
        # If still not successful after retries, throw an exception
        if (-not $activeIPv4Adapter.IPAddress -or -not $activeIPv4Adapter.DNSServer) {
            throw "Unable to get IP Address or DNS Server from Active adapter."
        }
        return $activeIPv4Adapter
    }
    catch {
        Write-Host "Error: $_"
        throw $_
    }
}

# Function to lookup an endpoint in ISE
Function Get-ISEEndpoint {
    param (
        $EndpointMac
    )

    $EndpointMac = Format-MacAddress -UnformattedMac $EndpointMac
    $EncodedMacAddress = [System.Web.HttpUtility]::UrlEncode($EndpointMac)
    $ApiUrl = $Url + $EncodedMacAddress

    Log-Info -Info "Function: $(${MyInvocation}.MyCommand.Name)`n$ApiUrl" -LogFileName $LogFileName

    try {
        $Response = Invoke-WebRequest -Uri $ApiUrl -Headers $headers -UseBasicParsing -Method GET -ErrorAction Stop -ErrorVariable WebRequestError

        # Clean JSON response - Powershell cannot parse nested json structure.
        $ResponseContent = $Response.Content -replace '"assetConnectedLinks"\s*:\s*\{\s*""\s*:\s*""\s*\},?', ''
        $ResponseContent = $ResponseContent -replace ',\s*}', '}'
                
        # Log the successful response
        Log-Info -Info $Response.Content -LogFileName $LogFileName
                
        return $ResponseContent | ConvertFrom-Json
    } catch [System.Net.WebException] {
        # Log the streamlined error message
        Log-Info -Info ("An error occurred: " + $_.Exception.Message) -LogFileName $LogFileName

        if ($_.Exception.Response.StatusCode -eq 404) {
            Write-Host "The server returned a 404 Not Found status code, MAC address was not found."
        } else {
            Write-Host "An error occurred: $($_.Exception.Message)"
        }
        throw $_
    }
}


# Function to update endpoint group membership
Function Update-ISEEndpoint {
    param (
        $Endpoint
    )

    $EndpointJson = @{
        "groupId" = $EndpointGroupId
        "id" = $Endpoint.id
        "mac" = $Endpoint.mac
        "name" = $Endpoint.name
        "staticGroupAssignment" = $true
        "staticProfileAssignment" = $false
    }

    $Body = $EndpointJson | ConvertTo-Json

    $Endpointmac = Format-MacAddress -UnformattedMac $Endpoint.mac
    $EncodedMacAddress = [System.Web.HttpUtility]::UrlEncode($Endpointmac)
    $ApiUrl = $Url + $EncodedMacAddress

    #Log the API Call
    Log-Info -Info "Function: $(${MyInvocation}.MyCommand.Name)`n$ApiUrl" -LogFileName $LogFileName

    Try {
        $Response = Invoke-WebRequest -Uri $ApiUrl -Method PUT -Headers @{
            "accept" = "application/json"
            "Content-Type" = "application/json"
            "Authorization" = "Basic $Base64AuthInfo"
        } -Body $Body -UseBasicParsing -ErrorAction Stop -ErrorVariable WebRequestError

        # Log the successful response
        Log-Info -Info $Response.Content -LogFileName $LogFileName

        $StatusCode = $Response.StatusCode

        if ($StatusCode -eq 200) {
            # Clean JSON response - Powershell cannot parse nested json structure.
            $ResponseContent = $Response.Content -replace '"assetConnectedLinks"\s*:\s*\{\s*""\s*:\s*""\s*\},?', ''
            $ResponseContent = $ResponseContent -replace ',\s*}', '}'
            
            return $ResponseContent | ConvertFrom-Json    

        } else {
            throw "Whitelist Group Assignment Failed - Received status code $StatusCode"
        }
    } catch {
        # Log the error
        Log-Info -Info ("An error occurred: " + $_.Exception.Message) -LogFileName $LogFileName
        Throw $_
    }
}

#Function to lookup Endpoint Session Information
Function Get-ISEEndpoint-Session {
    param (
        $Endpointmac
    )

    $Endpointmac = Format-MacAddress -UnformattedMac $Endpointmac
    $EncodedMacAddress = [System.Web.HttpUtility]::UrlEncode($Endpointmac)
    $ApiUrl = "https://$ServerName/admin/API/mnt/Session/MACAddress/$EncodedMacAddress"

    #Log the API Call
    Log-Info -Info "Function: $(${MyInvocation}.MyCommand.Name)`n$ApiUrl" -LogFileName $LogFileName

    $headers = @{
    "Authorization" = "Basic $base64AuthInfo"
    }
    
    Try {
        $response = Invoke-WebRequest -Uri $ApiUrl -Method Get -Headers $headers -UseBasicParsing -ErrorAction Stop -ErrorVariable WebRequestError

        # Log the successful response
        Log-Info -Info $Response.Content -LogFileName $LogFileName
        
        $StatusCode = $Response.StatusCode

        if ($StatusCode -eq 200) {
            $xml = [xml]$response.Content

            # Extract relevant elements
            $network_device_name = $xml.sessionParameters.network_device_name
            $nas_ip_address = $xml.sessionParameters.nas_ip_address
            $nas_port_id = $xml.sessionParameters.nas_port_id
            $acs_server = $xml.sessionParameters.acs_server
            $destination_ip_address = $xml.sessionParameters.destination_ip_address
            $calling_station_id = $xml.sessionParameters.calling_station_id

            # Create a custom object to hold the extracted data
            $sessionInfo = [PSCustomObject]@{
                NetworkDeviceName = $network_device_name
                NasIpAddress = $nas_ip_address
                NasPortId = $nas_port_id
                AcsServer = $acs_server
                DestinationIpAddress = $destination_ip_address
                CallingStationId = $calling_station_id
            }
    
            # Return the custom object
            return $sessionInfo
        } else {
            throw "No Session information found for Endpoint. $StatusCode"
        }
    } catch {
        # Log the error
        Log-Info -Info ("An error occurred: " + $_.Exception.Message) -LogFileName $LogFileName
        Throw $_
    }
}

#Function to force CoA on Endpoint Connected Port
Function ISE-CoA {
    param (
        $session_info
    )

    $REAUTH_TYPE_DEFAULT = 0
    $REAUTH_TYPE_LAST = 1
    $REAUTH_TYPE_RERUN = 2

    $headers = @{
    "Authorization" = "Basic $base64AuthInfo"
    }

    $EncodedMacAddress = [System.Uri]::EscapeDataString($session_info.CallingStationId)
    $ApiUrl = "https://$ServerName/admin/API/mnt/CoA/Reauth/$($session_info.AcsServer)/$EncodedMacAddress/$REAUTH_TYPE_DEFAULT"

    #Log the API Call
    Log-Info -Info "Function: $(${MyInvocation}.MyCommand.Name)`n$ApiUrl" -LogFileName $LogFileName

    try {
        $response = Invoke-WebRequest -Uri $ApiUrl -Method Get -Headers $headers -UseBasicParsing -ErrorAction Stop

        # Log the successful response
        Log-Info -Info $Response.Content -LogFileName $LogFileName

        $StatusCode = $Response.StatusCode

        if ($StatusCode -eq 200) {
        $xmlResponse = [xml]$response.Content

        # Access the 'requestType' and 'results' directly
        $requestType = $xmlResponse.remoteCoA.requestType
        $results = $xmlResponse.remoteCoA.results

        # Create a custom object to hold the extracted data
        $coa_results = [PSCustomObject]@{
            RequestType = $requestType
            Results = $results
        }

        return $coa_results

        } else {
            throw "Unable to complete CoA action. $StatusCode"
        }
    } catch {
        # Log the error
        Log-Info -Info ("An error occurred: " + $_.Exception.Message) -LogFileName $LogFileName
        Throw $_
    }
}


Try {
    Write-Host $Banner -ForegroundColor Green

    Write-Host "Getting Active Adapter:"
    $activeIPv4Adapter = Get-ActiveIPv4Adapter

    if ($ActiveIPv4Adapter) {            
        $ActiveIPv4Adapter | Format-List | Write-Output
	
        Write-Host "Searching for MAC $($ActiveIPv4Adapter.MacAddress) on Server."

        $EndpointInfo = Get-ISEEndpoint -EndpointMac $ActiveIPv4Adapter.MacAddress
        $EndpointId = $EndpointInfo.id
        Write-Host "Found Endpoint ID: $EndpointId"

        Write-Host "Updating Whitelist: " -NoNewline
        
        #Add sleep delay to accomodate any ISE DB update latency.
        Start-Sleep -Seconds $DelayTime
        
        $Update = Update-ISEEndpoint -Endpoint $EndpointInfo

        if ($Update.groupId -eq $EndpointGroupId) {
            Write-Host "Update Successful.`n" -ForegroundColor Green

            Write-Host 'Attempting to Reauth Endpoint.'
            $retryCount = 0
            $maxRetries = 3 #Can take time for authentication session to appear in ISE monitor node, make multiple attempts.
            do {
                $endpoint_session = Get-ISEEndpoint-Session -Endpointmac $ActiveIPv4Adapter.MacAddress

                #Make sure Session Info complete before calling CoA (AcsServer is required)
                $hasNullOrEmptyValues = $endpoint_session.PSObject.Properties | Where-Object {
                    $_.Value -eq $null -or [string]::IsNullOrWhiteSpace($_.Value)
                } | Measure-Object

                if ($hasNullOrEmptyValues.Count -gt 0) {
                    $retryCount++
                    if ($retryCount -le 3) {
                        Write-Host "Session Info Incomplete - Retrying (Attempt $retryCount of $maxRetries)..."
                        Start-Sleep -Seconds $DelayTime
                    } else {
                        throw "Session Info Incomplete - Unable to perform CoA Operation.`n$endpoint_session"
                    }
                } else {
                    Write-Host "Found ISE Session Information" -ForegroundColor Green
                    Write-Output $endpoint_session | Format-Table NetworkDeviceName,NasIpAddress,NasPortId,AcsServer

                    $coa = ISE-CoA -session_info $endpoint_session
                    if ($coa.Results) {
                        Write-Host "CoA operation completed." -ForegroundColor Green
                        Write-Host "Script completed all steps." -ForegroundColor Green
                    } else {
                        Write-Host "Unable to complete CoA operation."
                    }
                }
            } while ($hasNullOrEmptyValues.Count -gt 0 -and $retryCount -le $maxRetries)
        }
    }
} Catch {
    Write-Host "Whitelist Script did not complete!" -ForegroundColor Yellow
    Write-Host "Last Error: `n$_"
} finally {
    Write-Host "Log File: $LogFileName" -ForegroundColor DarkYellow
}

Start-Sleep -s 3 #Add sleep to allow screen capture for troubleshooting.