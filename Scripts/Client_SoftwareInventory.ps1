# ==============================================================================
# SCRIPT: Get-ClientInventory.ps1
# PURPOSE: Extract software inventory for Workstations (Windows/macOS) from 
#          Microsoft Defender and enrich with Intune Primary Users via Graph API.
# ==============================================================================

# ------------------------------------------------------------------------------
# 0. CONFIGURATION & CREDENTIALS
# ------------------------------------------------------------------------------
$TenantId     = "PASTE_TENANT_ID_HERE"
$ClientId     = "PASTE_CLIENT_ID_HERE"
$ClientSecret = "PASTE_CLIENT_SECRET_HERE"

# Output directory for client snapshots
$OutputDirectory = "C:\Scripts\Software-Inventory\JSON-Files\Clients"

if (!(Test-Path -Path $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
}

# ------------------------------------------------------------------------------
# 1. AUTHENTICATE WITH MICROSOFT GRAPH
# ------------------------------------------------------------------------------
Write-Host "[1/4] Authenticating with Microsoft Graph..." -ForegroundColor Cyan

$TokenBody = @{
    grant_type    = "client_credentials"
    client_id     = $ClientId
    client_secret = $ClientSecret
    scope         = "https://graph.microsoft.com/.default"
}

try {
    $TokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Method Post -Body $TokenBody
    $AccessToken   = $TokenResponse.access_token
    $Headers       = @{ 
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json; charset=utf-8" 
    }
    Write-Host "      Authentication Successful!" -ForegroundColor Green
} catch {
    Write-Host "      Authentication Failed: $_" -ForegroundColor Red
    return
}

# ------------------------------------------------------------------------------
# 2. FETCH INTUNE PRIMARY USERS (PAGINATED WITH /USERS SUB-ENDPOINT)
# ------------------------------------------------------------------------------
Write-Host "[2/4] Fetching official Primary Users from Intune Graph API..." -ForegroundColor Cyan
$IntuneLookup = @{}

try {
    # Request Intune device list with pagination (up to 999 per page)
    $IntuneUrl = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$select=id,deviceName,userPrincipalName&`$top=999"

    while ($IntuneUrl) {
        $IntuneResponse = Invoke-RestMethod -Uri $IntuneUrl -Method Get -Headers $Headers
        
        foreach ($device in $IntuneResponse.value) {
            if ($device.deviceName) {
                # Strip domain suffix and convert to uppercase for exact matching (e.g., 'PC-01.domain.com' -> 'PC-01')
                $cleanName = $device.deviceName.Split('.')[0].ToUpper()
                $primaryUser = $null

                # Query the explicit Intune Primary User sub-endpoint
                try {
                    $UserUrl = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices('$($device.id)')/users?`$select=userPrincipalName"
                    $UserResponse = Invoke-RestMethod -Uri $UserUrl -Method Get -Headers $Headers
                    if ($UserResponse.value.userPrincipalName) {
                        $primaryUser = $UserResponse.value[0].userPrincipalName
                    }
                } catch { }

                # Fallback to enrollment UPN if primary user mapping is empty
                if (-not $primaryUser -and $device.userPrincipalName) {
                    $primaryUser = $device.userPrincipalName
                }

                # Store result in lookup table with "Unassigned" fallback
                if ($primaryUser) {
                    $IntuneLookup[$cleanName] = $primaryUser
                } else {
                    $IntuneLookup[$cleanName] = "Unassigned"
                }
            }
        }

        # Follow @odata.nextLink for pagination
        $IntuneUrl = $IntuneResponse.'@odata.nextLink'
    }

    Write-Host "      Mapped Primary Users for $($IntuneLookup.Count) Intune devices." -ForegroundColor Green
} catch {
    Write-Host "      Warning: Failed to fetch Intune records: $_" -ForegroundColor Yellow
    Write-Host "      Proceeding with inventory extraction..." -ForegroundColor Yellow
}

# ------------------------------------------------------------------------------
# 3. DEFINE KQL QUERY & FETCH WORKSTATION INVENTORY
# ------------------------------------------------------------------------------
Write-Host "[3/4] Querying Defender API for Windows Workstations..." -ForegroundColor Cyan

# Explicitly requires Windows OS while filtering out Windows Server OS versions
$KqlQuery = @"
DeviceTvmSoftwareInventory
| join kind=inner (
    DeviceInfo 
    | where OSPlatform contains 'Windows' 
        and OSPlatform !contains 'Server' 
        and DeviceType != 'Server'
        and DeviceType != 'NetworkDevice'
    | summarize arg_max(Timestamp, *) by DeviceId
) on DeviceId
| project 
    SnapshotDate = now(),
    DeviceId, 
    DeviceName, 
    OSPlatform, 
    SoftwareVendor, 
    SoftwareName, 
    SoftwareVersion,
    ProductCodeCpe
"@

$QueryBody = @{ Query = $KqlQuery } | ConvertTo-Json -Depth 2

try {
    $GraphUrl  = "https://graph.microsoft.com/v1.0/security/runHuntingQuery"
    $Response  = Invoke-RestMethod -Uri $GraphUrl -Method Post -Headers $Headers -Body $QueryBody
    $Results   = $Response.results
    
    Write-Host "      Defender Query Completed! Retrieved $($Results.Count) client software records." -ForegroundColor Green
} catch {
    $StreamReader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
    $ErrorDetails = $StreamReader.ReadToEnd()
    Write-Host "      API Query Failed: $_" -ForegroundColor Red
    Write-Host "      Graph Details: $ErrorDetails" -ForegroundColor Yellow
    return
}

# ------------------------------------------------------------------------------
# 4. ENRICH WITH PRIMARY USERS & EXPORT TO CLEAN NDJSON
# ------------------------------------------------------------------------------
$DateStamp  = Get-Date -Format "yyyy-MM-dd"
$OutputFile = Join-Path -Path $OutputDirectory -ChildPath "clients-inventory-$DateStamp.json"

if ($Results) {
    Write-Host "[4/4] Enriching records and exporting to NDJSON..." -ForegroundColor Cyan

    $ndjson = foreach ($item in $Results) {
        # Normalize the Defender DeviceName to match the Intune lookup format
        $matchedUser = "Unassigned"
        if ($item.DeviceName) {
            $cleanDefenderName = $item.DeviceName.Split('.')[0].ToUpper()
            if ($IntuneLookup.ContainsKey($cleanDefenderName)) {
                $matchedUser = $IntuneLookup[$cleanDefenderName]
            }
        }

        # Add or update the PrimaryUser property directly on the object
        $item | Add-Member -MemberType NoteProperty -Name "PrimaryUser" -Value $matchedUser -Force

        # Convert back to compressed single-line JSON string
        $item | ConvertTo-Json -Compress -Depth 5
    }

    $ndjson | Out-File -FilePath $OutputFile -Encoding utf8
    
    Write-Host "      Export Complete! Saved clean NDJSON to: $OutputFile" -ForegroundColor Green
} else {
    Write-Host "[4/4] No client software records returned." -ForegroundColor Gray
}
    $ndjson | Out-File -FilePath $OutputFile -Encoding utf8
    
    Write-Host "      Export Complete! Saved clean NDJSON to: $OutputFile" -ForegroundColor Green
} else {
    Write-Host "[4/4] No client software records returned." -ForegroundColor Gray
}
