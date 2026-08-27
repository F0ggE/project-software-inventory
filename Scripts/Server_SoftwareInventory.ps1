# ==============================================================================
# SCRIPT: Get-ServerInventory.ps1
# PURPOSE: Extract software inventory for Windows Servers and Linux endpoints 
#          from Microsoft Defender via Graph API for Elasticsearch ingestion.
# ==============================================================================

# ------------------------------------------------------------------------------
# 0. CONFIGURATION & CREDENTIALS
# ------------------------------------------------------------------------------
$TenantId     = "PASTE_TENANT_ID_HERE"
$ClientId     = "PASTE_CLIENT_ID_HERE"
$ClientSecret = "PASTE_CLIENT_SECRET_HERE"

# Output directory for server snapshots
$OutputDirectory = "C:\Scripts\Software-Inventory\JSON-Files\Servers"

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
    Write-Host "      Authentication Successful!" -ForegroundColor Green
} catch {
    Write-Host "      Authentication Failed: $_" -ForegroundColor Red
    return
}

# ------------------------------------------------------------------------------
# 2. DEFINE KQL QUERY (WINDOWS SERVERS & LINUX ENDPOINTS)
# ------------------------------------------------------------------------------
Write-Host "[2/4] Querying Defender API for Server Fleet (Windows & Linux)..." -ForegroundColor Cyan

# Compound filter to capture Windows Servers, all Linux distros, and server-role devices
$KqlQuery = @"
DeviceTvmSoftwareInventory
| join kind=inner (
    DeviceInfo 
    | where OSPlatform contains 'Server' 
         or OSPlatform startswith 'Linux' 
         or OSPlatform contains 'Linux'
         or DeviceType == 'Server'
    | summarize arg_max(Timestamp, *) by DeviceId
) on DeviceId
| project 
    SnapshotDate = now(),
    DeviceId, 
    DeviceName, 
    OSPlatform, 
    OSDistribution,
    SoftwareVendor, 
    SoftwareName, 
    SoftwareVersion,
    ProductCodeCpe
"@

$Headers   = @{ 
    "Authorization" = "Bearer $AccessToken"
    "Content-Type"  = "application/json; charset=utf-8" 
}
$QueryBody = @{ Query = $KqlQuery } | ConvertTo-Json -Depth 2

# ------------------------------------------------------------------------------
# 3. EXECUTE GRAPH QUERY & EXPORT JSON
# ------------------------------------------------------------------------------
try {
    $GraphUrl  = "https://graph.microsoft.com/v1.0/security/runHuntingQuery"
    $Response  = Invoke-RestMethod -Uri $GraphUrl -Method Post -Headers $Headers -Body $QueryBody
    $Results   = $Response.results
    
    Write-Host "      Query Completed! Retrieved $($Results.Count) total server software records." -ForegroundColor Green
} catch {
    $StreamReader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
    $ErrorDetails = $StreamReader.ReadToEnd()
    Write-Host "      API Query Failed: $_" -ForegroundColor Red
    Write-Host "      Graph Details: $ErrorDetails" -ForegroundColor Yellow
    return
}

# ------------------------------------------------------------------------------
# 4. EXPORT TO CLEAN NDJSON (FILEBEAT INGESTION READY)
# ------------------------------------------------------------------------------
$DateStamp  = Get-Date -Format "yyyy-MM-dd"
$OutputFile = Join-Path -Path $OutputDirectory -ChildPath "servers-inventory-$DateStamp.json"

if ($Results) {
    # Force output to strip array wrappers and write pure line-by-line JSON objects
    $ndjson = foreach ($item in $Results) {
        $item | ConvertTo-Json -Compress -Depth 5
    }
    $ndjson | Out-File -FilePath $OutputFile -Encoding utf8
    
    Write-Host "[4/4] Export Complete! Saved clean NDJSON to: $OutputFile" -ForegroundColor Green
} else {
    Write-Host "[4/4] No records returned." -ForegroundColor Gray
}