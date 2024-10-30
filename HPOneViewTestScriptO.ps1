# Enable TLS 1.2 for secure connections
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Define paths for configuration and logging
$ConfigPath = "C:\temp\HpOneView\config.json"
$LogFile = "C:\Temp\HPOneView\Logs\HPOneViewScriptLog.txt"

# Function to securely fetch configuration data (URLs, usernames, etc.)
function Get-Config {
    if (Test-Path -Path $ConfigPath) {
        return Get-Content -Path $ConfigPath | ConvertFrom-Json
    } else {
        Write-Host "Configuration file not found at $ConfigPath"
        exit
    }
}

# Function to log messages with timestamp
function Log-Message {
    param (
        [String]$message
    )
    $timestamp = Get-Date -Format "MM-dd-yyyy HH:mm:ss"
    $logEntry = "$timestamp - $message"
    Write-Host $logEntry
    Add-Content -Path $LogFile -Value $logEntry
}

# Fetch configuration
$config = Get-Config
$oneviewServerUrl = $config.OneViewUrl
$itsmServerUrl = $config.ITSMUrl
$itsmUsername = $config.ITSMUsername
$itsmPassword = $config.ITSMPwd
$assignmentGroup = $config.AssignmentGroup

# Function to get an authentication token from OneView
function Get-OneViewApiToken {
    $username = $config.OneViewUsername
    $password = $config.OneViewPassword
    $body = @{
        userName = $username
        password = $password
        authLoginDomain = $config.OneViewDomain
    } | ConvertTo-Json

    $headers = @{
        "Content-Type" = "application/json";
        "X-Api-Version" = "300"
    }
    
    try {
        Log-Message "Authenticating with OneView..."
        $uri = "$oneviewServerUrl/rest/login-sessions"
        $response = Invoke-RestMethod -Uri $uri -Method Post -Body $body -Headers $headers
        Log-Message "OneView token retrieved successfully."
        return $response.sessionID
    } catch {
        Log-Message "Error in OneView authentication: $($_.Exception.Message)"
        return $null
    }
}

# Function to create Base64 authorization for ServiceNow
function Get-ITSMAuthHeader {
    $auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$itsmUsername:$itsmPassword"))
    return "Basic $auth"
}

# Function to check for existing ServiceNow tickets
function Check-ExistingTicket {
    param (
        [String]$serverId
    )
    $apiUrl = "$itsmServerUrl/api/now/table/incident?sysparm_query=active=true^cmdb_ci=$serverId"
    $headers = @{
        "Accept" = "application/json"
        "Authorization" = (Get-ITSMAuthHeader)
    }

    try {
        Log-Message "Checking existing tickets for Server ID: $serverId..."
        $existingTickets = Invoke-RestMethod -Uri $apiUrl -Headers $headers -Method Get
        return $existingTickets.result
    } catch {
        Log-Message "Error while checking tickets: $($_.Exception.Message)"
        return $null
    }
}

# Function to create a new ServiceNow ticket
function New-ASPENTicket {
    param(
        [String]$shortDescription,
        [String]$description,
        [String]$serverName,
        [String]$serverId
    )
    $apiUrl = "$itsmServerUrl/api/now/table/incident"
    $headers = @{
        "Authorization" = (Get-ITSMAuthHeader)
        "Content-Type" = "application/json"
    }
    $body = @{
        "caller_id" = "hws_automation";
        "assignment_group" = $assignmentGroup;
        "description" = $description;
        "short_description" = $shortDescription;
        "business_service" = "Managed Cloud Private Cloud";
        "service_offering" = "Private Cloud - System Monitoring OneView";
        "contact_type" = "event";
        "u_opened_by_group" = "GLBL_Infra_OPS";
        "u_ticket_type" = "INC";
        "impact" = "3";
        "urgency" = "3";
        "u_hostname" = $serverName;
        "cmdb_ci" = $serverId;
        "u_non_productive_system" = "No"
    } | ConvertTo-Json -Depth 100

    try {
        Log-Message "Creating new ticket in ServiceNow..."
        $response = Invoke-RestMethod -Uri $apiUrl -Headers $headers -Method Post -Body $body
        Log-Message "Ticket created successfully. Ticket ID: $($response.result.sys_id)"
        return $response.result
    } catch {
        Log-Message "Error while creating ticket in ServiceNow: $($_.Exception.Message)"
        return $null
    }
}

# Function to process alerts from OneView
function Process-Alerts {
    $token = Get-OneViewApiToken
    if (-not $token) {
        Log-Message "Failed to retrieve OneView token. Exiting..."
        return
    }

    $headers = @{
        "Authorization" = "Bearer $token";
        "X-Api-Version" = "300"
    }
    $alertsApiUrl = "$oneviewServerUrl/rest/resource-alerts"

    try {
        Log-Message "Fetching alerts from OneView..."
        $alerts = Invoke-RestMethod -Uri $alertsApiUrl -Headers $headers -Method Get

        foreach ($alert in $alerts.members) {
            if ($alert.state -eq 'Active') {
                Log-Message "Critical alert found: $($alert.description)"
                $existingTickets = Check-ExistingTicket -serverId $alert.resourceID
                if (-not $existingTickets) {
                    Log-Message "No existing ticket found, creating a new one..."
                    New-ASPENTicket -shortDescription "Critical Alert: $($alert.resourceName)" -description $alert.description -serverName $alert.resourceName -serverId $alert.resourceID
                } else {
                    Log-Message "Existing ticket found for alert."
                }
            }
        }
    } catch {
        Log-Message "Error while fetching alerts: $($_.Exception.Message)"
    }
}

# Run the alert processing
Process-Alerts
