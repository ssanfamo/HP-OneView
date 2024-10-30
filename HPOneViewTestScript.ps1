
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

# Define HPE OneView server credentials
$oneviewServer = @{
    Url = "https://prdsdcapl30188.linux.adsint.biz"; 
    Username = "SVC_OneViewAPI"; 
    Password = "l7WI6mp@rbCcw7*l"
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$itsmServer = "https://adidasaspentest.service-now.com/"
$itsmUsername = "SVC_OneViewAPI_AP"
$itsmPassword = "l7WI6mp@rbCcw7*l"

# ServiceNow instance URL and API endpoint
$InstanceUrl = $itsmServer 

# File to store previous alert statuses
$statusFile = "C:\temp\HpOneView\alert_statuses.json"

# Authentication Headers for ServiceNow
$Ticketheaders = @{
    "Accept" = "*/*";
    "Authorization" = "Basic T25lVmlld19hcGk6cEhJQDNJVnhMSQ==";  # Adjust as necessary for your auth type
    "Content-Type" = "application/json" 
}

# Function to log messages to both the console and a file
function Log-Message {
    param (
        [String]$message
    )

    # Define the path to the log file
    $logFile = "C:\\Temp\\HPOneView\\Logs\\HPOneViewScriptLog.txt"

    # Get the current timestamp for log entries
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    # Format the log entry with timestamp
    $logEntry = "$timestamp - $message"

    # Write log entry to the PowerShell console
    Write-Host $logEntry

    # Append log entry to the specified log file
    Add-Content -Path $logFile -Value $logEntry
}

function Get-OneViewApiToken {
    # Define your credentials
    $username = "yourUsername"
    $password = "yourPassword"

    # Combine credentials with a colon and convert to Base64 for Basic Auth (if applicable)
    $combinedCredentials = "${username}:$password"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($combinedCredentials)
    $base64Credentials = [System.Convert]::ToBase64String($bytes)
    $basicAuthValue = "Basic $base64Credentials"

    try {
        # Prepare the body and headers for OneView API request
        $body = @{
            userName = $username
            password = $password
            authLoginDomain = "emea.adsint.biz"
        } | ConvertTo-Json

        $headers = @{
            "Content-Type" = "application/json";
            "X-Api-Version" = "300";  # Ensure this version matches your OneView API version
            "Authorization" = $basicAuthValue  # Using Basic Auth (verify if supported)
        }

        # Optionally disable SSL certificate validation
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

        Log-Message "Authenticating with OneView..."
        $uri = "$($oneviewServer.Url)/rest/login-sessions"
        $response = Invoke-RestMethod -Uri $uri -Method Post -Body $body -Headers $headers
        Log-Message "Successfully retrieved OneView token."
        return $response.sessionID
    } catch {
        Log-Message "Error during OneView authentication: $($_.Exception.Message)"
        return $null
    }
}

# Function to check for existing open tickets
function Check-ExistingTicket {
    param (
        [String]$itsmApiToken,
        [String]$serverId
    )
    $apiUrl = "$InstanceUrl/api/now/table/incident?sysparm_query=active=true^cmdb_ci=$serverId"
    try {
        Log-Message "Checking for existing tickets with Server ID: $serverId..."
        $existingTickets = Invoke-RestMethod -Uri $apiUrl -Headers $Ticketheaders -Method Get
        Log-Message "Successfully retrieved existing tickets."
        return $existingTickets.result
    } catch {
        Log-Message "Error while checking for existing tickets: $($_.Exception.Message)"
        return $null
    }
}

# Function to create a new ticket in ServiceNow
function New-ASPENTicket {
    param(
        [parameter(Mandatory=$true)][String] $assignmentGroup,
        [parameter(Mandatory=$true)][String] $shortDescription,
        [parameter(Mandatory=$true)][String] $description,
        [parameter(Mandatory=$true)][String] $nonprod,
        [String] $FirstServer,
        [String] $FirstServerID
    )
    $apiCallTkt = "$InstanceUrl/api/now/table/incident"
    
    $jsonTkt = @{
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
        "u_hostname" = $FirstServer;
        "cmdb_ci" = $FirstServerID;
        "u_non_productive_system" = $nonprod
    } | ConvertTo-Json -Depth 100

    try {
        Log-Message "Creating a new ticket in ServiceNow..."
        $response = Invoke-RestMethod -Uri $apiCallTkt -Headers $Ticketheaders -Method Post -Body $jsonTkt -ContentType "application/json"
        Log-Message "Successfully created a ticket. Ticket ID: $($response.result.sys_id)"
        return $response.result
    } catch {
        Log-Message "Error while creating ticket in ServiceNow: $($_.Exception.Message)"
        return $null
    }
}


# Process alerts from the OneView server
function Process-Alerts {
    $oneViewApiToken = Get-OneViewApiToken
    if ($oneViewApiToken -eq $null) {
        Log-Message "Failed to authenticate with OneView, exiting..."
        return
    }

    $alertsApi = "$($oneviewServer.Url)/rest/resource-alerts"
    try {
        $headers = @{
            "Authorization" = "Bearer $oneViewApiToken";
            "X-Api-Version" = "300"  # Ensure this version matches your OneView API version
        }
        
        Log-Message "Fetching alerts from OneView..."
        $alerts = Invoke-RestMethod -Uri $alertsApi -Headers $headers -Method Get
        
        foreach ($alert in $alerts.members) {
            if ($alert.state -eq 'Active') {
                Log-Message "Critical alert found: $($alert.description)"
                $existingTickets = Check-ExistingTicket -itsmApiToken $itsmApiToken -serverId $alert.resourceID
                if ($existingTickets -eq $null -or $existingTickets.Count -eq 0) {
                    Log-Message "No existing ticket found, creating a new one..."
                    New-ASPENTicket -assignmentGroup "YourAssignmentGroup" -shortDescription "Critical Alert" -description $alert.description -nonprod "No" -FirstServer $alert.resourceName -FirstServerID $alert.resourceID
                } else {
                    Log-Message "Existing ticket found, no need to create a new one."
                }
            }
        }
    } catch {
        Log-Message "Error while fetching alerts: $($_.Exception.Message)"
    }
}



jwn1J*CA#WjuZ5