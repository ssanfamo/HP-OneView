package main

import (
    "bytes"            // Used for creating request bodies
    "encoding/base64"  // Encoding for ServiceNow auth
    "encoding/json"    // JSON encoding and decoding
    "fmt"              // Formatting strings
    "log"              // Logging errors and info
    "net/http"         // HTTP requests
    "os"               // File and environment handling
    "time"             // Timestamping logs
)

// Config struct to hold configuration data
type Config struct {
    OneViewUrl        string `json:"OneViewUrl"`
    OneViewUsername   string `json:"OneViewUsername"`
    OneViewPassword   string `json:"OneViewPassword"`
    OneViewDomain     string `json:"OneViewDomain"`
    ServiceNowUrl     string `json:"ServiceNowUrl"`
    ServiceNowUsername string `json:"ServiceNowUsername"`
    ServiceNowPassword string `json:"ServiceNowPassword"`
    AssignmentGroup   string `json:"AssignmentGroup"`
}

// LoadConfig reads config.json and unmarshals it into Config struct
func LoadConfig() (*Config, error) {
    file, err := os.ReadFile("config.json")
    if err != nil {
        return nil, err
    }
    var config Config
    err = json.Unmarshal(file, &config)
    return &config, err
}

// LogMessage writes log messages with timestamps to a log file
func LogMessage(message string) {
    logFile := "logs/OneViewScraper.log"
    timestamp := time.Now().Format("01-02-2006 15:04:05")
    logEntry := fmt.Sprintf("%s - %s\n", timestamp, message)

    fmt.Print(logEntry) // Print to console
    f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        log.Fatal(err)
    }
    defer f.Close()
    if _, err := f.WriteString(logEntry); err != nil {
        log.Fatal(err)
    }
}

// GetOneViewToken authenticates with OneView and retrieves a session token
func GetOneViewToken(config *Config) (string, error) {
    url := fmt.Sprintf("%s/rest/login-sessions", config.OneViewUrl)
    credentials := map[string]string{
        "userName":        config.OneViewUsername,
        "password":        config.OneViewPassword,
        "authLoginDomain": config.OneViewDomain,
    }
    body, _ := json.Marshal(credentials)

    req, _ := http.NewRequest("POST", url, bytes.NewReader(body))
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("X-Api-Version", "300")

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        LogMessage(fmt.Sprintf("Error authenticating with OneView: %v", err))
        return "", err
    }
    defer resp.Body.Close()

    var result map[string]interface{}
    json.NewDecoder(resp.Body).Decode(&result)

    token, ok := result["sessionID"].(string)
    if !ok {
        LogMessage("Failed to retrieve OneView token.")
        return "", fmt.Errorf("token not found")
    }
    LogMessage("OneView token retrieved successfully.")
    return token, nil
}

// GetBase64AuthHeader creates a Base64-encoded authorization header for ServiceNow
func GetBase64AuthHeader(username, password string) string {
    auth := username + ":" + password
    return "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
}

// CheckExistingTicket checks ServiceNow for active tickets related to a server
func CheckExistingTicket(config *Config, serverID string) bool {
    url := fmt.Sprintf("%s/api/now/table/incident?sysparm_query=active=true^cmdb_ci=%s", config.ServiceNowUrl, serverID)
    req, _ := http.NewRequest("GET", url, nil)
    req.Header.Set("Authorization", GetBase64AuthHeader(config.ServiceNowUsername, config.ServiceNowPassword))
    req.Header.Set("Accept", "application/json")

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        LogMessage(fmt.Sprintf("Error checking existing tickets: %v", err))
        return false
    }
    defer resp.Body.Close()

    var result map[string]interface{}
    json.NewDecoder(resp.Body).Decode(&result)
    tickets, ok := result["result"].([]interface{})
    return ok && len(tickets) > 0
}

// CreateServiceNowTicket creates a new incident in ServiceNow
func CreateServiceNowTicket(config *Config, alertDescription, serverName, serverID string) {
    url := fmt.Sprintf("%s/api/now/table/incident", config.ServiceNowUrl)
    incident := map[string]interface{}{
        "caller_id":          "hws_automation",
        "assignment_group":   config.AssignmentGroup,
        "short_description":  "Critical Alert: " + serverName,
        "description":        alertDescription,
        "business_service":   "Managed Cloud Private Cloud",
        "service_offering":   "Private Cloud - System Monitoring OneView",
        "contact_type":       "event",
        "u_opened_by_group":  "GLBL_Infra_OPS",
        "u_ticket_type":      "INC",
        "impact":             "3",
        "urgency":            "3",
        "u_hostname":         serverName,
        "cmdb_ci":            serverID,
        "u_non_productive_system": "No",
    }
    body, _ := json.Marshal(incident)

    req, _ := http.NewRequest("POST", url, bytes.NewReader(body))
    req.Header.Set("Authorization", GetBase64AuthHeader(config.ServiceNowUsername, config.ServiceNowPassword))
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Accept", "application/json")

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        LogMessage(fmt.Sprintf("Error creating ServiceNow ticket: %v", err))
        return
    }
    defer resp.Body.Close()
    LogMessage("Ticket created successfully in ServiceNow.")
}

// main function to load config, retrieve alerts, and process each alert
func main() {
    config, err := LoadConfig()
    if err != nil {
        log.Fatalf("Error loading config: %v", err)
    }

    token, err := GetOneViewToken(config)
    if err != nil {
        log.Fatalf("Failed to retrieve OneView token.")
    }

    alertsURL := config.OneViewUrl + "/rest/resource-alerts"
    req, _ := http.NewRequest("GET", alertsURL, nil)
    req.Header.Set("Authorization", "Bearer "+token)
    req.Header.Set("X-Api-Version", "300")

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        LogMessage(fmt.Sprintf("Error fetching alerts from OneView: %v", err))
        return
    }
    defer resp.Body.Close()

    var alerts map[string]interface{}
    json.NewDecoder(resp.Body).Decode(&alerts)

    for _, alert := range alerts["members"].([]interface{}) {
        alertData := alert.(map[string]interface{})
        state := alertData["state"].(string)
        if state == "Active" {
            serverID := alertData["resourceID"].(string)
            serverName := alertData["resourceName"].(string)
            description := alertData["description"].(string)

            if !CheckExistingTicket(config, serverID) {
                CreateServiceNowTicket(config, description, serverName, serverID)
            }
        }
    }
}
