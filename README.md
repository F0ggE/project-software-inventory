# 🛡️ Defender & Intune Inventory to Elasticsearch

Automated PowerShell and Filebeat pipeline to extract software inventories for workstations and servers from Microsoft 365 Defender, enrich client devices with official Microsoft Intune Primary Users, and stream structured NDJSON data directly into custom Elasticsearch data streams.

---

## 📌 About
This project bridges the gap between Microsoft Defender Advanced Hunting and Elasticsearch. It runs scheduled data pulls, maps devices to their assigned corporate users via the Microsoft Graph API, cleans the output into lightweight NDJSON, and leverages Filebeat conditional routing to separate server and client software footprints into distinct indices (`logs-defender.clients-default` and `logs-defender.servers-default`).

---

## 🔐 Azure App Registration & Permissions

To allow the PowerShell scripts to authenticate using the Client Credentials flow, create an App Registration in **Microsoft Entra ID** and grant the following **Application Permissions** under **Microsoft Graph**:

| API / Permission Type | Permission Name | Purpose |
| :--- | :--- | :--- |
| **Microsoft Graph** (Application) | `DeviceManagementManagedDevices.Read.All` | Pulls Intune devices and maps primary user UPNs. |
| **Microsoft Graph** (Application) | `AdvancedHunting.Read.All` | Executes KQL queries against Microsoft 365 Defender. |

> ⚠️ **Important:** Ensure you click **"Grant admin consent"** for your organization after assigning these permissions.

---

## 📂 Repository Structure

```text
├── Scripts/
│   ├── Get_ClientInventory.ps1   # Pulls workstation software + Intune primary user
│   └── Get_ServerInventory.ps1   # Pulls server infrastructure software inventory
├── Config/
│   └── filebeat.yml              # Filebeat inputs, parsers, and conditional routing
└── README.md
