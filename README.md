# 👑 EndpointPrivilegeManager

EndpointPrivilegeManager is a PowerShell based utility that allows for bulk export and creation of Microsoft Intune Endpoint Privilege Manager Rule Policies.

## ⚠ Public Preview Notice

EndpointPrivilegeManager is currently in Public Preview, meaning that although the it is functional, you may encounter issues or bugs with the script.

> [!TIP]
> If you do encounter bugs, want to contribute, submit feedback or suggestions, please create and an issue.

## 🗒 Prerequisites

> [!IMPORTANT]
>
> - Supports PowerShell 7 on Windows
> - `Microsoft.Graph.Authentication` module should be installed, the script will detect and install if required.
> - Entra ID App Registration with appropriate Graph Scopes or using Interactive Sign-In with a privileged account.

## 🔄 Updates

- **v0.2**
  - Updated logic for hash grouping of exported rules
- v0.1
  - Initial release

## ⏯ Usage

Run  the script to capture EPM report data to a CSV file in the same location as the PowerShell script:

```powershell
.\EndpointPrivilegeManager.ps1  -tenantID '437e8ffb-3030-469a-99da-e5b527908099' -report
```

After modifying the exported CSV file, it can then be imported with the below command to add new policies to Intune:

```powershell
.\EndpointPrivilegeManager.ps1  -tenantID '437e8ffb-3030-469a-99da-e5b527908099' -import -importPath ".\EPM-Report-20250321-111725.csv"
```

OR

After modifying the exported CSV file, it can then be imported with the below command to add new policies to Intune and assign them to specified groups:

```powershell
.\EndpointPrivilegeManager.ps1  -tenantID '437e8ffb-3030-469a-99da-e5b527908099' -import -importPath ".\EPM-Report-20250321-111725.csv" -assign
```
