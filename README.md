# 👑 EPManager

EPManager is a PowerShell based utility that allows for bulk export and creation of Microsoft Intune Endpoint Privilege Manager Rule Policies.

## ⚠ Public Preview Notice

EPManager is currently in Public Preview, meaning that although the it is functional, you may encounter issues or bugs with the script.

> [!TIP]
> If you do encounter bugs, want to contribute, submit feedback or suggestions, please create and an issue.

## 🗒 Prerequisites

> [!IMPORTANT]
>
> - Supports PowerShell 7 on Windows
> - `Microsoft.Graph.Authentication` module should be installed, the script will detect and install if required.
> - Entra ID App Registration with appropriate Graph Scopes or using Interactive Sign-In with a privileged account.

## 🔄 Updates

- **v0.3**
  - Improved Functions and information.
- v0.2
  - Updated logic for hash grouping of exported rules
- v0.1
  - Initial release

## ⏯ Usage

Run  the script to capture EPM report data to a CSV file in the same location as the PowerShell script:

```powershell
.\EPManager.ps1 -tenantID '437e8ffb-3030-469a-99da-e5b527908099' -report
```

After modifying the exported CSV file, it can then be imported with the below command to add new policies to Intune:

```powershell
.\EPManager.ps1 -tenantID '437e8ffb-3030-469a-99da-e5b527908099' -import -importPath ".\EPManager-Report-20250321-111725.csv"
```

OR

After modifying the exported CSV file, it can then be imported with the below command to add new policies to Intune and assign them to specified groups:

```powershell
.\EPManager.ps1  -tenantID '437e8ffb-3030-469a-99da-e5b527908099' -import -importPath ".\EPManager-Report-20250321-111725.csv" -assign
```

## 🚑 Support

If you encounter any issues or have questions:

1. Check the [Issues](https://github.com/ennnbeee/EPManager/issues) page
2. Open a new issue if needed

Thank you for your support.

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

Created by [Nick Benton](https://github.com/ennnbeee) of [odds+endpoints](https://www.oddsandendpoints.co.uk/)
