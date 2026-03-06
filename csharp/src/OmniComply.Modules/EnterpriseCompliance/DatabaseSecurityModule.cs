using System;
using System.ComponentModel.Composition;
using OmniComply.Core.Engine;
using OmniComply.Core.Interfaces;
using OmniComply.Core.Helpers;

namespace OmniComply.Modules.EnterpriseCompliance
{
    [Export(typeof(IComplianceModule))]
    [ExportMetadata("Name", "Database Security")]
    [ExportMetadata("Category", "Database Security")]
    [ExportMetadata("Order", 30)]
    public class DatabaseSecurityModule : ComplianceModuleBase
    {
        public override string Name => "Database Security";
        public override string Description => "Validates SQL Server installation security, authentication mode, encryption, and data directory permissions";
        public override string Category => "Database Security";
        public override int Order => 30;

        private const string Nist = "SC-28, AC-3";
        private const string Cis = "N/A";
        private const string Iso = "A.10.1.1, A.9.4.1";
        private const string PciDss = "3.4, 8.1";
        private const string Sox = "ITGC-07";

        protected override void RunChecks()
        {
            CheckSqlServerInstalled();
            CheckSqlServerAuthentication();
            CheckSqlServerTde();
            CheckDataDirectoryPermissions();
        }

        private void CheckSqlServerInstalled()
        {
            try
            {
                bool sqlInstalled = false;
                string currentValue = "Not Installed";

                string instanceNames = RegistryHelper.GetString(
                    @"HKLM\SOFTWARE\Microsoft\Microsoft SQL Server",
                    "InstalledInstances");

                if (instanceNames != null && instanceNames.Length > 0)
                {
                    sqlInstalled = true;
                    currentValue = "Installed: " + instanceNames;
                }
                else
                {
                    // Check for instances via the Instance Names key
                    bool keyExists = RegistryHelper.KeyExists(
                        @"HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL");

                    if (keyExists)
                    {
                        sqlInstalled = true;
                        currentValue = "Installed (instances detected via registry)";
                    }
                }

                AddCheck(
                    "SQL Server Installed",
                    "SQL Server installation should be detected and inventoried for security assessment",
                    sqlInstalled,
                    currentValue,
                    "SQL Server detected and inventoried",
                    "If SQL Server is expected, verify installation. If not needed, remove SQL Server components via Programs and Features to reduce attack surface.",
                    nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss, sox: Sox,
                    intuneRecommendation: "Devices > Configuration profiles > Settings catalog. Use custom OMA-URI policies to inventory SQL Server installations across managed endpoints for asset tracking."
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    "SQL Server Installed",
                    "SQL Server installation should be detected and inventoried for security assessment",
                    false,
                    "Error: " + ex.Message,
                    "SQL Server detected and inventoried",
                    "Verify registry access permissions and ensure the compliance scanner has adequate privileges.",
                    nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss, sox: Sox
                );
            }
        }

        private void CheckSqlServerAuthentication()
        {
            try
            {
                bool passed = false;
                string currentValue = "SQL Server not detected";

                // Find the instance-specific registry path
                string instancePath = FindSqlInstanceRegistryPath();

                if (instancePath != null)
                {
                    int loginMode = RegistryHelper.GetDword(
                        instancePath + @"\MSSQLServer",
                        "LoginMode");

                    // LoginMode: 1 = Windows Authentication only, 2 = Mixed Mode
                    switch (loginMode)
                    {
                        case 1:
                            passed = true;
                            currentValue = "Windows Authentication Only (Mode 1)";
                            break;
                        case 2:
                            passed = false;
                            currentValue = "Mixed Mode Authentication (Mode 2)";
                            break;
                        default:
                            currentValue = "Unknown authentication mode (value: " + loginMode + ")";
                            break;
                    }
                }

                AddCheck(
                    "SQL Server Authentication Mode",
                    "SQL Server should use Windows Authentication Only mode to prevent weak SQL logins",
                    passed,
                    currentValue,
                    "Windows Authentication Only (Mode 1)",
                    "Change SQL Server authentication to Windows Authentication Only via SQL Server Management Studio > Server Properties > Security > Server authentication, or set LoginMode=1 in the registry and restart SQL Server service.",
                    nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss, sox: Sox,
                    intuneRecommendation: "N/A - SQL Server authentication mode must be configured directly on the database server. Use Intune compliance scripts to audit the LoginMode registry value on managed endpoints."
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    "SQL Server Authentication Mode",
                    "SQL Server should use Windows Authentication Only mode to prevent weak SQL logins",
                    false,
                    "Error: " + ex.Message,
                    "Windows Authentication Only (Mode 1)",
                    "Verify registry access permissions and SQL Server installation status.",
                    nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss, sox: Sox
                );
            }
        }

        private void CheckSqlServerTde()
        {
            try
            {
                bool passed = false;
                string currentValue = "SQL Server not detected or TDE not configured";

                string instancePath = FindSqlInstanceRegistryPath();

                if (instancePath != null)
                {
                    // Check if TDE certificate exists by querying for encryption keys in the registry
                    // TDE is configured per-database, so we check for the server-level certificate
                    bool superSocketLibExists = RegistryHelper.KeyExists(
                        instancePath + @"\MSSQLServer\SuperSocketNetLib");

                    if (superSocketLibExists)
                    {
                        // Check for ForceEncryption which indicates SSL/TLS is configured (related to TDE readiness)
                        int forceEncryption = RegistryHelper.GetDword(
                            instancePath + @"\MSSQLServer\SuperSocketNetLib",
                            "ForceEncryption");

                        // Also try to run sqlcmd to check TDE status
                        var result = ProcessHelper.RunCmd(
                            "sqlcmd -Q \"SELECT db.name, dm.encryption_state FROM sys.dm_database_encryption_keys dm JOIN sys.databases db ON dm.database_id = db.database_id\" -h -1 2>nul");

                        if (result.Success && !string.IsNullOrWhiteSpace(result.StandardOutput)
                            && result.StandardOutput.Contains("3"))
                        {
                            passed = true;
                            currentValue = "TDE is active (encryption_state=3 detected)";
                        }
                        else if (forceEncryption == 1)
                        {
                            // ForceEncryption is enabled which provides transport-level encryption
                            currentValue = "ForceEncryption enabled but TDE status could not be verified via sqlcmd";
                        }
                        else
                        {
                            currentValue = "TDE not detected; ForceEncryption=" + (forceEncryption == 1 ? "Enabled" : "Disabled");
                        }
                    }
                    else
                    {
                        currentValue = "SQL Server detected but network configuration not found";
                    }
                }

                AddCheck(
                    "SQL Server Transparent Data Encryption",
                    "SQL Server databases containing sensitive data should have Transparent Data Encryption (TDE) enabled",
                    passed,
                    currentValue,
                    "TDE enabled on sensitive databases",
                    "Enable TDE on databases: CREATE DATABASE ENCRYPTION KEY WITH ALGORITHM = AES_256 ENCRYPTION BY SERVER CERTIFICATE [cert_name]; ALTER DATABASE [db_name] SET ENCRYPTION ON. Also enable ForceEncryption for transport-level protection.",
                    nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss, sox: Sox,
                    intuneRecommendation: "N/A - TDE is a server-side database configuration. Use Intune proactive remediation scripts to audit SQL Server encryption status on managed endpoints."
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    "SQL Server Transparent Data Encryption",
                    "SQL Server databases containing sensitive data should have Transparent Data Encryption (TDE) enabled",
                    false,
                    "Error: " + ex.Message,
                    "TDE enabled on sensitive databases",
                    "Verify SQL Server is installed and accessible. Ensure sqlcmd is available on the PATH.",
                    nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss, sox: Sox
                );
            }
        }

        private void CheckDataDirectoryPermissions()
        {
            try
            {
                bool passed = false;
                string currentValue = "SQL Server not detected";

                string instancePath = FindSqlInstanceRegistryPath();

                if (instancePath != null)
                {
                    string dataDir = RegistryHelper.GetString(
                        instancePath + @"\Setup",
                        "SQLDataRoot");

                    if (!string.IsNullOrEmpty(dataDir))
                    {
                        // Check permissions using icacls
                        var result = ProcessHelper.RunCmd(
                            string.Format("icacls \"{0}\"", dataDir));

                        if (result.Success && !string.IsNullOrWhiteSpace(result.StandardOutput))
                        {
                            string output = result.StandardOutput;

                            // Check for overly permissive access - Everyone or BUILTIN\Users with write access
                            bool hasEveryoneAccess = output.IndexOf("Everyone", StringComparison.OrdinalIgnoreCase) >= 0;
                            bool hasUsersWriteAccess = output.IndexOf("BUILTIN\\Users:(OI)(CI)(F)", StringComparison.OrdinalIgnoreCase) >= 0
                                || output.IndexOf("BUILTIN\\Users:(OI)(CI)(M)", StringComparison.OrdinalIgnoreCase) >= 0;

                            if (!hasEveryoneAccess && !hasUsersWriteAccess)
                            {
                                passed = true;
                                currentValue = "Data directory permissions are restricted: " + dataDir;
                            }
                            else
                            {
                                currentValue = "Overly permissive access detected on: " + dataDir;
                                if (hasEveryoneAccess)
                                    currentValue += " (Everyone group has access)";
                                if (hasUsersWriteAccess)
                                    currentValue += " (BUILTIN\\Users has write access)";
                            }
                        }
                        else
                        {
                            currentValue = "Could not query permissions for: " + dataDir;
                        }
                    }
                    else
                    {
                        currentValue = "SQL data directory path not found in registry";
                    }
                }

                AddCheck(
                    "SQL Data Directory Permissions",
                    "SQL Server data directories must have restricted permissions to prevent unauthorized access",
                    passed,
                    currentValue,
                    "Restricted to SQL Server service account and administrators only",
                    "Remove overly permissive ACLs from the SQL data directory. Use icacls to restrict access: icacls \"<DataDir>\" /remove Everyone /remove \"BUILTIN\\Users\" and grant access only to the SQL Server service account and local Administrators.",
                    nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss, sox: Sox,
                    intuneRecommendation: "Devices > Scripts > Add PowerShell script to audit SQL data directory ACLs. Use Intune proactive remediations to detect and remediate overly permissive file system permissions."
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    "SQL Data Directory Permissions",
                    "SQL Server data directories must have restricted permissions to prevent unauthorized access",
                    false,
                    "Error: " + ex.Message,
                    "Restricted to SQL Server service account and administrators only",
                    "Verify SQL Server installation and ensure the compliance scanner has file system access.",
                    nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss, sox: Sox
                );
            }
        }

        /// <summary>
        /// Finds the registry path for the first SQL Server instance.
        /// Returns a path like HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL15.MSSQLSERVER
        /// </summary>
        private string FindSqlInstanceRegistryPath()
        {
            try
            {
                // Get the list of installed instance names
                object instancesValue = RegistryHelper.GetValue(
                    @"HKLM\SOFTWARE\Microsoft\Microsoft SQL Server",
                    "InstalledInstances");

                string[] instances = instancesValue as string[];
                if (instances == null || instances.Length == 0)
                    return null;

                string instanceName = instances[0];

                // Get the instance ID mapping (e.g., MSSQLSERVER -> MSSQL15.MSSQLSERVER)
                string instanceId = RegistryHelper.GetString(
                    @"HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL",
                    instanceName);

                if (!string.IsNullOrEmpty(instanceId))
                {
                    return @"HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\" + instanceId;
                }
            }
            catch
            {
            }

            return null;
        }
    }
}
