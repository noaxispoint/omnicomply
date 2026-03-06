using System;
using System.ComponentModel.Composition;
using System.IO;
using OmniComply.Core.Engine;
using OmniComply.Core.Interfaces;
using OmniComply.Core.Helpers;

namespace OmniComply.Modules.Privacy
{
    [Export(typeof(IComplianceModule))]
    [ExportMetadata("Name", "Data Retention Destruction")]
    [ExportMetadata("Category", "Data Retention and Destruction")]
    [ExportMetadata("Order", 32)]
    public class DataRetentionDestructionModule : ComplianceModuleBase
    {
        public override string Name => "Data Retention Destruction";
        public override string Description => "Validates File Server Resource Manager availability, secure deletion tools, disk cleanup scheduling, and recycle bin policies";
        public override string Category => "Data Retention and Destruction";
        public override int Order => 32;

        private const string Nist = "MP-6, SI-12";
        private const string Cis = "3.4";
        private const string Iso = "A.8.3.2, A.11.2.7";
        private const string Gdpr = "Article 17";
        private const string Ccpa = "\u00a7 1798.105";

        protected override void RunChecks()
        {
            CheckFsrmInstalled();
            CheckSecureDeletionToolAvailable();
            CheckDiskCleanupScheduled();
            CheckRecycleBinPolicy();
        }

        private void CheckFsrmInstalled()
        {
            try
            {
                bool fsrmInstalled = false;
                string currentValue = "FSRM not detected";

                // Check for FSRM via registry (server feature)
                bool fsrmKeyExists = RegistryHelper.KeyExists(
                    @"HKLM\SYSTEM\CurrentControlSet\Services\SrmSvc");

                if (fsrmKeyExists)
                {
                    // Check if the service is configured
                    var result = ProcessHelper.RunCmd("sc query SrmSvc");
                    if (result.Success && result.StandardOutput != null
                        && (result.StandardOutput.IndexOf("RUNNING", StringComparison.OrdinalIgnoreCase) >= 0
                            || result.StandardOutput.IndexOf("STOPPED", StringComparison.OrdinalIgnoreCase) >= 0))
                    {
                        fsrmInstalled = true;
                        if (result.StandardOutput.IndexOf("RUNNING", StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            currentValue = "FSRM service (SrmSvc) is installed and running";
                        }
                        else
                        {
                            currentValue = "FSRM service (SrmSvc) is installed but not running";
                        }
                    }
                }

                if (!fsrmInstalled)
                {
                    // Check via dism on server SKUs
                    var dismResult = ProcessHelper.RunCmd(
                        "dism /online /get-featureinfo /featurename:FS-Resource-Manager 2>nul");

                    if (dismResult.Success && dismResult.StandardOutput != null
                        && dismResult.StandardOutput.IndexOf("Enabled", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        fsrmInstalled = true;
                        currentValue = "FSRM Windows feature is enabled";
                    }
                    else if (dismResult.StandardOutput != null
                        && dismResult.StandardOutput.IndexOf("Disabled", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        currentValue = "FSRM Windows feature is available but disabled";
                    }
                }

                AddCheck(
                    "File Server Resource Manager",
                    "File Server Resource Manager (FSRM) should be installed for file classification, quota management, and data retention enforcement",
                    fsrmInstalled,
                    currentValue,
                    "FSRM installed and configured",
                    "Install FSRM via Server Manager: Add Roles and Features > File and Storage Services > File Server Resource Manager. Or via PowerShell: Install-WindowsFeature FS-Resource-Manager -IncludeManagementTools. Configure file classification and expiration rules.",
                    nist: Nist, cis: Cis, iso27001: Iso, gdpr: Gdpr, ccpa: Ccpa,
                    intuneRecommendation: "N/A - FSRM is a Windows Server feature. For endpoint data retention, use Devices > Configuration profiles to enforce Microsoft Information Protection labels and configure auto-expiration policies via Microsoft Purview."
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    "File Server Resource Manager",
                    "File Server Resource Manager (FSRM) should be installed for file classification, quota management, and data retention enforcement",
                    false,
                    "Error: " + ex.Message,
                    "FSRM installed and configured",
                    "Verify service query permissions and DISM access.",
                    nist: Nist, cis: Cis, iso27001: Iso, gdpr: Gdpr, ccpa: Ccpa
                );
            }
        }

        private void CheckSecureDeletionToolAvailable()
        {
            try
            {
                bool toolAvailable = false;
                string currentValue = "No secure deletion tool found";

                // Check for cipher.exe in System32 (built-in Windows tool for secure overwrite)
                string system32Path = Environment.GetFolderPath(Environment.SpecialFolder.System);
                string cipherPath = Path.Combine(system32Path, "cipher.exe");

                bool cipherExists = File.Exists(cipherPath);

                // Check for SDelete (Sysinternals) in common locations
                bool sdeleteExists = false;
                var sdeleteSearchPaths = new[]
                {
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "SysinternalsSuite", "sdelete.exe"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "SysinternalsSuite", "sdelete.exe"),
                    Path.Combine(system32Path, "sdelete.exe"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Sysinternals", "sdelete.exe"),
                    @"C:\Tools\sdelete.exe",
                    @"C:\SysinternalsSuite\sdelete.exe"
                };

                foreach (var sPath in sdeleteSearchPaths)
                {
                    if (File.Exists(sPath))
                    {
                        sdeleteExists = true;
                        break;
                    }
                }

                // Also check if sdelete is on PATH
                if (!sdeleteExists)
                {
                    var whereResult = ProcessHelper.RunCmd("where sdelete.exe 2>nul");
                    if (whereResult.Success && !string.IsNullOrWhiteSpace(whereResult.StandardOutput))
                    {
                        sdeleteExists = true;
                    }

                    // Also check for sdelete64
                    if (!sdeleteExists)
                    {
                        whereResult = ProcessHelper.RunCmd("where sdelete64.exe 2>nul");
                        if (whereResult.Success && !string.IsNullOrWhiteSpace(whereResult.StandardOutput))
                        {
                            sdeleteExists = true;
                        }
                    }
                }

                if (cipherExists && sdeleteExists)
                {
                    toolAvailable = true;
                    currentValue = "Both cipher.exe and sdelete.exe available";
                }
                else if (cipherExists)
                {
                    toolAvailable = true;
                    currentValue = "cipher.exe available (built-in); sdelete.exe not found";
                }
                else if (sdeleteExists)
                {
                    toolAvailable = true;
                    currentValue = "sdelete.exe available; cipher.exe not found";
                }

                AddCheck(
                    "Secure Deletion Tool Available",
                    "A secure deletion tool (cipher.exe or sdelete.exe) must be available for compliant data destruction",
                    toolAvailable,
                    currentValue,
                    "cipher.exe and/or sdelete.exe available",
                    "cipher.exe is included with Windows and supports /W switch for wiping free space. For file-level secure deletion, install Sysinternals SDelete: https://docs.microsoft.com/sysinternals/downloads/sdelete. Deploy via SCCM or Intune for enterprise-wide availability.",
                    nist: Nist, cis: Cis, iso27001: Iso, gdpr: Gdpr, ccpa: Ccpa,
                    intuneRecommendation: "Devices > Scripts > Deploy a PowerShell script to install SDelete or verify cipher.exe availability. Alternatively, use Intune Win32 app deployment to distribute Sysinternals SDelete across managed devices."
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    "Secure Deletion Tool Available",
                    "A secure deletion tool (cipher.exe or sdelete.exe) must be available for compliant data destruction",
                    false,
                    "Error: " + ex.Message,
                    "cipher.exe and/or sdelete.exe available",
                    "Verify file system access permissions.",
                    nist: Nist, cis: Cis, iso27001: Iso, gdpr: Gdpr, ccpa: Ccpa
                );
            }
        }

        private void CheckDiskCleanupScheduled()
        {
            try
            {
                bool scheduled = false;
                string currentValue = "No disk cleanup scheduled task detected";

                // Check for scheduled tasks related to disk cleanup
                var result = ProcessHelper.RunCmd(
                    "schtasks /query /fo CSV /nh 2>nul");

                if (result.Success && !string.IsNullOrWhiteSpace(result.StandardOutput))
                {
                    string output = result.StandardOutput;

                    bool hasCleanmgr = output.IndexOf("cleanmgr", StringComparison.OrdinalIgnoreCase) >= 0;
                    bool hasDiskCleanup = output.IndexOf("Disk Cleanup", StringComparison.OrdinalIgnoreCase) >= 0;
                    bool hasSilentCleanup = output.IndexOf("SilentCleanup", StringComparison.OrdinalIgnoreCase) >= 0;
                    bool hasStorageSense = output.IndexOf("StorageSense", StringComparison.OrdinalIgnoreCase) >= 0;

                    if (hasCleanmgr || hasDiskCleanup || hasSilentCleanup || hasStorageSense)
                    {
                        scheduled = true;
                        var detectedTasks = new System.Collections.Generic.List<string>();
                        if (hasCleanmgr) detectedTasks.Add("cleanmgr");
                        if (hasDiskCleanup) detectedTasks.Add("Disk Cleanup");
                        if (hasSilentCleanup) detectedTasks.Add("SilentCleanup");
                        if (hasStorageSense) detectedTasks.Add("Storage Sense");

                        currentValue = "Cleanup task(s) detected: " + string.Join(", ", detectedTasks);
                    }
                }

                // Also check if Storage Sense is enabled
                if (!scheduled)
                {
                    int storageSenseEnabled = RegistryHelper.GetDword(
                        @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy",
                        "01");

                    if (storageSenseEnabled == 1)
                    {
                        scheduled = true;
                        currentValue = "Storage Sense is enabled via user settings";
                    }
                }

                AddCheck(
                    "Disk Cleanup Scheduled",
                    "Automated disk cleanup must be scheduled to ensure regular removal of temporary and unnecessary data",
                    scheduled,
                    currentValue,
                    "Disk cleanup or Storage Sense scheduled",
                    "Enable Storage Sense via Settings > System > Storage > Storage Sense. Or create a scheduled task: schtasks /create /tn \"DiskCleanup\" /tr \"cleanmgr /sagerun:1\" /sc weekly /d MON /st 02:00. Configure cleanmgr preset via: cleanmgr /sageset:1.",
                    nist: Nist, cis: Cis, iso27001: Iso, gdpr: Gdpr, ccpa: Ccpa,
                    intuneRecommendation: "Devices > Configuration profiles > Settings catalog > Storage > 'Allow Storage Sense Global'. Set to 'Allowed' and configure cleanup cadence. Also configure 'Storage Sense Cloud Content Dehydration Threshold' for OneDrive-backed files."
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    "Disk Cleanup Scheduled",
                    "Automated disk cleanup must be scheduled to ensure regular removal of temporary and unnecessary data",
                    false,
                    "Error: " + ex.Message,
                    "Disk cleanup or Storage Sense scheduled",
                    "Verify access to scheduled tasks and registry.",
                    nist: Nist, cis: Cis, iso27001: Iso, gdpr: Gdpr, ccpa: Ccpa
                );
            }
        }

        private void CheckRecycleBinPolicy()
        {
            try
            {
                int noRecycleFiles = RegistryHelper.GetDword(
                    @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                    "NoRecycleFiles");

                int confirmFileDelete = RegistryHelper.GetDword(
                    @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                    "ConfirmFileDelete");

                bool passed = false;
                string currentValue;

                if (noRecycleFiles == 1)
                {
                    passed = true;
                    currentValue = "Recycle Bin bypassed - files are immediately deleted (NoRecycleFiles=1)";
                }
                else if (confirmFileDelete == 1)
                {
                    passed = true;
                    currentValue = "Delete confirmation enabled (ConfirmFileDelete=1)";
                }
                else
                {
                    currentValue = string.Format(
                        "NoRecycleFiles={0}, ConfirmFileDelete={1} - no enhanced deletion policy configured",
                        noRecycleFiles == -1 ? "Not Set" : noRecycleFiles.ToString(),
                        confirmFileDelete == -1 ? "Not Set" : confirmFileDelete.ToString());
                }

                AddCheck(
                    "Recycle Bin Policy",
                    "Recycle Bin must be configured with a data retention-aware policy (bypass or deletion confirmation)",
                    passed,
                    currentValue,
                    "NoRecycleFiles=1 or ConfirmFileDelete=1",
                    "Configure via Group Policy: User Configuration > Administrative Templates > Windows Components > File Explorer > Do not move deleted files to the Recycle Bin (set Enabled for immediate deletion). Or enable delete confirmation: right-click Recycle Bin > Properties > Display delete confirmation dialog.",
                    nist: Nist, cis: Cis, iso27001: Iso, gdpr: Gdpr, ccpa: Ccpa,
                    intuneRecommendation: "Devices > Configuration profiles > Settings catalog > Administrative Templates > File Explorer > 'Do not move deleted files to the Recycle Bin'. Set to 'Enabled' for environments requiring immediate data destruction compliance."
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    "Recycle Bin Policy",
                    "Recycle Bin must be configured with a data retention-aware policy (bypass or deletion confirmation)",
                    false,
                    "Error: " + ex.Message,
                    "NoRecycleFiles=1 or ConfirmFileDelete=1",
                    "Verify registry access to HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer.",
                    nist: Nist, cis: Cis, iso27001: Iso, gdpr: Gdpr, ccpa: Ccpa
                );
            }
        }
    }
}
