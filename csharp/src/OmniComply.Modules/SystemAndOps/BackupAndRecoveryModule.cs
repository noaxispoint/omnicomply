using System;
using System.ComponentModel.Composition;
using System.ServiceProcess;
using OmniComply.Core.Engine;
using OmniComply.Core.Interfaces;
using OmniComply.Core.Helpers;

namespace OmniComply.Modules.SystemAndOps
{
    [Export(typeof(IComplianceModule))]
    [ExportMetadata("Name", "Backup And Recovery")]
    [ExportMetadata("Category", "Backup And Recovery")]
    [ExportMetadata("Order", 28)]
    public class BackupAndRecoveryModule : ComplianceModuleBase
    {
        public override string Name => "Backup And Recovery";
        public override string Description => "Validates system restore point availability, VSS shadow storage configuration, and recovery partition presence";
        public override string Category => "Backup And Recovery";
        public override int Order => 28;

        private const string Nist = "CP-9, CP-10";
        private const string Cis = "11.2";
        private const string Iso = "A.12.3.1, A.17.1.1";

        protected override void RunChecks()
        {
            CheckSystemRestorePoints();
            CheckVssConfiguration();
            CheckRecoveryPartition();
        }

        /// <summary>
        /// Checks for existing system restore points (shadow copies) using "vssadmin list shadows".
        /// The presence of shadow copies indicates that backup snapshots are being maintained.
        /// </summary>
        private void CheckSystemRestorePoints()
        {
            var result = ProcessHelper.RunCmd("vssadmin list shadows");

            bool hasShadowCopies = false;
            int shadowCount = 0;
            string currentValue;

            if (result.Success && !string.IsNullOrWhiteSpace(result.StandardOutput))
            {
                string output = result.StandardOutput;
                string[] lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

                foreach (string line in lines)
                {
                    if (line.TrimStart().StartsWith("Shadow Copy ID:", StringComparison.OrdinalIgnoreCase))
                    {
                        shadowCount++;
                    }
                }

                hasShadowCopies = shadowCount > 0;

                if (hasShadowCopies)
                {
                    // Try to find the most recent shadow copy creation date
                    string latestDate = "Unknown";
                    for (int i = lines.Length - 1; i >= 0; i--)
                    {
                        string trimmed = lines[i].TrimStart();
                        if (trimmed.StartsWith("Creation Time:", StringComparison.OrdinalIgnoreCase) ||
                            trimmed.StartsWith("Contained", StringComparison.OrdinalIgnoreCase))
                        {
                            continue;
                        }
                        // Look for lines with date-like content following "Shadow Copy Volume:"
                        if (trimmed.IndexOf("Creation", StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            int colonIndex = trimmed.IndexOf(':');
                            if (colonIndex >= 0 && colonIndex < trimmed.Length - 1)
                            {
                                latestDate = trimmed.Substring(colonIndex + 1).Trim();
                                break;
                            }
                        }
                    }

                    currentValue = string.Format("{0} shadow copy/copies found (most recent: {1})", shadowCount, latestDate);
                }
                else
                {
                    currentValue = "No shadow copies found";
                }
            }
            else if (!string.IsNullOrWhiteSpace(result.StandardError) &&
                     result.StandardError.IndexOf("No items found", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                currentValue = "No shadow copies found (vssadmin returned no items)";
            }
            else if (!result.Success)
            {
                currentValue = "Unable to query shadow copies: " + (result.StandardError ?? "vssadmin command failed");
                // Treat as not passed but don't fail hard; may need elevation
            }
            else
            {
                currentValue = "No shadow copies found";
            }

            AddCheck(
                check: "System Restore Points",
                requirement: "System restore points (shadow copies) should exist to enable point-in-time recovery",
                passed: hasShadowCopies,
                currentValue: currentValue,
                expectedValue: "At least one shadow copy present",
                remediation: "Create a system restore point: Checkpoint-Computer -Description \"Manual Restore Point\" -RestorePointType MODIFY_SETTINGS. Or enable System Protection and configure automatic restore point creation via SystemPropertiesProtection.exe.",
                nist: Nist, cis: Cis, iso27001: Iso,
                intuneRecommendation: "Devices > Configuration profiles > Create profile > Settings catalog. Enable System Protection and configure restore point creation. Deploy PowerShell scripts via Intune to create periodic restore points on managed devices."
            );
        }

        /// <summary>
        /// Checks VSS shadow storage configuration using "vssadmin list shadowstorage".
        /// Verifies that shadow storage is allocated and the VSS service is properly configured.
        /// </summary>
        private void CheckVssConfiguration()
        {
            bool vssServiceAvailable = false;
            string vssServiceStatus = "Unknown";

            try
            {
                using (var service = new ServiceController("VSS"))
                {
                    vssServiceAvailable = service.StartType != ServiceStartMode.Disabled;
                    vssServiceStatus = string.Format("Status: {0}, StartType: {1}",
                        service.Status, service.StartType);
                }
            }
            catch (InvalidOperationException)
            {
                vssServiceStatus = "Service not found";
            }

            // Check shadow storage allocation
            var storageResult = ProcessHelper.RunCmd("vssadmin list shadowstorage");
            bool hasStorageAllocated = false;
            string storageInfo = "No shadow storage configured";

            if (storageResult.Success && !string.IsNullOrWhiteSpace(storageResult.StandardOutput))
            {
                string output = storageResult.StandardOutput;

                if (output.IndexOf("Shadow Copy Storage", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    output.IndexOf("Used Shadow Copy Storage", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    hasStorageAllocated = true;

                    // Extract storage details
                    string[] lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                    string usedStorage = null;
                    string maxStorage = null;

                    foreach (string line in lines)
                    {
                        string trimmed = line.Trim();
                        if (trimmed.StartsWith("Used Shadow Copy Storage space:", StringComparison.OrdinalIgnoreCase))
                        {
                            int colonIndex = trimmed.LastIndexOf(':');
                            if (colonIndex >= 0)
                                usedStorage = trimmed.Substring(colonIndex + 1).Trim();
                        }
                        else if (trimmed.StartsWith("Maximum Shadow Copy Storage space:", StringComparison.OrdinalIgnoreCase))
                        {
                            int colonIndex = trimmed.LastIndexOf(':');
                            if (colonIndex >= 0)
                                maxStorage = trimmed.Substring(colonIndex + 1).Trim();
                        }
                    }

                    storageInfo = string.Format("Shadow storage allocated (Used: {0}, Max: {1})",
                        usedStorage ?? "Unknown", maxStorage ?? "Unknown");
                }
            }
            else if (!storageResult.Success)
            {
                storageInfo = "Unable to query shadow storage: " + (storageResult.StandardError ?? "command failed");
            }

            bool passed = vssServiceAvailable && hasStorageAllocated;
            string currentValue = string.Format("VSS Service: {0}; Storage: {1}", vssServiceStatus, storageInfo);

            AddCheck(
                check: "VSS Configuration",
                requirement: "Volume Shadow Copy Service must be available and shadow storage must be allocated for backup operations",
                passed: passed,
                currentValue: currentValue,
                expectedValue: "VSS service available and shadow storage allocated",
                remediation: "Configure VSS shadow storage: vssadmin resize shadowstorage /for=C: /on=C: /maxsize=10%. Ensure VSS service is not disabled: Set-Service -Name VSS -StartupType Manual. Enable system protection: Enable-ComputerRestore -Drive \"C:\\\".",
                nist: Nist, cis: Cis, iso27001: Iso,
                intuneRecommendation: "Devices > Configuration profiles > Create profile > Settings catalog. Ensure VSS service is not disabled. Deploy configuration scripts via Intune to set appropriate shadow storage limits on managed devices."
            );
        }

        /// <summary>
        /// Checks for the presence of a recovery partition using WMI Win32_DiskPartition
        /// to look for partitions with a recovery type.
        /// </summary>
        private void CheckRecoveryPartition()
        {
            var partitions = WmiHelper.QueryAll("Win32_DiskPartition");
            bool recoveryFound = false;
            string currentValue = "No recovery partition detected";

            foreach (var partition in partitions)
            {
                string partitionType = WmiHelper.GetPropertyString(partition, "Type");
                string partitionName = WmiHelper.GetPropertyString(partition, "Name");
                bool bootable = WmiHelper.GetProperty(partition, "Bootable", false);

                if (!string.IsNullOrWhiteSpace(partitionType) &&
                    partitionType.IndexOf("Recovery", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    recoveryFound = true;
                    long sizeBytes = WmiHelper.GetProperty(partition, "Size", 0L);
                    double sizeMb = sizeBytes / (1024.0 * 1024.0);
                    currentValue = string.Format("Recovery partition found: {0} (Type: {1}, Size: {2:F0} MB)",
                        partitionName ?? "Unknown", partitionType, sizeMb);
                    break;
                }
            }

            // If no recovery partition found via type, check for GPT recovery GUID-based partitions
            if (!recoveryFound)
            {
                // Fallback: check WinRE status via reagentc
                var reagentResult = ProcessHelper.RunCmd("reagentc /info");
                if (reagentResult.Success && !string.IsNullOrWhiteSpace(reagentResult.StandardOutput))
                {
                    string output = reagentResult.StandardOutput;
                    if (output.IndexOf("Enabled", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        recoveryFound = true;
                        currentValue = "Windows Recovery Environment (WinRE) enabled via reagentc";
                    }
                    else
                    {
                        currentValue = "Windows Recovery Environment (WinRE) is disabled or not configured";
                    }
                }
            }

            AddCheck(
                check: "Recovery Partition",
                requirement: "A recovery partition must be present on the system to enable disaster recovery and system restoration",
                passed: recoveryFound,
                currentValue: currentValue,
                expectedValue: "Recovery partition present",
                remediation: "If the recovery partition is missing, enable WinRE: reagentc /enable. If WinRE files are missing, use Windows installation media to repair: DISM /Online /Cleanup-Image /RestoreHealth. For enterprise deployments, include the recovery partition in the base OS image.",
                nist: Nist, cis: Cis, iso27001: Iso,
                intuneRecommendation: "Devices > Compliance policies > Create policy > Windows 10 and later. Monitor device health for recovery environment status. Use Windows Autopilot and automated device provisioning to ensure recovery partitions are maintained during OS deployments."
            );
        }
    }
}
