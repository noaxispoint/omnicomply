using System;
using System.ComponentModel.Composition;
using System.ServiceProcess;
using OmniComply.Core.Engine;
using OmniComply.Core.Interfaces;
using OmniComply.Core.Helpers;

namespace OmniComply.Modules.SystemAndOps
{
    [Export(typeof(IComplianceModule))]
    [ExportMetadata("Name", "Backup Recovery")]
    [ExportMetadata("Category", "Backup Recovery")]
    [ExportMetadata("Order", 27)]
    public class BackupRecoveryModule : ComplianceModuleBase
    {
        public override string Name => "Backup Recovery";
        public override string Description => "Validates Windows backup service status, system restore configuration, Volume Shadow Copy service, and recovery options";
        public override string Category => "Backup Recovery";
        public override int Order => 27;

        private const string Nist = "CP-9, CP-10";
        private const string Cis = "11.2";
        private const string Iso = "A.12.3.1, A.17.1.1";
        private const string Sox = "ITGC-06";

        protected override void RunChecks()
        {
            CheckWindowsBackupService();
            CheckSystemRestoreEnabled();
            CheckVolumeShadowCopyService();
            CheckRecoveryOptions();
        }

        /// <summary>
        /// Checks whether a Windows Backup service (wbengine or SDRSVC) is running.
        /// wbengine is the Block Level Backup Engine Service; SDRSVC is the Windows Backup service.
        /// </summary>
        private void CheckWindowsBackupService()
        {
            bool wbengineRunning = false;
            bool sdrsvcRunning = false;
            string wbengineStatus = "Not Found";
            string sdrsvcStatus = "Not Found";

            try
            {
                using (var service = new ServiceController("wbengine"))
                {
                    wbengineRunning = service.Status == ServiceControllerStatus.Running;
                    wbengineStatus = service.Status.ToString();
                }
            }
            catch (InvalidOperationException)
            {
                wbengineStatus = "Not Installed";
            }

            try
            {
                using (var service = new ServiceController("SDRSVC"))
                {
                    sdrsvcRunning = service.Status == ServiceControllerStatus.Running;
                    sdrsvcStatus = service.Status.ToString();
                }
            }
            catch (InvalidOperationException)
            {
                sdrsvcStatus = "Not Installed";
            }

            bool passed = wbengineRunning || sdrsvcRunning;
            string currentValue = string.Format("wbengine: {0}, SDRSVC: {1}", wbengineStatus, sdrsvcStatus);

            AddCheck(
                check: "Windows Backup Service",
                requirement: "A Windows Backup service (wbengine or SDRSVC) must be available for system backup operations",
                passed: passed,
                currentValue: currentValue,
                expectedValue: "At least one backup service running (wbengine or SDRSVC)",
                remediation: "Install and enable Windows Server Backup feature: Install-WindowsFeature Windows-Server-Backup. Or start the backup engine service: Set-Service -Name wbengine -StartupType Manual; Start-Service -Name wbengine. For client systems, ensure Windows Backup is configured via Settings > Update & Security > Backup.",
                nist: Nist, cis: Cis, iso27001: Iso, sox: Sox,
                intuneRecommendation: "Devices > Configuration profiles > Create profile > Settings catalog. Configure backup policies and ensure backup services are enabled. For cloud backup, configure OneDrive Known Folder Move under Devices > Configuration profiles > OneDrive settings."
            );
        }

        /// <summary>
        /// Checks whether System Restore is enabled by verifying the RPSessionInterval
        /// registry value. A value of 0 means System Restore is disabled.
        /// </summary>
        private void CheckSystemRestoreEnabled()
        {
            const string regPath = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore";
            int rpSessionInterval = RegistryHelper.GetDword(regPath, "RPSessionInterval", -1);

            bool passed;
            string currentValue;

            if (rpSessionInterval == -1)
            {
                // Key not present; check if System Restore is disabled via DisableSR
                int disableSR = RegistryHelper.GetDword(regPath, "DisableSR", -1);
                if (disableSR == 1)
                {
                    passed = false;
                    currentValue = "System Restore explicitly disabled (DisableSR = 1)";
                }
                else
                {
                    passed = true;
                    currentValue = "RPSessionInterval not set (System Restore may be using defaults)";
                }
            }
            else if (rpSessionInterval == 0)
            {
                passed = false;
                currentValue = "System Restore disabled (RPSessionInterval = 0)";
            }
            else
            {
                passed = true;
                currentValue = string.Format("System Restore enabled (RPSessionInterval = {0})", rpSessionInterval);
            }

            AddCheck(
                check: "System Restore Enabled",
                requirement: "System Restore must be enabled to allow recovery from system configuration changes",
                passed: passed,
                currentValue: currentValue,
                expectedValue: "Enabled (RPSessionInterval != 0)",
                remediation: "Enable System Restore via: SystemPropertiesProtection.exe > Select system drive > Configure > Turn on system protection. Or via Group Policy: Computer Configuration > Administrative Templates > System > System Restore > Turn off System Restore = Disabled.",
                nist: Nist, cis: Cis, iso27001: Iso, sox: Sox,
                intuneRecommendation: "Devices > Configuration profiles > Create profile > Settings catalog. Search for 'System Restore' and ensure 'Turn off System Restore' is set to 'Disabled' (which enables System Restore). Alternatively, use PowerShell scripts deployed via Intune to enable System Restore on managed devices."
            );
        }

        /// <summary>
        /// Checks whether the Volume Shadow Copy Service (VSS) is running.
        /// VSS is required for system backup and restore point operations.
        /// </summary>
        private void CheckVolumeShadowCopyService()
        {
            try
            {
                using (var service = new ServiceController("VSS"))
                {
                    // VSS is typically set to Manual start and runs on demand.
                    // We check that the service exists and is not disabled.
                    bool serviceAvailable = service.Status == ServiceControllerStatus.Running ||
                                            service.StartType != ServiceStartMode.Disabled;

                    string currentValue = string.Format("Status: {0}, StartType: {1}",
                        service.Status, service.StartType);

                    AddCheck(
                        check: "Volume Shadow Copy Service (VSS)",
                        requirement: "Volume Shadow Copy Service must be available (not disabled) to support backup and restore operations",
                        passed: serviceAvailable,
                        currentValue: currentValue,
                        expectedValue: "Available (not disabled)",
                        remediation: "Ensure VSS is not disabled: Set-Service -Name VSS -StartupType Manual. VSS runs on demand and does not need to be continuously running. If disabled, restore with: sc config VSS start= demand.",
                        nist: Nist, cis: Cis, iso27001: Iso, sox: Sox,
                        intuneRecommendation: "Devices > Configuration profiles > Create profile > Settings catalog. Ensure the Volume Shadow Copy Service start type is not set to 'Disabled'. VSS is required for Windows backup functionality and system protection."
                    );
                }
            }
            catch (InvalidOperationException)
            {
                AddCheck(
                    check: "Volume Shadow Copy Service (VSS)",
                    requirement: "Volume Shadow Copy Service must be available (not disabled) to support backup and restore operations",
                    passed: false,
                    currentValue: "Service not found",
                    expectedValue: "Available (not disabled)",
                    remediation: "The VSS service is missing. Repair Windows system files: sfc /scannow and DISM /Online /Cleanup-Image /RestoreHealth.",
                    nist: Nist, cis: Cis, iso27001: Iso, sox: Sox,
                    intuneRecommendation: "Devices > Configuration profiles > Create profile > Settings catalog. Ensure the Volume Shadow Copy Service start type is not set to 'Disabled'. VSS is required for Windows backup functionality."
                );
            }
        }

        /// <summary>
        /// Checks whether a recovery partition exists on the system by looking for
        /// a partition with Type containing "Recovery" via WMI Win32_DiskPartition.
        /// </summary>
        private void CheckRecoveryOptions()
        {
            var partitions = WmiHelper.QueryAll("Win32_DiskPartition");
            bool recoveryPartitionFound = false;
            string recoveryInfo = "No recovery partition detected";

            foreach (var partition in partitions)
            {
                string partitionType = WmiHelper.GetPropertyString(partition, "Type");
                string partitionName = WmiHelper.GetPropertyString(partition, "Name");

                if (!string.IsNullOrWhiteSpace(partitionType) &&
                    partitionType.IndexOf("Recovery", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    recoveryPartitionFound = true;
                    long sizeBytes = WmiHelper.GetProperty(partition, "Size", 0L);
                    double sizeMb = sizeBytes / (1024.0 * 1024.0);
                    recoveryInfo = string.Format("Recovery partition found: {0} ({1:F0} MB)",
                        partitionName ?? "Unknown", sizeMb);
                    break;
                }
            }

            // Also check via reagentc-like approach: look for WinRE status in the BCD or registry
            if (!recoveryPartitionFound)
            {
                var reagentResult = ProcessHelper.RunCmd("reagentc /info");
                if (reagentResult.Success && !string.IsNullOrWhiteSpace(reagentResult.StandardOutput))
                {
                    string output = reagentResult.StandardOutput;
                    if (output.IndexOf("Enabled", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        recoveryPartitionFound = true;
                        recoveryInfo = "Windows Recovery Environment (WinRE) is enabled";
                    }
                    else if (output.IndexOf("Disabled", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        recoveryInfo = "Windows Recovery Environment (WinRE) is disabled";
                    }
                }
            }

            AddCheck(
                check: "Recovery Options",
                requirement: "A system recovery partition or Windows Recovery Environment must be available for disaster recovery",
                passed: recoveryPartitionFound,
                currentValue: recoveryInfo,
                expectedValue: "Recovery partition or WinRE available",
                remediation: "Enable Windows Recovery Environment: reagentc /enable. If the recovery partition is missing, it may need to be recreated using Windows installation media. For enterprise environments, configure WinPE-based recovery via deployment tools.",
                nist: Nist, cis: Cis, iso27001: Iso, sox: Sox,
                intuneRecommendation: "Devices > Compliance policies > Create policy > Windows 10 and later. Monitor device health status for recovery environment availability. Use Autopilot device reset capabilities for managed recovery scenarios."
            );
        }
    }
}
