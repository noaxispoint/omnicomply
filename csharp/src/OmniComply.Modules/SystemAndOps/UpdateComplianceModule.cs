using System;
using System.Collections.Generic;
using System.ComponentModel.Composition;
using System.Management;
using OmniComply.Core.Engine;
using OmniComply.Core.Interfaces;
using OmniComply.Core.Helpers;
using System.ServiceProcess;

namespace OmniComply.Modules.SystemAndOps
{
    [Export(typeof(IComplianceModule))]
    [ExportMetadata("Name", "Update Compliance")]
    [ExportMetadata("Category", "Update Compliance")]
    [ExportMetadata("Order", 10)]
    public class UpdateComplianceModule : ComplianceModuleBase
    {
        public override string Name => "Update Compliance";
        public override string Description => "Validates Windows Update service status, auto-update configuration, recent patch installation, and OS version support";
        public override string Category => "Update Compliance";
        public override int Order => 10;

        private const string Nist = "SI-2, CM-3";
        private const string Cis = "7.1";
        private const string Iso = "A.12.6.1";
        private const string PciDss = "6.2";
        private const string Sox = "ITGC-03";

        protected override void RunChecks()
        {
            CheckWindowsUpdateServiceRunning();
            CheckAutoUpdateEnabled();
            CheckRecentUpdatesInstalled();
            CheckOsVersionSupport();
        }

        /// <summary>
        /// Checks whether the Windows Update service (wuauserv) is running.
        /// </summary>
        private void CheckWindowsUpdateServiceRunning()
        {
            try
            {
                using (var service = new ServiceController("wuauserv"))
                {
                    bool serviceRunning = service.Status == ServiceControllerStatus.Running;

                    AddCheck(
                        check: "Windows Update Service Running",
                        requirement: "Windows Update service must be running to ensure timely patch delivery",
                        passed: serviceRunning,
                        currentValue: service.Status.ToString(),
                        expectedValue: "Running",
                        remediation: "Start the Windows Update service: Set-Service -Name wuauserv -StartupType Automatic; Start-Service -Name wuauserv. Or via Group Policy: Computer Configuration > Administrative Templates > Windows Components > Windows Update.",
                        nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss, sox: Sox,
                        intuneRecommendation: "Devices > Windows > Update rings for Windows 10 and later > Create profile. Ensure the update ring is assigned to all target devices and the service channel is configured appropriately."
                    );
                }
            }
            catch (InvalidOperationException)
            {
                AddCheck(
                    check: "Windows Update Service Running",
                    requirement: "Windows Update service must be running to ensure timely patch delivery",
                    passed: false,
                    currentValue: "Service not found",
                    expectedValue: "Running",
                    remediation: "The Windows Update service (wuauserv) is missing. Restore the service by running: sc create wuauserv binPath= \"%systemroot%\\system32\\svchost.exe -k netsvcs\" start= auto, or repair Windows with sfc /scannow and DISM /Online /Cleanup-Image /RestoreHealth.",
                    nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss, sox: Sox,
                    intuneRecommendation: "Devices > Windows > Update rings for Windows 10 and later > Create profile. Ensure the update ring is assigned to all target devices and the service channel is configured appropriately."
                );
            }
        }

        /// <summary>
        /// Checks whether automatic updates are enabled via Group Policy registry key.
        /// NoAutoUpdate == 0 (or key not present) means auto-update is enabled.
        /// </summary>
        private void CheckAutoUpdateEnabled()
        {
            const string regPath = @"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU";
            int noAutoUpdate = RegistryHelper.GetDword(regPath, "NoAutoUpdate", -1);

            // If the key does not exist (-1), auto-update is enabled by default.
            // If the value is 0, auto-update is explicitly enabled.
            // If the value is 1, auto-update is explicitly disabled.
            bool passed = noAutoUpdate == 0 || noAutoUpdate == -1;
            string currentValue;

            if (noAutoUpdate == -1)
                currentValue = "Not Configured (defaults to enabled)";
            else if (noAutoUpdate == 0)
                currentValue = "Enabled (NoAutoUpdate = 0)";
            else
                currentValue = "Disabled (NoAutoUpdate = " + noAutoUpdate + ")";

            AddCheck(
                check: "Auto-Update Enabled",
                requirement: "Windows automatic updates must be enabled to ensure critical patches are applied promptly",
                passed: passed,
                currentValue: currentValue,
                expectedValue: "Enabled (NoAutoUpdate = 0 or not configured)",
                remediation: "Enable automatic updates via Group Policy: Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates > Enabled. Or set registry: reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU\" /v NoAutoUpdate /t REG_DWORD /d 0 /f",
                nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss, sox: Sox,
                intuneRecommendation: "Devices > Windows > Update rings for Windows 10 and later > Create profile. Set 'Automatic update behavior' to 'Auto install at maintenance time' or 'Auto install and restart at scheduled time'. Configure active hours to minimize user disruption."
            );
        }

        /// <summary>
        /// Checks whether any hotfixes have been installed within the last 30 days
        /// using the Win32_QuickFixEngineering WMI class.
        /// </summary>
        private void CheckRecentUpdatesInstalled()
        {
            var hotfixes = WmiHelper.QueryAll("Win32_QuickFixEngineering");

            bool hasRecentUpdate = false;
            string mostRecentHotFixId = "None found";
            string mostRecentDateStr = "N/A";
            DateTime mostRecentDate = DateTime.MinValue;

            foreach (var hotfix in hotfixes)
            {
                string installedOnStr = WmiHelper.GetPropertyString(hotfix, "InstalledOn");
                string hotFixId = WmiHelper.GetPropertyString(hotfix, "HotFixID");

                if (!string.IsNullOrWhiteSpace(installedOnStr))
                {
                    DateTime installedOn;
                    if (DateTime.TryParse(installedOnStr, out installedOn))
                    {
                        if (installedOn > mostRecentDate)
                        {
                            mostRecentDate = installedOn;
                            mostRecentHotFixId = hotFixId ?? "Unknown";
                            mostRecentDateStr = installedOn.ToString("yyyy-MM-dd");
                        }
                    }
                }
            }

            if (mostRecentDate != DateTime.MinValue)
            {
                double daysSinceUpdate = (DateTime.Now - mostRecentDate).TotalDays;
                hasRecentUpdate = daysSinceUpdate <= 30;
                mostRecentDateStr = string.Format("{0} ({1} - {2:F0} days ago)",
                    mostRecentHotFixId, mostRecentDate.ToString("yyyy-MM-dd"), daysSinceUpdate);
            }

            AddCheck(
                check: "Recent Updates Installed",
                requirement: "System must have received updates within the last 30 days to maintain security posture",
                passed: hasRecentUpdate,
                currentValue: mostRecentDateStr,
                expectedValue: "Update installed within 30 days",
                remediation: "Run Windows Update immediately: Settings > Update & Security > Windows Update > Check for updates. Or via PowerShell: Install-Module PSWindowsUpdate; Get-WindowsUpdate -Install -AcceptAll.",
                nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss, sox: Sox,
                intuneRecommendation: "Devices > Windows > Update rings for Windows 10 and later > Create profile. Set 'Quality update deferral period' to '0' days for critical updates. Configure 'Feature update deferral period' based on organizational testing requirements."
            );
        }

        /// <summary>
        /// Checks whether the OS build version is still within a supported lifecycle.
        /// Windows 10 builds prior to 19041 (version 2004) are considered end-of-life.
        /// </summary>
        private void CheckOsVersionSupport()
        {
            var os = WmiHelper.QueryFirst("Win32_OperatingSystem");

            bool supported = false;
            string currentValue = "Unable to determine OS version";

            if (os != null)
            {
                string version = WmiHelper.GetPropertyString(os, "Version");
                string caption = WmiHelper.GetPropertyString(os, "Caption");

                if (!string.IsNullOrWhiteSpace(version))
                {
                    currentValue = string.Format("{0} (Version: {1})", caption ?? "Windows", version);

                    // Parse the build number from the version string (e.g., "10.0.19041")
                    string[] parts = version.Split('.');
                    int buildNumber = 0;

                    if (parts.Length >= 3 && int.TryParse(parts[2], out buildNumber))
                    {
                        // Windows 10 builds prior to 19041 are end-of-life
                        // Windows 11 builds (22000+) are supported
                        supported = buildNumber >= 19041;
                    }
                    else
                    {
                        currentValue = string.Format("{0} (Version: {1} - unable to parse build)", caption ?? "Windows", version);
                    }
                }
            }

            AddCheck(
                check: "OS Version Support",
                requirement: "Operating system must be a supported version that receives security updates",
                passed: supported,
                currentValue: currentValue,
                expectedValue: "Windows 10 build 19041+ or Windows 11",
                remediation: "Upgrade to a supported Windows version. End-of-life operating systems no longer receive security patches. Use Windows Update Assistant or Media Creation Tool to upgrade to the latest supported version.",
                nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss, sox: Sox,
                intuneRecommendation: "Devices > Compliance policies > Create policy > Windows 10 and later. Under 'Device Properties', set 'Minimum OS version' to a supported build (e.g., 10.0.19041). Non-compliant devices will be flagged and can be blocked from accessing corporate resources via Conditional Access."
            );
        }
    }
}
