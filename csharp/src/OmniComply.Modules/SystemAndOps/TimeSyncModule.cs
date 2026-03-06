using System;
using System.ComponentModel.Composition;
using System.ServiceProcess;
using OmniComply.Core.Engine;
using OmniComply.Core.Interfaces;
using OmniComply.Core.Helpers;

namespace OmniComply.Modules.SystemAndOps
{
    [Export(typeof(IComplianceModule))]
    [ExportMetadata("Name", "Time Sync")]
    [ExportMetadata("Category", "Time Synchronization")]
    [ExportMetadata("Order", 16)]
    public class TimeSyncModule : ComplianceModuleBase
    {
        public override string Name => "Time Sync";
        public override string Description => "Validates Windows Time service status, NTP server configuration, and time synchronization type";
        public override string Category => "Time Synchronization";
        public override int Order => 16;

        private const string Nist = "AU-8";
        private const string Cis = "2.3.17";
        private const string Iso = "A.12.4.4";
        private const string PciDss = "10.4";

        protected override void RunChecks()
        {
            CheckWindowsTimeService();
            CheckNtpConfigured();
            CheckTimeSyncType();
        }

        /// <summary>
        /// Checks whether the Windows Time service (W32Time) is running.
        /// </summary>
        private void CheckWindowsTimeService()
        {
            try
            {
                using (var service = new ServiceController("W32Time"))
                {
                    bool serviceRunning = service.Status == ServiceControllerStatus.Running;

                    AddCheck(
                        check: "Windows Time Service Running",
                        requirement: "Windows Time service (W32Time) must be running to maintain accurate system clock synchronization",
                        passed: serviceRunning,
                        currentValue: service.Status.ToString(),
                        expectedValue: "Running",
                        remediation: "Start the Windows Time service: Set-Service -Name W32Time -StartupType Automatic; Start-Service -Name W32Time. Or via command line: sc config W32Time start= auto && net start W32Time.",
                        nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss,
                        intuneRecommendation: "Devices > Configuration profiles > Create profile > Settings catalog. Search for 'Windows Time Service' and configure the W32Time service to start automatically. Assign the profile to all managed devices."
                    );
                }
            }
            catch (InvalidOperationException)
            {
                AddCheck(
                    check: "Windows Time Service Running",
                    requirement: "Windows Time service (W32Time) must be running to maintain accurate system clock synchronization",
                    passed: false,
                    currentValue: "Service not found",
                    expectedValue: "Running",
                    remediation: "The Windows Time service is missing. Register it with: w32tm /register, then start it: net start W32Time.",
                    nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss,
                    intuneRecommendation: "Devices > Configuration profiles > Create profile > Settings catalog. Search for 'Windows Time Service' and configure the W32Time service to start automatically. Assign the profile to all managed devices."
                );
            }
        }

        /// <summary>
        /// Checks whether an NTP server is configured in the registry.
        /// The NtpServer value should not be empty. The default "time.windows.com" is acceptable
        /// but an organization should configure a reliable NTP source.
        /// </summary>
        private void CheckNtpConfigured()
        {
            const string regPath = @"HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Parameters";
            string ntpServer = RegistryHelper.GetString(regPath, "NtpServer");

            bool passed = !string.IsNullOrWhiteSpace(ntpServer);
            string currentValue;

            if (string.IsNullOrWhiteSpace(ntpServer))
            {
                currentValue = "Not Configured";
            }
            else
            {
                currentValue = ntpServer;
            }

            AddCheck(
                check: "NTP Server Configured",
                requirement: "An NTP time source must be configured to ensure accurate and consistent timestamps across systems",
                passed: passed,
                currentValue: currentValue,
                expectedValue: "NTP server configured (e.g., time.windows.com or organizational NTP server)",
                remediation: "Configure an NTP server: w32tm /config /manualpeerlist:\"time.nist.gov,0x1 time.windows.com,0x1\" /syncfromflags:manual /reliable:YES /update. Then restart the service: net stop W32Time && net start W32Time.",
                nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss,
                intuneRecommendation: "Devices > Configuration profiles > Create profile > Settings catalog. Search for 'NTP Server' and configure 'W32Time > NtpServer' with your organizational time servers. Use ADMX-backed policies for NTP configuration."
            );
        }

        /// <summary>
        /// Checks whether the time synchronization type is set to "NTP" or "NT5DS".
        /// NTP is used for standalone/workgroup systems; NT5DS is used for domain-joined systems.
        /// </summary>
        private void CheckTimeSyncType()
        {
            const string regPath = @"HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Parameters";
            string syncType = RegistryHelper.GetString(regPath, "Type");

            bool passed = false;
            string currentValue;

            if (string.IsNullOrWhiteSpace(syncType))
            {
                currentValue = "Not Configured";
            }
            else
            {
                currentValue = syncType;
                passed = string.Equals(syncType, "NTP", StringComparison.OrdinalIgnoreCase) ||
                         string.Equals(syncType, "NT5DS", StringComparison.OrdinalIgnoreCase);
            }

            AddCheck(
                check: "Time Sync Type",
                requirement: "Time synchronization type must be set to NTP (standalone) or NT5DS (domain-joined) for reliable clock synchronization",
                passed: passed,
                currentValue: currentValue,
                expectedValue: "NTP or NT5DS",
                remediation: "Configure the time sync type: For standalone systems: w32tm /config /syncfromflags:manual /update. For domain-joined systems: w32tm /config /syncfromflags:domhier /update. Then restart: net stop W32Time && net start W32Time.",
                nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss,
                intuneRecommendation: "Devices > Configuration profiles > Create profile > Settings catalog. Configure W32Time parameters: set 'Type' to 'NTP' for workgroup devices or 'NT5DS' for hybrid Azure AD joined devices that should sync from the domain hierarchy."
            );
        }
    }
}
