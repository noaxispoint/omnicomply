using System;
using System.ComponentModel.Composition;
using System.ServiceProcess;
using OmniComply.Core.Engine;
using OmniComply.Core.Interfaces;

namespace OmniComply.Modules.AuditAndLogging
{
    [Export(typeof(IComplianceModule))]
    [ExportMetadata("Name", "Logging Services")]
    [ExportMetadata("Category", "Logging Services")]
    [ExportMetadata("Order", 4)]
    public class LoggingServicesModule : ComplianceModuleBase
    {
        public override string Name => "Logging Services";
        public override string Description => "Validates that required logging services are running and configured properly";
        public override string Category => "Logging Services";
        public override int Order => 4;

        protected override void RunChecks()
        {
            CheckEventLogService();
            CheckWinRMService();
            CheckTaskSchedulerService();
        }

        /// <summary>
        /// Checks Windows Event Log service status and startup type.
        /// </summary>
        private void CheckEventLogService()
        {
            try
            {
                using (var service = new ServiceController("EventLog"))
                {
                    bool serviceRunning = service.Status == ServiceControllerStatus.Running;

                    AddCheck(
                        check: "Windows Event Log Service Running",
                        requirement: "HIPAA \u00a7 164.312(b) - Audit Controls Active",
                        passed: serviceRunning,
                        currentValue: service.Status.ToString(),
                        expectedValue: "Running",
                        remediation: "Start-Service -Name EventLog",
                        nist: "AU-6",
                        cis: "8.2",
                        iso27001: "A.12.4.1",
                        sox: "ITGC-05");

                    // Check startup type
                    bool serviceAutomatic = service.StartType == ServiceStartMode.Automatic;

                    AddCheck(
                        check: "Windows Event Log Service Startup Type",
                        requirement: "SOC 2 CC7.2 - System Monitoring",
                        passed: serviceAutomatic,
                        currentValue: service.StartType.ToString(),
                        expectedValue: "Automatic",
                        remediation: "Set-Service -Name EventLog -StartupType Automatic",
                        nist: "AU-6",
                        cis: "8.2",
                        iso27001: "A.12.4.1",
                        sox: "ITGC-05");
                }
            }
            catch (InvalidOperationException)
            {
                AddCheck(
                    check: "Windows Event Log Service",
                    requirement: "HIPAA \u00a7 164.312(b) - Audit Controls",
                    passed: false,
                    currentValue: "Service not found",
                    expectedValue: "Service exists and running",
                    remediation: "Critical system service missing - reinstall Windows",
                    nist: "AU-6",
                    cis: "8.2",
                    iso27001: "A.12.4.1",
                    sox: "ITGC-05");
            }
        }

        /// <summary>
        /// Checks WinRM service status for event log forwarding capability.
        /// </summary>
        private void CheckWinRMService()
        {
            try
            {
                using (var service = new ServiceController("WinRM"))
                {
                    bool winrmRunning = service.Status == ServiceControllerStatus.Running;

                    AddCheck(
                        check: "WinRM Service (for log forwarding)",
                        requirement: "SOC 2 CC7.2 - Centralized Log Collection",
                        passed: winrmRunning,
                        currentValue: service.Status.ToString(),
                        expectedValue: "Running (if using WinRM forwarding)",
                        remediation: "Start-Service -Name WinRM; Enable-PSRemoting -Force",
                        nist: "AU-6, AU-9",
                        cis: "8.2",
                        iso27001: "A.12.4.1, A.12.4.2",
                        sox: "ITGC-05");
                }
            }
            catch (InvalidOperationException)
            {
                AddCheck(
                    check: "WinRM Service (for log forwarding)",
                    requirement: "SOC 2 CC7.2 - Centralized Log Collection",
                    passed: false,
                    currentValue: "Service not found",
                    expectedValue: "Running (if using WinRM forwarding)",
                    remediation: "Install and configure WinRM: winrm quickconfig",
                    nist: "AU-6, AU-9",
                    cis: "8.2",
                    iso27001: "A.12.4.1, A.12.4.2",
                    sox: "ITGC-05");
            }
        }

        /// <summary>
        /// Checks Task Scheduler service status for automated log review tasks.
        /// </summary>
        private void CheckTaskSchedulerService()
        {
            try
            {
                using (var service = new ServiceController("Schedule"))
                {
                    bool taskSchedulerRunning = service.Status == ServiceControllerStatus.Running;

                    AddCheck(
                        check: "Task Scheduler Service",
                        requirement: "HIPAA \u00a7 164.308(a)(1)(ii)(D) - Automated Log Review",
                        passed: taskSchedulerRunning,
                        currentValue: service.Status.ToString(),
                        expectedValue: "Running",
                        remediation: "Start-Service -Name Schedule",
                        nist: "AU-6",
                        cis: "8.2",
                        iso27001: "A.12.4.1",
                        sox: "ITGC-05");
                }
            }
            catch (InvalidOperationException)
            {
                AddCheck(
                    check: "Task Scheduler Service",
                    requirement: "HIPAA \u00a7 164.308(a)(1)(ii)(D) - Automated Log Review",
                    passed: false,
                    currentValue: "Service not found",
                    expectedValue: "Running",
                    remediation: "Verify Task Scheduler service is installed and start it: sc start Schedule",
                    nist: "AU-6",
                    cis: "8.2",
                    iso27001: "A.12.4.1",
                    sox: "ITGC-05");
            }
        }
    }
}
