using System;
using System.ComponentModel.Composition;
using OmniComply.Core.Engine;
using OmniComply.Core.Interfaces;
using OmniComply.Core.Helpers;

namespace OmniComply.Modules.Privacy
{
    [Export(typeof(IComplianceModule))]
    [ExportMetadata("Name", "Data Integrity")]
    [ExportMetadata("Category", "Data Integrity")]
    [ExportMetadata("Order", 35)]
    public class DataIntegrityModule : ComplianceModuleBase
    {
        public override string Name => "Data Integrity";
        public override string Description => "Validates event log integrity, NTFS journaling, Windows Event Forwarding, and file integrity monitoring";
        public override string Category => "Data Integrity";
        public override int Order => 35;

        private const string Nist = "SI-7, AU-9";
        private const string Cis = "8.11";
        private const string Iso = "A.12.4.1, A.14.1.2";
        private const string Gdpr = "Article 32.1.b";
        private const string Ccpa = "\u00a7 1798.150";

        protected override void RunChecks()
        {
            CheckEventLogIntegrity();
            CheckNtfsJournaling();
            CheckWindowsEventForwarding();
            CheckFileIntegrityMonitoring();
        }

        private void CheckEventLogIntegrity()
        {
            try
            {
                int restrictGuestAccess = RegistryHelper.GetDword(
                    @"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Security",
                    "RestrictGuestAccess");

                bool passed = restrictGuestAccess == 1;
                string currentValue;

                if (restrictGuestAccess == 1)
                {
                    currentValue = "Guest access to Security event log is restricted (RestrictGuestAccess=1)";
                }
                else if (restrictGuestAccess == 0)
                {
                    currentValue = "Guest access to Security event log is NOT restricted (RestrictGuestAccess=0)";
                }
                else
                {
                    currentValue = "RestrictGuestAccess not configured (value: " + restrictGuestAccess + ")";
                }

                // Additionally check if the event log file has restricted permissions
                string logFile = RegistryHelper.GetString(
                    @"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Security",
                    "File");

                if (!string.IsNullOrEmpty(logFile))
                {
                    currentValue += "; Log file: " + logFile;
                }

                AddCheck(
                    "Event Log Integrity Protection",
                    "Security event log must restrict guest access to prevent unauthorized log viewing or tampering",
                    passed,
                    currentValue,
                    "RestrictGuestAccess=1",
                    "Set registry value: HKLM\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Security\\RestrictGuestAccess = 1. Also ensure the Security event log file has restricted NTFS permissions allowing access only to SYSTEM and local Administrators.",
                    nist: Nist, cis: Cis, iso27001: Iso, gdpr: Gdpr, ccpa: Ccpa,
                    intuneRecommendation: "Devices > Configuration profiles > Settings catalog > Event Log Service > Security > 'Restrict Guest Access' = Enabled. Also configure maximum log size and retention policies under Event Log Service settings."
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    "Event Log Integrity Protection",
                    "Security event log must restrict guest access to prevent unauthorized log viewing or tampering",
                    false,
                    "Error: " + ex.Message,
                    "RestrictGuestAccess=1",
                    "Verify registry access to HKLM\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Security.",
                    nist: Nist, cis: Cis, iso27001: Iso, gdpr: Gdpr, ccpa: Ccpa
                );
            }
        }

        private void CheckNtfsJournaling()
        {
            try
            {
                bool journalActive = false;
                string currentValue = "Unable to query USN journal";

                var result = ProcessHelper.RunCmd("fsutil usn queryjournal C:");

                if (result.Success && !string.IsNullOrWhiteSpace(result.StandardOutput))
                {
                    string output = result.StandardOutput;

                    // If the command succeeds, the USN journal is active
                    if (output.IndexOf("Usn Journal ID", StringComparison.OrdinalIgnoreCase) >= 0
                        || output.IndexOf("Journal Id", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        journalActive = true;

                        // Extract journal size if available
                        string maxSize = "Unknown";
                        var lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                        foreach (var line in lines)
                        {
                            if (line.IndexOf("Maximum Size", StringComparison.OrdinalIgnoreCase) >= 0
                                || line.IndexOf("MaximumSize", StringComparison.OrdinalIgnoreCase) >= 0)
                            {
                                maxSize = line.Trim();
                                break;
                            }
                        }

                        currentValue = "USN Journal active on C: drive; " + maxSize;
                    }
                    else if (output.IndexOf("not active", StringComparison.OrdinalIgnoreCase) >= 0
                        || output.IndexOf("disabled", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        currentValue = "USN Journal is not active on C: drive";
                    }
                    else
                    {
                        currentValue = "USN Journal status unclear from fsutil output";
                    }
                }
                else if (!string.IsNullOrEmpty(result.StandardError))
                {
                    // Common error: access denied or not NTFS
                    if (result.StandardError.IndexOf("Access is denied", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        currentValue = "Access denied when querying USN journal (requires elevation)";
                    }
                    else
                    {
                        currentValue = "fsutil error: " + result.StandardError.Trim();
                    }
                }

                AddCheck(
                    "NTFS USN Journal Active",
                    "The NTFS Update Sequence Number (USN) journal must be active for file change tracking and integrity monitoring",
                    journalActive,
                    currentValue,
                    "USN Journal active on system drive",
                    "Enable the USN journal on C: drive via: fsutil usn createjournal m=33554432 a=4194304 C: (creates a 32MB journal). The USN journal is typically enabled by default on NTFS volumes.",
                    nist: Nist, cis: Cis, iso27001: Iso, gdpr: Gdpr, ccpa: Ccpa,
                    intuneRecommendation: "Devices > Scripts > Deploy a PowerShell proactive remediation script to verify USN journal status on managed devices and create the journal if missing."
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    "NTFS USN Journal Active",
                    "The NTFS Update Sequence Number (USN) journal must be active for file change tracking and integrity monitoring",
                    false,
                    "Error: " + ex.Message,
                    "USN Journal active on system drive",
                    "Verify fsutil.exe accessibility and ensure the scanner runs with administrative privileges.",
                    nist: Nist, cis: Cis, iso27001: Iso, gdpr: Gdpr, ccpa: Ccpa
                );
            }
        }

        private void CheckWindowsEventForwarding()
        {
            try
            {
                bool wefRunning = false;
                string currentValue = "Windows Event Collector service (Wecsvc) not detected";

                var result = ProcessHelper.RunCmd("sc query Wecsvc");

                if (result.Success && !string.IsNullOrWhiteSpace(result.StandardOutput))
                {
                    string output = result.StandardOutput;

                    if (output.IndexOf("RUNNING", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        wefRunning = true;
                        currentValue = "Windows Event Collector service (Wecsvc) is running";
                    }
                    else if (output.IndexOf("STOPPED", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        currentValue = "Windows Event Collector service (Wecsvc) is installed but stopped";
                    }
                    else if (output.IndexOf("START_PENDING", StringComparison.OrdinalIgnoreCase) >= 0
                        || output.IndexOf("STOP_PENDING", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        currentValue = "Windows Event Collector service (Wecsvc) is in a pending state";
                    }
                }
                else
                {
                    // Check if the service exists but query failed
                    bool serviceExists = RegistryHelper.KeyExists(
                        @"HKLM\SYSTEM\CurrentControlSet\Services\Wecsvc");

                    if (serviceExists)
                    {
                        currentValue = "Wecsvc service exists in registry but could not be queried";
                    }
                }

                AddCheck(
                    "Windows Event Forwarding",
                    "Windows Event Collector service must be running for centralized event log aggregation and integrity monitoring",
                    wefRunning,
                    currentValue,
                    "Wecsvc service running",
                    "Enable and start the Windows Event Collector service: wecutil qc /q. Or via services.msc: find 'Windows Event Collector' and set startup type to Automatic. Configure subscriptions with: wecutil cs <subscription.xml>.",
                    nist: Nist, cis: Cis, iso27001: Iso, gdpr: Gdpr, ccpa: Ccpa,
                    intuneRecommendation: "Devices > Configuration profiles > Settings catalog > Event Log Service > Configure Windows Event Forwarding. For cloud-native forwarding, configure Microsoft Defender for Endpoint or Microsoft Sentinel agent for centralized log collection."
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    "Windows Event Forwarding",
                    "Windows Event Collector service must be running for centralized event log aggregation and integrity monitoring",
                    false,
                    "Error: " + ex.Message,
                    "Wecsvc service running",
                    "Verify service query permissions.",
                    nist: Nist, cis: Cis, iso27001: Iso, gdpr: Gdpr, ccpa: Ccpa
                );
            }
        }

        private void CheckFileIntegrityMonitoring()
        {
            try
            {
                bool fimDetected = false;
                string currentValue = "No file integrity monitoring detected";

                // Check for Windows System File Checker (SFC) scheduled task
                var schtaskResult = ProcessHelper.RunCmd(
                    "schtasks /query /fo CSV /nh 2>nul");

                bool sfcScheduled = false;
                if (schtaskResult.Success && !string.IsNullOrWhiteSpace(schtaskResult.StandardOutput))
                {
                    sfcScheduled = schtaskResult.StandardOutput.IndexOf("sfc", StringComparison.OrdinalIgnoreCase) >= 0
                        || schtaskResult.StandardOutput.IndexOf("System File Checker", StringComparison.OrdinalIgnoreCase) >= 0;
                }

                // Check Component Based Servicing (CBS) - indicates Windows integrity checking is active
                bool cbsActive = RegistryHelper.KeyExists(
                    @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing");

                // Check for last SFC scan results in CBS log
                bool cbsLogExists = false;
                string cbsLogPath = Environment.ExpandEnvironmentVariables(
                    @"%SystemRoot%\Logs\CBS\CBS.log");

                var cbsLogCheck = ProcessHelper.RunCmd(
                    string.Format("if exist \"{0}\" echo FOUND", cbsLogPath));

                if (cbsLogCheck.StandardOutput != null
                    && cbsLogCheck.StandardOutput.IndexOf("FOUND", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    cbsLogExists = true;
                }

                // Check for third-party FIM tools (OSSEC, Wazuh, Tripwire)
                bool thirdPartyFim = false;
                var fimServices = new[]
                {
                    "OssecSvc", "WazuhSvc", "wazuh-agent",
                    "Tripwire Enterprise Agent", "twdaemon"
                };

                foreach (var service in fimServices)
                {
                    var svcResult = ProcessHelper.RunCmd(string.Format("sc query \"{0}\" 2>nul", service));
                    if (svcResult.Success && svcResult.StandardOutput != null
                        && (svcResult.StandardOutput.IndexOf("RUNNING", StringComparison.OrdinalIgnoreCase) >= 0
                            || svcResult.StandardOutput.IndexOf("STOPPED", StringComparison.OrdinalIgnoreCase) >= 0))
                    {
                        thirdPartyFim = true;
                        currentValue = "Third-party FIM detected: " + service;
                        break;
                    }
                }

                if (thirdPartyFim)
                {
                    fimDetected = true;
                }
                else if (sfcScheduled && cbsActive)
                {
                    fimDetected = true;
                    currentValue = "SFC scheduled task detected; Component Based Servicing active";
                }
                else if (cbsActive && cbsLogExists)
                {
                    fimDetected = true;
                    currentValue = "Component Based Servicing active with CBS log present";
                }
                else
                {
                    var details = new System.Collections.Generic.List<string>();
                    if (cbsActive) details.Add("CBS registry key exists");
                    if (cbsLogExists) details.Add("CBS.log present");
                    if (sfcScheduled) details.Add("SFC task scheduled");

                    if (details.Count > 0)
                    {
                        currentValue = "Partial integrity monitoring: " + string.Join(", ", details);
                    }
                }

                AddCheck(
                    "File Integrity Monitoring",
                    "File integrity monitoring must be in place via SFC, Component Based Servicing, or a third-party FIM solution",
                    fimDetected,
                    currentValue,
                    "File integrity monitoring active",
                    "Schedule regular SFC scans: schtasks /create /tn \"SFC_Scan\" /tr \"sfc /scannow\" /sc weekly /d SUN /st 03:00 /ru SYSTEM. For enterprise environments, deploy a dedicated FIM solution (OSSEC, Wazuh, Tripwire) or enable Microsoft Defender for Endpoint tamper protection.",
                    nist: Nist, cis: Cis, iso27001: Iso, gdpr: Gdpr, ccpa: Ccpa,
                    intuneRecommendation: "Endpoint Security > Endpoint detection and response > Configure Microsoft Defender for Endpoint. Enable 'Tamper Protection' under Endpoint Security > Antivirus. For advanced FIM, integrate with Microsoft Sentinel for file change tracking alerts."
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    "File Integrity Monitoring",
                    "File integrity monitoring must be in place via SFC, Component Based Servicing, or a third-party FIM solution",
                    false,
                    "Error: " + ex.Message,
                    "File integrity monitoring active",
                    "Verify scheduled task query permissions and registry access.",
                    nist: Nist, cis: Cis, iso27001: Iso, gdpr: Gdpr, ccpa: Ccpa
                );
            }
        }
    }
}
