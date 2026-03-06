using System;
using System.Collections.Generic;
using System.ComponentModel.Composition;
using System.Management;
using OmniComply.Core.Engine;
using OmniComply.Core.Helpers;
using OmniComply.Core.Interfaces;

namespace OmniComply.Modules.AuditAndLogging
{
    [Export(typeof(IComplianceModule))]
    [ExportMetadata("Name", "Event Log Configuration")]
    [ExportMetadata("Category", "Event Log Configuration")]
    [ExportMetadata("Order", 2)]
    public class EventLogConfigurationModule : ComplianceModuleBase
    {
        public override string Name => "Event Log Configuration";
        public override string Description => "Validates event log sizes, retention policies, and availability for SOC 2 and HIPAA compliance";
        public override string Category => "Event Log Configuration";
        public override int Order => 2;

        private static readonly string EventLogRegistryBase = @"HKLM\SYSTEM\CurrentControlSet\Services\EventLog";

        private class LogConfigDefinition
        {
            public string LogName { get; set; }
            public int MinSizeKB { get; set; }
            public string Requirement { get; set; }
            public string NIST { get; set; }
            public string CIS { get; set; }
            public string ISO27001 { get; set; }
            public string SOX { get; set; }
        }

        protected override void RunChecks()
        {
            var requiredLogConfigs = new List<LogConfigDefinition>
            {
                new LogConfigDefinition
                {
                    LogName = "Security",
                    MinSizeKB = 2097152,  // 2 GB in KB
                    Requirement = "HIPAA \u00a7 164.308(a)(1)(ii)(D) - Sufficient log retention",
                    NIST = "AU-4, AU-11",
                    CIS = "8.3",
                    ISO27001 = "A.12.4.1, A.12.4.2",
                    SOX = "ITGC-05"
                },
                new LogConfigDefinition
                {
                    LogName = "Application",
                    MinSizeKB = 1048576,  // 1 GB in KB
                    Requirement = "SOC 2 CC7.2 - System Monitoring",
                    NIST = "AU-4, AU-11",
                    CIS = "8.3",
                    ISO27001 = "A.12.4.1",
                    SOX = "ITGC-05"
                },
                new LogConfigDefinition
                {
                    LogName = "System",
                    MinSizeKB = 1048576,  // 1 GB in KB
                    Requirement = "SOC 2 CC7.2 - System Monitoring",
                    NIST = "AU-4, AU-11",
                    CIS = "8.3",
                    ISO27001 = "A.12.4.1",
                    SOX = "ITGC-05"
                }
            };

            foreach (var logConfig in requiredLogConfigs)
            {
                CheckLogSize(logConfig);
                CheckLogEnabled(logConfig);
                CheckRetentionMode(logConfig);
            }

            CheckSecurityLogActivity();
        }

        private void CheckLogSize(LogConfigDefinition logConfig)
        {
            string registryPath = string.Format(@"{0}\{1}", EventLogRegistryBase, logConfig.LogName);

            // MaxSize is stored in bytes in the registry
            int maxSizeBytes = RegistryHelper.GetDword(registryPath, "MaxSize", -1);

            if (maxSizeBytes > 0)
            {
                int currentSizeKB = maxSizeBytes / 1024;
                bool passed = currentSizeKB >= logConfig.MinSizeKB;

                AddCheck(
                    check: string.Format("{0} Log Size", logConfig.LogName),
                    requirement: logConfig.Requirement,
                    passed: passed,
                    currentValue: string.Format("{0} KB", currentSizeKB),
                    expectedValue: string.Format("Minimum {0} KB", logConfig.MinSizeKB),
                    remediation: string.Format("wevtutil sl {0} /ms:{1}", logConfig.LogName, (long)logConfig.MinSizeKB * 1024),
                    nist: logConfig.NIST,
                    cis: logConfig.CIS,
                    iso27001: logConfig.ISO27001,
                    sox: logConfig.SOX,
                    intuneRecommendation: string.Format(
                        "Devices > Configuration profiles > Create profile > Settings catalog > Administrative Templates > Windows Components > Event Log Service > {0} > Specify the maximum log file size (KB) = {1}",
                        logConfig.LogName, logConfig.MinSizeKB));
            }
            else
            {
                AddCheck(
                    check: string.Format("{0} Log Size", logConfig.LogName),
                    requirement: logConfig.Requirement,
                    passed: false,
                    currentValue: "Unable to read MaxSize from registry",
                    expectedValue: string.Format("Minimum {0} KB", logConfig.MinSizeKB),
                    remediation: string.Format("wevtutil sl {0} /ms:{1}", logConfig.LogName, (long)logConfig.MinSizeKB * 1024),
                    nist: logConfig.NIST,
                    cis: logConfig.CIS,
                    iso27001: logConfig.ISO27001,
                    sox: logConfig.SOX);
            }
        }

        private void CheckLogEnabled(LogConfigDefinition logConfig)
        {
            string registryPath = string.Format(@"{0}\{1}", EventLogRegistryBase, logConfig.LogName);

            // Check if the log key exists - its existence along with valid File value indicates the log is configured
            bool keyExists = RegistryHelper.KeyExists(registryPath);
            string filePath = RegistryHelper.GetString(registryPath, "File", null);
            bool logEnabled = keyExists && !string.IsNullOrEmpty(filePath);

            AddCheck(
                check: string.Format("{0} Log Enabled", logConfig.LogName),
                requirement: logConfig.Requirement,
                passed: logEnabled,
                currentValue: logEnabled ? "True" : "False",
                expectedValue: "True",
                remediation: string.Format("wevtutil sl {0} /e:true", logConfig.LogName),
                nist: logConfig.NIST,
                cis: logConfig.CIS,
                iso27001: logConfig.ISO27001,
                sox: logConfig.SOX);
        }

        private void CheckRetentionMode(LogConfigDefinition logConfig)
        {
            string registryPath = string.Format(@"{0}\{1}", EventLogRegistryBase, logConfig.LogName);

            // Retention: 0 = Overwrite as needed (Circular), -1 = Do not overwrite (Archive), positive = AutoBackup days
            int retention = RegistryHelper.GetDword(registryPath, "Retention", -999);
            string autoBackupLogFiles = RegistryHelper.GetString(registryPath, "AutoBackupLogFiles", "0");

            string retentionMode;
            bool retentionGood;

            if (retention == 0)
            {
                retentionMode = "Circular";
                retentionGood = true;
            }
            else if (string.Equals(autoBackupLogFiles, "1", StringComparison.OrdinalIgnoreCase) || retention > 0)
            {
                retentionMode = "AutoBackup";
                retentionGood = true;
            }
            else if (retention == -1)
            {
                retentionMode = "DoNotOverwrite";
                retentionGood = false;
            }
            else
            {
                retentionMode = "Unknown";
                retentionGood = false;
            }

            AddCheck(
                check: string.Format("{0} Retention Policy", logConfig.LogName),
                requirement: logConfig.Requirement,
                passed: retentionGood,
                currentValue: retentionMode,
                expectedValue: "Circular or AutoBackup",
                remediation: "Configure via Group Policy or wevtutil",
                nist: logConfig.NIST,
                cis: logConfig.CIS,
                iso27001: logConfig.ISO27001,
                sox: logConfig.SOX);
        }

        private void CheckSecurityLogActivity()
        {
            bool logsActive = false;
            string currentValue;

            try
            {
                // Query for recent security events using WMI
                var events = WmiHelper.QueryAll(
                    "Win32_NTLogEvent WHERE Logfile='Security'");

                if (events != null && events.Count > 0)
                {
                    // Check if we have any events at all - presence indicates active logging
                    var firstEvent = events[0];
                    string timeGenerated = WmiHelper.GetPropertyString(firstEvent, "TimeGenerated");

                    if (!string.IsNullOrEmpty(timeGenerated))
                    {
                        // WMI datetime format: yyyyMMddHHmmss.ffffff+zzz
                        // Parse the date portion to verify recency
                        DateTime eventTime;
                        if (TryParseWmiDateTime(timeGenerated, out eventTime))
                        {
                            logsActive = eventTime > DateTime.Now.AddDays(-1);
                            currentValue = logsActive
                                ? "Events found in last 24 hours"
                                : string.Format("Most recent event: {0}", eventTime.ToString("yyyy-MM-dd HH:mm:ss"));
                        }
                        else
                        {
                            // Events exist but date parsing failed; treat as active
                            logsActive = true;
                            currentValue = "Events found in Security log";
                        }
                    }
                    else
                    {
                        logsActive = true;
                        currentValue = "Events found in Security log";
                    }
                }
                else
                {
                    currentValue = "No events found in Security log";
                }
            }
            catch (Exception ex)
            {
                currentValue = string.Format("Unable to verify: {0}", ex.Message);
            }

            AddCheck(
                check: "Security Log Activity",
                requirement: "HIPAA \u00a7 164.312(b) - Audit Controls Active",
                passed: logsActive,
                currentValue: currentValue,
                expectedValue: "Events logged within 24 hours",
                remediation: "Verify audit policies are enabled and Event Log service is running",
                nist: "AU-6",
                cis: "8.2",
                iso27001: "A.12.4.1",
                sox: "ITGC-05");
        }

        /// <summary>
        /// Attempts to parse a WMI datetime string (yyyyMMddHHmmss.ffffff+zzz format).
        /// </summary>
        private static bool TryParseWmiDateTime(string wmiDateTime, out DateTime result)
        {
            result = DateTime.MinValue;

            if (string.IsNullOrEmpty(wmiDateTime) || wmiDateTime.Length < 14)
                return false;

            try
            {
                int year = int.Parse(wmiDateTime.Substring(0, 4));
                int month = int.Parse(wmiDateTime.Substring(4, 2));
                int day = int.Parse(wmiDateTime.Substring(6, 2));
                int hour = int.Parse(wmiDateTime.Substring(8, 2));
                int minute = int.Parse(wmiDateTime.Substring(10, 2));
                int second = int.Parse(wmiDateTime.Substring(12, 2));

                result = new DateTime(year, month, day, hour, minute, second, DateTimeKind.Local);
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
