using System;
using System.Collections.Generic;
using System.ComponentModel.Composition;
using System.Linq;
using OmniComply.Core.Engine;
using OmniComply.Core.Helpers;
using OmniComply.Core.Interfaces;

namespace OmniComply.Modules.AuditAndLogging
{
    [Export(typeof(IComplianceModule))]
    [ExportMetadata("Name", "Audit Policies")]
    [ExportMetadata("Category", "Audit Policy")]
    [ExportMetadata("Order", 1)]
    public class AuditPoliciesModule : ComplianceModuleBase
    {
        public override string Name => "Audit Policies";
        public override string Description => "Validates Advanced Audit Policy Configuration for SOC 2 and HIPAA compliance";
        public override string Category => "Audit Policy";
        public override int Order => 1;

        private class AuditPolicyDefinition
        {
            public string Subcategory { get; set; }
            public string Expected { get; set; }
            public string Requirement { get; set; }
            public string AuditCategory { get; set; }
            public string NIST { get; set; }
            public string CIS { get; set; }
            public string ISO27001 { get; set; }
            public string PCIDSS { get; set; }
            public string SOX { get; set; }
            public string GDPR { get; set; }
            public string CCPA { get; set; }
            public string IntuneRecommendation { get; set; }
        }

        protected override void RunChecks()
        {
            var requiredPolicies = BuildPolicyDefinitions();

            // Run auditpol to get current audit policy configuration in CSV format
            var result = ProcessHelper.RunAuditpol("/get /category:* /r");
            var auditLines = ParseCsvOutput(result.StandardOutput);

            foreach (var policy in requiredPolicies)
            {
                var matchingLine = auditLines.FirstOrDefault(line =>
                    string.Equals(GetField(line, "Subcategory"), policy.Subcategory, StringComparison.OrdinalIgnoreCase));

                if (matchingLine != null)
                {
                    var currentSetting = GetField(matchingLine, "Inclusion Setting");
                    var passed = string.Equals(currentSetting, policy.Expected, StringComparison.OrdinalIgnoreCase);

                    AddCheck(
                        check: policy.Subcategory,
                        requirement: policy.Requirement,
                        passed: passed,
                        currentValue: currentSetting ?? "Unknown",
                        expectedValue: policy.Expected,
                        remediation: string.Format("auditpol /set /subcategory:\"{0}\" /success:enable /failure:enable", policy.Subcategory),
                        nist: policy.NIST,
                        cis: policy.CIS,
                        iso27001: policy.ISO27001,
                        pciDss: policy.PCIDSS,
                        sox: policy.SOX,
                        gdpr: policy.GDPR,
                        ccpa: policy.CCPA,
                        intuneRecommendation: policy.IntuneRecommendation);
                }
                else
                {
                    AddCheck(
                        check: policy.Subcategory,
                        requirement: policy.Requirement,
                        passed: false,
                        currentValue: "Not Found",
                        expectedValue: policy.Expected,
                        remediation: string.Format("auditpol /set /subcategory:\"{0}\" /success:enable /failure:enable", policy.Subcategory),
                        nist: policy.NIST,
                        cis: policy.CIS,
                        iso27001: policy.ISO27001,
                        pciDss: policy.PCIDSS,
                        sox: policy.SOX,
                        gdpr: policy.GDPR,
                        ccpa: policy.CCPA,
                        intuneRecommendation: policy.IntuneRecommendation);
                }
            }
        }

        private List<AuditPolicyDefinition> BuildPolicyDefinitions()
        {
            return new List<AuditPolicyDefinition>
            {
                // Account Logon
                new AuditPolicyDefinition
                {
                    Subcategory = "Credential Validation",
                    Expected = "Success and Failure",
                    Requirement = "HIPAA \u00a7 164.312(b) - Audit Controls",
                    AuditCategory = "Account Logon",
                    NIST = "AU-2, AU-12, AC-7",
                    CIS = "8.2, 8.5",
                    ISO27001 = "A.9.4.2, A.12.4.1",
                    PCIDSS = "10.2.4, 10.2.5",
                    SOX = "ITGC-05",
                    IntuneRecommendation = "Devices > Configuration profiles > Create profile > Settings catalog > Local Policies Security Options > Audit: Audit the access of global system objects"
                },
                new AuditPolicyDefinition
                {
                    Subcategory = "Kerberos Authentication Service",
                    Expected = "Success and Failure",
                    Requirement = "HIPAA \u00a7 164.312(d) - Person or Entity Authentication",
                    AuditCategory = "Account Logon"
                },
                new AuditPolicyDefinition
                {
                    Subcategory = "Kerberos Service Ticket Operations",
                    Expected = "Success and Failure",
                    Requirement = "HIPAA \u00a7 164.312(d) - Person or Entity Authentication",
                    AuditCategory = "Account Logon"
                },

                // Account Management
                new AuditPolicyDefinition
                {
                    Subcategory = "User Account Management",
                    Expected = "Success and Failure",
                    Requirement = "SOC 2 CC6.2 - System Credentials / HIPAA \u00a7 164.308(a)(3)(ii)(A)",
                    AuditCategory = "Account Management",
                    NIST = "AC-2(4), AU-2",
                    CIS = "5.1, 5.2",
                    ISO27001 = "A.9.2.1, A.9.2.5",
                    PCIDSS = "8.1.1, 8.1.4, 10.2.5",
                    SOX = "ITGC-01"
                },
                new AuditPolicyDefinition
                {
                    Subcategory = "Computer Account Management",
                    Expected = "Success and Failure",
                    Requirement = "SOC 2 CC6.2 - System Credentials",
                    AuditCategory = "Account Management"
                },
                new AuditPolicyDefinition
                {
                    Subcategory = "Security Group Management",
                    Expected = "Success and Failure",
                    Requirement = "SOC 2 CC6.3 - Access Removal / HIPAA \u00a7 164.308(a)(4)(ii)(C)",
                    AuditCategory = "Account Management",
                    NIST = "AC-2(4), AU-2",
                    CIS = "5.4, 6.8",
                    ISO27001 = "A.9.2.5, A.9.4.4",
                    PCIDSS = "7.2.2, 10.2.5",
                    SOX = "ITGC-01"
                },
                new AuditPolicyDefinition
                {
                    Subcategory = "Distribution Group Management",
                    Expected = "Success and Failure",
                    Requirement = "SOC 2 CC6.3 - Access Removal",
                    AuditCategory = "Account Management"
                },
                new AuditPolicyDefinition
                {
                    Subcategory = "Application Group Management",
                    Expected = "Success and Failure",
                    Requirement = "SOC 2 CC6.3 - Access Removal",
                    AuditCategory = "Account Management"
                },
                new AuditPolicyDefinition
                {
                    Subcategory = "Other Account Management Events",
                    Expected = "Success and Failure",
                    Requirement = "SOC 2 CC6.2 - System Credentials",
                    AuditCategory = "Account Management"
                },

                // Logon/Logoff
                new AuditPolicyDefinition
                {
                    Subcategory = "Logon",
                    Expected = "Success and Failure",
                    Requirement = "HIPAA \u00a7 164.308(a)(5)(ii)(C) - Log-in Monitoring",
                    AuditCategory = "Logon/Logoff",
                    NIST = "AU-2, AC-7, AU-14",
                    CIS = "8.2, 8.3",
                    ISO27001 = "A.9.4.2, A.12.4.1",
                    PCIDSS = "10.2.4, 10.2.5",
                    SOX = "ITGC-05"
                },
                new AuditPolicyDefinition
                {
                    Subcategory = "Logoff",
                    Expected = "Success",
                    Requirement = "HIPAA \u00a7 164.308(a)(5)(ii)(C) - Log-in Monitoring",
                    AuditCategory = "Logon/Logoff"
                },
                new AuditPolicyDefinition
                {
                    Subcategory = "Account Lockout",
                    Expected = "Failure",
                    Requirement = "HIPAA \u00a7 164.308(a)(5)(ii)(C) - Log-in Monitoring",
                    AuditCategory = "Logon/Logoff"
                },
                new AuditPolicyDefinition
                {
                    Subcategory = "Special Logon",
                    Expected = "Success and Failure",
                    Requirement = "SOC 2 CC6.1 - Privileged Access Monitoring",
                    AuditCategory = "Logon/Logoff"
                },

                // Object Access
                new AuditPolicyDefinition
                {
                    Subcategory = "File System",
                    Expected = "Success and Failure",
                    Requirement = "HIPAA \u00a7 164.312(b) - Audit Controls (File Access)",
                    AuditCategory = "Object Access",
                    NIST = "AU-2, AU-12",
                    CIS = "8.5",
                    ISO27001 = "A.12.4.1, A.12.4.3",
                    PCIDSS = "10.2.1, 10.2.7",
                    SOX = "ITGC-04"
                },
                new AuditPolicyDefinition
                {
                    Subcategory = "Registry",
                    Expected = "Success and Failure",
                    Requirement = "SOC 2 CC7.2 - System Monitoring",
                    AuditCategory = "Object Access"
                },
                new AuditPolicyDefinition
                {
                    Subcategory = "Removable Storage",
                    Expected = "Success and Failure",
                    Requirement = "HIPAA \u00a7 164.312(b) - Audit Controls",
                    AuditCategory = "Object Access"
                },
                new AuditPolicyDefinition
                {
                    Subcategory = "Detailed File Share",
                    Expected = "Success and Failure",
                    Requirement = "HIPAA \u00a7 164.312(b) - Audit Controls (File Access)",
                    AuditCategory = "Object Access"
                },

                // Policy Change
                new AuditPolicyDefinition
                {
                    Subcategory = "Audit Policy Change",
                    Expected = "Success and Failure",
                    Requirement = "SOC 2 CC7.3 - Evaluation of Security Events",
                    AuditCategory = "Policy Change",
                    NIST = "AU-2, AU-6, CM-3",
                    CIS = "8.11",
                    ISO27001 = "A.12.4.1, A.12.4.4",
                    PCIDSS = "10.2.7, 10.5.5",
                    SOX = "ITGC-03"
                },
                new AuditPolicyDefinition
                {
                    Subcategory = "Authentication Policy Change",
                    Expected = "Success and Failure",
                    Requirement = "SOC 2 CC7.3 - Evaluation of Security Events",
                    AuditCategory = "Policy Change"
                },
                new AuditPolicyDefinition
                {
                    Subcategory = "Authorization Policy Change",
                    Expected = "Success and Failure",
                    Requirement = "SOC 2 CC7.3 - Evaluation of Security Events",
                    AuditCategory = "Policy Change"
                },

                // Privilege Use
                new AuditPolicyDefinition
                {
                    Subcategory = "Sensitive Privilege Use",
                    Expected = "Success and Failure",
                    Requirement = "SOC 2 CC6.1 - Logical Access Controls",
                    AuditCategory = "Privilege Use"
                },

                // System
                new AuditPolicyDefinition
                {
                    Subcategory = "Security State Change",
                    Expected = "Success and Failure",
                    Requirement = "SOC 2 CC7.2 - System Monitoring",
                    AuditCategory = "System"
                },
                new AuditPolicyDefinition
                {
                    Subcategory = "Security System Extension",
                    Expected = "Success and Failure",
                    Requirement = "SOC 2 CC7.2 - System Monitoring",
                    AuditCategory = "System"
                },
                new AuditPolicyDefinition
                {
                    Subcategory = "System Integrity",
                    Expected = "Success and Failure",
                    Requirement = "SOC 2 CC7.2 - System Monitoring",
                    AuditCategory = "System"
                },

                // Detailed Tracking
                new AuditPolicyDefinition
                {
                    Subcategory = "Process Creation",
                    Expected = "Success",
                    Requirement = "HIPAA \u00a7 164.312(b) - Audit Controls",
                    AuditCategory = "Detailed Tracking"
                }
            };
        }

        /// <summary>
        /// Parses the CSV output from auditpol /get /category:* /r into a list of dictionaries.
        /// Each dictionary maps header names to values for a single row.
        /// </summary>
        private static List<Dictionary<string, string>> ParseCsvOutput(string csvOutput)
        {
            var records = new List<Dictionary<string, string>>();
            if (string.IsNullOrWhiteSpace(csvOutput))
                return records;

            var lines = csvOutput.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

            // Find the header line (first non-empty line that contains commas)
            string[] headers = null;
            int dataStart = 0;

            for (int i = 0; i < lines.Length; i++)
            {
                var line = lines[i].Trim();
                if (line.Contains(",") && line.Contains("Subcategory"))
                {
                    headers = SplitCsvLine(line);
                    dataStart = i + 1;
                    break;
                }
            }

            if (headers == null)
                return records;

            for (int i = dataStart; i < lines.Length; i++)
            {
                var line = lines[i].Trim();
                if (string.IsNullOrWhiteSpace(line))
                    continue;

                var fields = SplitCsvLine(line);
                var record = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

                for (int j = 0; j < headers.Length && j < fields.Length; j++)
                {
                    record[headers[j]] = fields[j];
                }

                records.Add(record);
            }

            return records;
        }

        /// <summary>
        /// Splits a CSV line, handling quoted fields.
        /// </summary>
        private static string[] SplitCsvLine(string line)
        {
            var fields = new List<string>();
            bool inQuotes = false;
            var currentField = new System.Text.StringBuilder();

            foreach (char c in line)
            {
                if (c == '"')
                {
                    inQuotes = !inQuotes;
                }
                else if (c == ',' && !inQuotes)
                {
                    fields.Add(currentField.ToString().Trim());
                    currentField.Clear();
                }
                else
                {
                    currentField.Append(c);
                }
            }

            fields.Add(currentField.ToString().Trim());
            return fields.ToArray();
        }

        private static string GetField(Dictionary<string, string> record, string fieldName)
        {
            string value;
            return record.TryGetValue(fieldName, out value) ? value : null;
        }
    }
}
