using System;
using System.Collections.Generic;
using System.ComponentModel.Composition;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using OmniComply.Core.Engine;
using OmniComply.Core.Helpers;
using OmniComply.Core.Interfaces;

namespace OmniComply.Modules.AuditAndLogging
{
    [Export(typeof(IComplianceModule))]
    [ExportMetadata("Name", "File System Auditing")]
    [ExportMetadata("Category", "File System Auditing")]
    [ExportMetadata("Order", 3)]
    public class FileSystemAuditingModule : ComplianceModuleBase
    {
        public override string Name => "File System Auditing";
        public override string Description => "Validates file system auditing configuration including SACL and detailed file share auditing";
        public override string Category => "File System Auditing";
        public override int Order => 3;

        protected override void RunChecks()
        {
            CheckObjectAccessAuditPolicy();
            CheckSaclConfiguration();
            CheckDetailedFileShareAuditing();
        }

        /// <summary>
        /// Checks if Object Access auditing is enabled for the File System subcategory.
        /// </summary>
        private void CheckObjectAccessAuditPolicy()
        {
            var result = ProcessHelper.RunAuditpol("/get /subcategory:\"File System\" /r");
            bool objectAccessEnabled = false;

            if (result.Success && !string.IsNullOrWhiteSpace(result.StandardOutput))
            {
                var lines = result.StandardOutput.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

                foreach (var line in lines)
                {
                    if (line.IndexOf("File System", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        // Check if the Inclusion Setting contains Success or Failure
                        string inclusionSetting = ExtractInclusionSetting(line, lines);
                        if (!string.IsNullOrEmpty(inclusionSetting) &&
                            (inclusionSetting.IndexOf("Success", StringComparison.OrdinalIgnoreCase) >= 0 ||
                             inclusionSetting.IndexOf("Failure", StringComparison.OrdinalIgnoreCase) >= 0))
                        {
                            objectAccessEnabled = true;
                        }
                        break;
                    }
                }
            }

            if (objectAccessEnabled)
            {
                AddCheck(
                    check: "Object Access Policy Enabled",
                    requirement: "HIPAA \u00a7 164.312(b) - File Access Auditing",
                    passed: true,
                    currentValue: "Enabled",
                    expectedValue: "Enabled",
                    remediation: "N/A",
                    nist: "AU-2, AU-12",
                    cis: "8.2",
                    iso27001: "A.12.4.1",
                    sox: "ITGC-05");
            }
            else
            {
                AddCheck(
                    check: "Object Access Policy Enabled",
                    requirement: "HIPAA \u00a7 164.312(b) - File Access Auditing",
                    passed: false,
                    currentValue: "Disabled or Partial",
                    expectedValue: "Success and Failure",
                    remediation: "auditpol /set /subcategory:\"File System\" /success:enable /failure:enable",
                    nist: "AU-2, AU-12",
                    cis: "8.2",
                    iso27001: "A.12.4.1",
                    sox: "ITGC-05");
            }
        }

        /// <summary>
        /// Checks SACL configuration on sensitive folders.
        /// </summary>
        private void CheckSaclConfiguration()
        {
            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string publicDocuments = Environment.GetFolderPath(Environment.SpecialFolder.CommonDocuments);

            var sensitiveFolders = new List<string>
            {
                Path.Combine(userProfile, "Documents"),
                !string.IsNullOrEmpty(publicDocuments) ? publicDocuments : @"C:\Users\Public\Documents",
                @"C:\ProgramData"
            };

            int saclCount = 0;
            int foldersChecked = 0;

            foreach (var folder in sensitiveFolders)
            {
                if (!Directory.Exists(folder))
                    continue;

                foldersChecked++;

                try
                {
                    var directoryInfo = new DirectoryInfo(folder);
                    var security = directoryInfo.GetAccessControl(AccessControlSections.Audit);
                    var auditRules = security.GetAuditRules(true, true, typeof(System.Security.Principal.NTAccount));

                    if (auditRules.Count > 0)
                    {
                        saclCount++;
                    }
                }
                catch
                {
                    // Unable to read SACL - may require elevated privileges
                }
            }

            bool saclsConfigured = saclCount > 0;

            AddCheck(
                check: "SACL Configuration on Sensitive Folders",
                requirement: "HIPAA \u00a7 164.312(b) - Audit Controls for File Access",
                passed: saclsConfigured,
                currentValue: string.Format("{0} of {1} checked folders have auditing", saclCount, foldersChecked),
                expectedValue: "Auditing configured on folders containing ePHI/sensitive data",
                remediation: "Configure SACLs using icacls or PowerShell Set-Acl with audit rules",
                nist: "AU-2, AU-9",
                cis: "8.2",
                iso27001: "A.12.4.1, A.12.4.3",
                sox: "ITGC-05");
        }

        /// <summary>
        /// Checks if Detailed File Share auditing is enabled via auditpol.
        /// </summary>
        private void CheckDetailedFileShareAuditing()
        {
            var result = ProcessHelper.RunAuditpol("/get /subcategory:\"Detailed File Share\" /r");
            bool fileSharePassed = false;

            if (result.Success && !string.IsNullOrWhiteSpace(result.StandardOutput))
            {
                var lines = result.StandardOutput.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

                foreach (var line in lines)
                {
                    if (line.IndexOf("Detailed File Share", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        string inclusionSetting = ExtractInclusionSetting(line, lines);
                        if (!string.IsNullOrEmpty(inclusionSetting) &&
                            inclusionSetting.IndexOf("Success and Failure", StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            fileSharePassed = true;
                        }
                        break;
                    }
                }
            }

            AddCheck(
                check: "Detailed File Share Auditing",
                requirement: "HIPAA \u00a7 164.312(b) - Network Share Access Auditing",
                passed: fileSharePassed,
                currentValue: fileSharePassed ? "Enabled" : "Not Fully Enabled",
                expectedValue: "Success and Failure",
                remediation: "auditpol /set /subcategory:\"Detailed File Share\" /success:enable /failure:enable",
                nist: "AU-2, AU-12",
                cis: "8.2",
                iso27001: "A.12.4.1, A.13.1.1",
                sox: "ITGC-05");
        }

        /// <summary>
        /// Extracts the Inclusion Setting from auditpol CSV output.
        /// The /r format outputs CSV with headers in the first data line.
        /// </summary>
        private static string ExtractInclusionSetting(string dataLine, string[] allLines)
        {
            // Find the header line
            string[] headers = null;
            int headerIndex = -1;

            for (int i = 0; i < allLines.Length; i++)
            {
                if (allLines[i].IndexOf("Subcategory", StringComparison.OrdinalIgnoreCase) >= 0 &&
                    allLines[i].Contains(","))
                {
                    headers = allLines[i].Split(',');
                    headerIndex = i;
                    break;
                }
            }

            if (headers == null)
                return null;

            // Find the Inclusion Setting column index
            int inclusionIndex = -1;
            for (int i = 0; i < headers.Length; i++)
            {
                if (headers[i].Trim().Equals("Inclusion Setting", StringComparison.OrdinalIgnoreCase))
                {
                    inclusionIndex = i;
                    break;
                }
            }

            if (inclusionIndex < 0)
                return null;

            var fields = dataLine.Split(',');
            if (inclusionIndex < fields.Length)
            {
                return fields[inclusionIndex].Trim();
            }

            return null;
        }
    }
}
