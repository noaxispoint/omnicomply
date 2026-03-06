using System;
using System.ComponentModel.Composition;
using System.IO;
using System.Text;
using OmniComply.Core.Helpers;
using OmniComply.Core.Interfaces;
using OmniComply.Core.Models;

namespace OmniComply.Remediation
{
    [Export(typeof(IRemediationAction))]
    public class PasswordPolicyRemediation : IRemediationAction
    {
        public string Name => "Password Policy Remediation";
        public string Description => "Configures password complexity, length, history, and account lockout policies";
        public string Category => "Access Controls";
        public bool RequiresReboot => false;

        public RemediationResult Execute()
        {
            string tempFile = Path.Combine(Path.GetTempPath(), "omnicomply_secpol_" + Guid.NewGuid().ToString("N") + ".cfg");

            try
            {
                // Create security template
                var template = new StringBuilder();
                template.AppendLine("[Unicode]");
                template.AppendLine("Unicode=yes");
                template.AppendLine("[System Access]");
                template.AppendLine("MinimumPasswordAge = 1");
                template.AppendLine("MaximumPasswordAge = 90");
                template.AppendLine("MinimumPasswordLength = 12");
                template.AppendLine("PasswordComplexity = 1");
                template.AppendLine("PasswordHistorySize = 12");
                template.AppendLine("LockoutBadCount = 5");
                template.AppendLine("ResetLockoutCount = 30");
                template.AppendLine("LockoutDuration = 30");
                template.AppendLine("[Version]");
                template.AppendLine("signature=\"$CHICAGO$\"");
                template.AppendLine("Revision=1");

                File.WriteAllText(tempFile, template.ToString(), Encoding.Unicode);

                // Apply the security policy
                var result = ProcessHelper.RunSecedit(string.Format("/configure /db secedit.sdb /cfg \"{0}\" /quiet", tempFile));

                if (result.ExitCode == 0)
                {
                    return RemediationResult.Succeeded(
                        "Password policies applied:\n" +
                        "  Minimum length: 12 characters\n" +
                        "  Complexity: Enabled\n" +
                        "  History: 12 passwords\n" +
                        "  Max age: 90 days\n" +
                        "  Lockout threshold: 5 attempts\n" +
                        "  Lockout duration: 30 minutes");
                }
                else
                {
                    return RemediationResult.Failed("secedit returned exit code: " + result.ExitCode, result.StandardError);
                }
            }
            finally
            {
                try { if (File.Exists(tempFile)) File.Delete(tempFile); } catch { }
            }
        }

        public RemediationResult DryRun()
        {
            return RemediationResult.Succeeded(
                "Would apply the following password policies:\n" +
                "  Minimum password length: 12 characters\n" +
                "  Password complexity: Enabled\n" +
                "  Password history: 12 passwords remembered\n" +
                "  Maximum password age: 90 days\n" +
                "  Minimum password age: 1 day\n" +
                "  Account lockout threshold: 5 invalid attempts\n" +
                "  Account lockout duration: 30 minutes\n" +
                "  Reset lockout counter: 30 minutes");
        }
    }
}
