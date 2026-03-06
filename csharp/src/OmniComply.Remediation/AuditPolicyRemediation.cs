using System.ComponentModel.Composition;
using System.Text;
using OmniComply.Core.Helpers;
using OmniComply.Core.Interfaces;
using OmniComply.Core.Models;

namespace OmniComply.Remediation
{
    [Export(typeof(IRemediationAction))]
    public class AuditPolicyRemediation : IRemediationAction
    {
        public string Name => "Audit Policy Remediation";
        public string Description => "Configures all required audit policies for multi-framework compliance";
        public string Category => "Audit Policy";
        public bool RequiresReboot => false;

        private static readonly string[] SuccessAndFailurePolicies = new[]
        {
            "Credential Validation", "Kerberos Authentication Service", "Kerberos Service Ticket Operations",
            "User Account Management", "Computer Account Management", "Security Group Management",
            "Distribution Group Management", "Application Group Management", "Other Account Management Events",
            "Logon", "Special Logon", "File System", "Registry", "Removable Storage", "Detailed File Share",
            "Audit Policy Change", "Authentication Policy Change", "Authorization Policy Change",
            "Sensitive Privilege Use", "Security State Change", "Security System Extension", "System Integrity"
        };

        public RemediationResult Execute()
        {
            var sb = new StringBuilder();
            int succeeded = 0;
            int failed = 0;

            foreach (var policy in SuccessAndFailurePolicies)
            {
                var result = ProcessHelper.RunAuditpol(string.Format("/set /subcategory:\"{0}\" /success:enable /failure:enable", policy));
                if (result.Success) succeeded++; else failed++;
            }

            // Special cases
            ProcessHelper.RunAuditpol("/set /subcategory:\"Logoff\" /success:enable");
            ProcessHelper.RunAuditpol("/set /subcategory:\"Account Lockout\" /failure:enable");
            ProcessHelper.RunAuditpol("/set /subcategory:\"Process Creation\" /success:enable");

            // Enable command line auditing
            RegistryHelper.SetDword(@"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit",
                "ProcessCreationIncludeCmdLine_Enabled", 1);

            // Enable advanced audit policy override
            RegistryHelper.SetDword(@"HKLM\System\CurrentControlSet\Control\Lsa",
                "SCENoApplyLegacyAuditPolicy", 1);

            sb.AppendFormat("Configured {0} audit policies successfully, {1} failed", succeeded, failed);

            return failed == 0
                ? RemediationResult.Succeeded(sb.ToString())
                : RemediationResult.Failed(sb.ToString());
        }

        public RemediationResult DryRun()
        {
            var sb = new StringBuilder();
            sb.AppendLine("Would configure the following audit policies to Success and Failure:");
            foreach (var policy in SuccessAndFailurePolicies)
                sb.AppendLine("  - " + policy);
            sb.AppendLine("Special: Logoff (Success only), Account Lockout (Failure only), Process Creation (Success only)");
            sb.AppendLine("Would enable command line process auditing");
            sb.AppendLine("Would enable advanced audit policy override");
            return RemediationResult.Succeeded(sb.ToString());
        }
    }
}
