using System.ComponentModel.Composition;
using System.Text;
using OmniComply.Core.Helpers;
using OmniComply.Core.Interfaces;
using OmniComply.Core.Models;

namespace OmniComply.Remediation
{
    [Export(typeof(IRemediationAction))]
    public class EventLogRemediation : IRemediationAction
    {
        public string Name => "Event Log Remediation";
        public string Description => "Configures event log sizes to meet compliance requirements";
        public string Category => "Event Log Configuration";
        public bool RequiresReboot => false;

        public RemediationResult Execute()
        {
            var sb = new StringBuilder();
            bool allSuccess = true;

            // Security log: 2GB
            var r1 = ProcessHelper.Run("wevtutil.exe", "sl Security /ms:2147483648");
            if (r1.Success)
                sb.AppendLine("Security log set to 2GB");
            else
            {
                sb.AppendLine("Failed to set Security log: " + r1.StandardError);
                allSuccess = false;
            }

            // Application log: 1GB
            var r2 = ProcessHelper.Run("wevtutil.exe", "sl Application /ms:1073741824");
            if (r2.Success)
                sb.AppendLine("Application log set to 1GB");
            else
            {
                sb.AppendLine("Failed to set Application log: " + r2.StandardError);
                allSuccess = false;
            }

            // System log: 1GB
            var r3 = ProcessHelper.Run("wevtutil.exe", "sl System /ms:1073741824");
            if (r3.Success)
                sb.AppendLine("System log set to 1GB");
            else
            {
                sb.AppendLine("Failed to set System log: " + r3.StandardError);
                allSuccess = false;
            }

            return allSuccess
                ? RemediationResult.Succeeded(sb.ToString())
                : RemediationResult.Failed(sb.ToString());
        }

        public RemediationResult DryRun()
        {
            return RemediationResult.Succeeded(
                "Would set:\n  Security log: 2GB (2,147,483,648 bytes)\n  Application log: 1GB (1,073,741,824 bytes)\n  System log: 1GB (1,073,741,824 bytes)");
        }
    }
}
