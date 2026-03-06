using System.ComponentModel.Composition;
using System.Text;
using OmniComply.Core.Helpers;
using OmniComply.Core.Interfaces;
using OmniComply.Core.Models;

namespace OmniComply.Remediation
{
    [Export(typeof(IRemediationAction))]
    public class WindowsDefenderRemediation : IRemediationAction
    {
        public string Name => "Windows Defender Remediation";
        public string Description => "Enables Windows Defender protections and configures firewall";
        public string Category => "Endpoint Security";
        public bool RequiresReboot => false;

        public RemediationResult Execute()
        {
            var sb = new StringBuilder();

            // Use PowerShell to configure Defender (Set-MpPreference requires PS)
            RunPsCommand("Set-MpPreference -DisableRealtimeMonitoring $false", "Real-Time Protection", sb);
            RunPsCommand("Update-MpSignature", "Signature Update", sb);
            RunPsCommand("Set-MpPreference -PUAProtection 1", "PUA Protection", sb);
            RunPsCommand("Set-MpPreference -EnableNetworkProtection 1", "Network Protection", sb);
            RunPsCommand("Set-MpPreference -MAPSReporting 2", "Cloud Protection (Advanced)", sb);
            RunPsCommand("Set-MpPreference -DisableBehaviorMonitoring $false", "Behavior Monitoring", sb);
            RunPsCommand("Set-MpPreference -DisableIOAVProtection $false", "IOAV Protection", sb);

            // Enable all firewall profiles
            RunPsCommand("Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True", "Firewall Profiles", sb);

            return RemediationResult.Succeeded(sb.ToString());
        }

        public RemediationResult DryRun()
        {
            return RemediationResult.Succeeded(
                "Would apply:\n" +
                "  1. Enable Real-Time Protection\n" +
                "  2. Update antivirus signatures\n" +
                "  3. Enable PUA protection\n" +
                "  4. Enable Network Protection\n" +
                "  5. Enable Cloud-delivered protection (Advanced)\n" +
                "  6. Enable Behavior Monitoring\n" +
                "  7. Enable IOAV Protection\n" +
                "  8. Enable all firewall profiles");
        }

        private static void RunPsCommand(string command, string description, StringBuilder sb)
        {
            var result = ProcessHelper.Run("powershell.exe",
                string.Format("-NoProfile -NonInteractive -Command \"{0}\"", command));

            if (result.Success)
                sb.AppendFormat("{0}: Enabled\n", description);
            else
                sb.AppendFormat("{0}: Failed - {1}\n", description, result.StandardError.Trim());
        }
    }
}
