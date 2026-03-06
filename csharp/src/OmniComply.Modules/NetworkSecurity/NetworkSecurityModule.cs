using System;
using System.ComponentModel.Composition;
using OmniComply.Core.Engine;
using OmniComply.Core.Interfaces;
using OmniComply.Core.Helpers;

namespace OmniComply.Modules.NetworkSecurity
{
    [Export(typeof(IComplianceModule))]
    [ExportMetadata("Name", "Network Security")]
    [ExportMetadata("Category", "Network Security")]
    [ExportMetadata("Order", 11)]
    public class NetworkSecurityModule : ComplianceModuleBase
    {
        public override string Name => "Network Security";
        public override string Description => "Validates SMB protocol security, SMB signing requirements, and Remote Desktop Protocol configuration";
        public override string Category => "Network Security";
        public override int Order => 11;

        private const string Nist = "CM-7(1), SC-8, AC-17";
        private const string Cis = "4.8, 13.9, 12.6";
        private const string Iso = "A.12.6.2, A.13.1.1, A.9.4.2";
        private const string PciDss = "2.2.2, 4.2";

        protected override void RunChecks()
        {
            CheckSmbV1Disabled();
            CheckSmbClientSigning();
            CheckSmbServerSigning();
            CheckRdpStatus();
        }

        private void CheckSmbV1Disabled()
        {
            try
            {
                // Check via the mrxsmb10 service driver (Start=4 means disabled)
                int mrxsmbStart = RegistryHelper.GetDword(
                    @"HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10",
                    "Start");

                // Also check the LanmanServer SMB1 parameter (0 means disabled)
                int smb1ServerValue = RegistryHelper.GetDword(
                    @"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                    "SMB1");

                bool driverDisabled = mrxsmbStart == 4;
                bool serverDisabled = smb1ServerValue == 0;
                bool passed = driverDisabled || serverDisabled;

                string currentValue;
                if (driverDisabled && serverDisabled)
                {
                    currentValue = "Disabled (driver Start=4, SMB1=0)";
                }
                else if (driverDisabled)
                {
                    currentValue = "Disabled (driver Start=4, SMB1 server parameter not set)";
                }
                else if (serverDisabled)
                {
                    currentValue = "Disabled (SMB1=0, driver Start=" + mrxsmbStart + ")";
                }
                else
                {
                    currentValue = string.Format("Enabled (driver Start={0}, SMB1={1})",
                        mrxsmbStart == -1 ? "Not Found" : mrxsmbStart.ToString(),
                        smb1ServerValue == -1 ? "Not Found" : smb1ServerValue.ToString());
                }

                AddCheck(
                    "SMBv1 Protocol Disabled",
                    "SMBv1 must be disabled to prevent exploitation of known vulnerabilities (e.g., EternalBlue)",
                    passed,
                    currentValue,
                    "Disabled (driver Start=4 or SMB1=0)",
                    "Disable SMBv1 via PowerShell: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart. "
                    + "Or via registry: Set HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\SMB1 to 0 (DWORD) "
                    + "and HKLM\\SYSTEM\\CurrentControlSet\\Services\\mrxsmb10\\Start to 4 (DWORD). "
                    + "Group Policy: Computer Configuration > Administrative Templates > MS Security Guide > Configure SMBv1 client driver > Disable driver.",
                    nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss,
                    intuneRecommendation: "Devices > Configuration profiles > Create profile > Settings catalog. Search for 'SMB v1'. "
                    + "Set 'Configure SMB v1 client driver' to 'Disable driver' and 'Configure SMB v1 server' to 'Disabled'. "
                    + "Alternatively, use Endpoint Security > Attack surface reduction rules to block SMBv1 traffic."
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    "SMBv1 Protocol Disabled",
                    "SMBv1 must be disabled to prevent exploitation of known vulnerabilities (e.g., EternalBlue)",
                    false,
                    "Error: " + ex.Message,
                    "Disabled (driver Start=4 or SMB1=0)",
                    "Disable SMBv1 via PowerShell: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart",
                    nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss,
                    intuneRecommendation: "Devices > Configuration profiles > Settings catalog > Configure SMB v1 client driver to 'Disable driver'."
                );
            }
        }

        private void CheckSmbClientSigning()
        {
            try
            {
                int requireSigning = RegistryHelper.GetDword(
                    @"HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
                    "RequireSecuritySignature");

                bool passed = requireSigning == 1;
                string currentValue;
                switch (requireSigning)
                {
                    case 0: currentValue = "Disabled (0)"; break;
                    case 1: currentValue = "Enabled (1)"; break;
                    default: currentValue = "Not Configured (" + requireSigning + ")"; break;
                }

                AddCheck(
                    "SMB Client Signing Required",
                    "SMB client must require packet signing to prevent man-in-the-middle attacks",
                    passed,
                    currentValue,
                    "Enabled (1)",
                    "Enable SMB client signing via Group Policy: Computer Configuration > Windows Settings > Security Settings > "
                    + "Local Policies > Security Options > Microsoft network client: Digitally sign communications (always) = Enabled. "
                    + "Registry: HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\RequireSecuritySignature = 1 (DWORD).",
                    nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    "SMB Client Signing Required",
                    "SMB client must require packet signing to prevent man-in-the-middle attacks",
                    false,
                    "Error: " + ex.Message,
                    "Enabled (1)",
                    "Enable SMB client signing via Group Policy: Microsoft network client: Digitally sign communications (always) = Enabled",
                    nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss
                );
            }
        }

        private void CheckSmbServerSigning()
        {
            try
            {
                int requireSigning = RegistryHelper.GetDword(
                    @"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                    "RequireSecuritySignature");

                bool passed = requireSigning == 1;
                string currentValue;
                switch (requireSigning)
                {
                    case 0: currentValue = "Disabled (0)"; break;
                    case 1: currentValue = "Enabled (1)"; break;
                    default: currentValue = "Not Configured (" + requireSigning + ")"; break;
                }

                AddCheck(
                    "SMB Server Signing Required",
                    "SMB server must require packet signing to prevent relay and spoofing attacks",
                    passed,
                    currentValue,
                    "Enabled (1)",
                    "Enable SMB server signing via Group Policy: Computer Configuration > Windows Settings > Security Settings > "
                    + "Local Policies > Security Options > Microsoft network server: Digitally sign communications (always) = Enabled. "
                    + "Registry: HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\RequireSecuritySignature = 1 (DWORD).",
                    nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    "SMB Server Signing Required",
                    "SMB server must require packet signing to prevent relay and spoofing attacks",
                    false,
                    "Error: " + ex.Message,
                    "Enabled (1)",
                    "Enable SMB server signing via Group Policy: Microsoft network server: Digitally sign communications (always) = Enabled",
                    nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss
                );
            }
        }

        private void CheckRdpStatus()
        {
            try
            {
                int fDenyTSConnections = RegistryHelper.GetDword(
                    @"HKLM\System\CurrentControlSet\Control\Terminal Server",
                    "fDenyTSConnections");

                // fDenyTSConnections == 1 means RDP is disabled (which is the secure state)
                bool passed = fDenyTSConnections == 1;
                string currentValue;
                switch (fDenyTSConnections)
                {
                    case 0: currentValue = "RDP Enabled (0) - connections allowed"; break;
                    case 1: currentValue = "RDP Disabled (1) - connections denied"; break;
                    default: currentValue = "Not Configured (" + fDenyTSConnections + ")"; break;
                }

                AddCheck(
                    "Remote Desktop Protocol (RDP) Disabled",
                    "RDP should be disabled unless explicitly required and secured with NLA and access controls",
                    passed,
                    currentValue,
                    "Disabled (fDenyTSConnections=1)",
                    "Disable RDP via System Properties > Remote tab > uncheck 'Allow remote connections to this computer'. "
                    + "Or via Group Policy: Computer Configuration > Administrative Templates > Windows Components > "
                    + "Remote Desktop Services > Remote Desktop Session Host > Connections > Allow users to connect remotely = Disabled. "
                    + "Registry: HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\\fDenyTSConnections = 1 (DWORD). "
                    + "If RDP is required, ensure Network Level Authentication (NLA) is enforced and access is restricted by firewall rules.",
                    nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    "Remote Desktop Protocol (RDP) Disabled",
                    "RDP should be disabled unless explicitly required and secured with NLA and access controls",
                    false,
                    "Error: " + ex.Message,
                    "Disabled (fDenyTSConnections=1)",
                    "Disable RDP via System Properties > Remote tab or Group Policy",
                    nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss
                );
            }
        }
    }
}
