using System;
using System.ComponentModel.Composition;
using OmniComply.Core.Engine;
using OmniComply.Core.Interfaces;
using OmniComply.Core.Helpers;

namespace OmniComply.Modules.EnterpriseCompliance
{
    [Export(typeof(IComplianceModule))]
    [ExportMetadata("Name", "Change Management")]
    [ExportMetadata("Category", "Change Management")]
    [ExportMetadata("Order", 33)]
    public class ChangeManagementModule : ComplianceModuleBase
    {
        public override string Name => "Change Management";
        public override string Description => "Validates device management enrollment, installation logging, audit policy change tracking, and software restriction policies";
        public override string Category => "Change Management";
        public override int Order => 33;

        private const string Nist = "CM-3, CM-5";
        private const string Cis = "2.5";
        private const string Iso = "A.12.1.2, A.14.2.2";
        private const string PciDss = "6.4";
        private const string Sox = "ITGC-03";

        protected override void RunChecks()
        {
            CheckSccmIntuneManagedDevice();
            CheckInstallationLogging();
            CheckAuditPolicyChangeEnabled();
            CheckSoftwareRestriction();
        }

        private void CheckSccmIntuneManagedDevice()
        {
            try
            {
                bool managed = false;
                string currentValue = "Not managed by SCCM or Intune";

                // Check for SCCM client service
                var sccmResult = ProcessHelper.RunCmd("sc query CcmExec");
                bool sccmInstalled = sccmResult.Success && sccmResult.StandardOutput != null
                    && (sccmResult.StandardOutput.IndexOf("RUNNING", StringComparison.OrdinalIgnoreCase) >= 0
                        || sccmResult.StandardOutput.IndexOf("STOPPED", StringComparison.OrdinalIgnoreCase) >= 0);

                // Check for Intune enrollment via registry
                bool intuneEnrolled = RegistryHelper.KeyExists(
                    @"HKLM\SOFTWARE\Microsoft\Enrollments");

                if (intuneEnrolled)
                {
                    // Verify there is at least one enrollment entry with a provider
                    var enrollmentResult = ProcessHelper.RunCmd(
                        "reg query HKLM\\SOFTWARE\\Microsoft\\Enrollments /s /v ProviderID 2>nul");
                    if (enrollmentResult.Success && enrollmentResult.StandardOutput != null
                        && enrollmentResult.StandardOutput.IndexOf("ProviderID", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        intuneEnrolled = true;
                    }
                    else
                    {
                        intuneEnrolled = false;
                    }
                }

                if (sccmInstalled && intuneEnrolled)
                {
                    managed = true;
                    currentValue = "Co-managed: SCCM (CcmExec) and Intune enrollment detected";
                }
                else if (sccmInstalled)
                {
                    managed = true;
                    currentValue = "SCCM managed: CcmExec service detected";
                }
                else if (intuneEnrolled)
                {
                    managed = true;
                    currentValue = "Intune managed: MDM enrollment detected";
                }

                AddCheck(
                    "SCCM/Intune Device Management",
                    "Device must be managed by SCCM or Intune for centralized change management and policy enforcement",
                    managed,
                    currentValue,
                    "Device managed by SCCM and/or Intune",
                    "Enroll the device in Microsoft Intune via Settings > Accounts > Access work or school > Connect, or install the SCCM client agent from the Configuration Manager distribution point.",
                    nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss, sox: Sox,
                    intuneRecommendation: "Devices > Enroll devices > Windows enrollment. Configure Automatic enrollment for Azure AD joined devices. Set MDM user scope to 'All' or specific groups for comprehensive device management coverage."
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    "SCCM/Intune Device Management",
                    "Device must be managed by SCCM or Intune for centralized change management and policy enforcement",
                    false,
                    "Error: " + ex.Message,
                    "Device managed by SCCM and/or Intune",
                    "Verify service query and registry access permissions.",
                    nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss, sox: Sox
                );
            }
        }

        private void CheckInstallationLogging()
        {
            try
            {
                string logging = RegistryHelper.GetString(
                    @"HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer",
                    "Logging");

                bool passed = false;
                string currentValue;

                if (!string.IsNullOrEmpty(logging))
                {
                    // The recommended logging value is "voicewarmupx" which enables verbose MSI logging
                    passed = logging.IndexOf("voicewarmupx", StringComparison.OrdinalIgnoreCase) >= 0;
                    currentValue = "Logging value: " + logging;

                    if (!passed)
                    {
                        currentValue += " (does not contain recommended 'voicewarmupx' flags)";
                    }
                }
                else
                {
                    currentValue = "Installation logging not configured (registry value missing)";
                }

                AddCheck(
                    "Windows Installer Logging",
                    "Windows Installer logging must be enabled with verbose flags for change tracking and audit trail",
                    passed,
                    currentValue,
                    "Logging contains 'voicewarmupx'",
                    "Configure via Group Policy: Computer Configuration > Administrative Templates > Windows Components > Windows Installer > Specify the types of events Windows Installer always logs. Set to 'voicewarmupx'. Or set registry HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\Logging = \"voicewarmupx\".",
                    nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss, sox: Sox,
                    intuneRecommendation: "Devices > Configuration profiles > Settings catalog > Administrative Templates > Windows Installer > 'Specify the types of events Windows Installer always logs' = 'voicewarmupx'."
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    "Windows Installer Logging",
                    "Windows Installer logging must be enabled with verbose flags for change tracking and audit trail",
                    false,
                    "Error: " + ex.Message,
                    "Logging contains 'voicewarmupx'",
                    "Verify registry access permissions for HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer.",
                    nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss, sox: Sox
                );
            }
        }

        private void CheckAuditPolicyChangeEnabled()
        {
            try
            {
                var result = ProcessHelper.Run("auditpol.exe",
                    "/get /subcategory:\"Audit Policy Change\"");

                bool passed = false;
                string currentValue = "Unable to query audit policy";

                if (result.Success && !string.IsNullOrWhiteSpace(result.StandardOutput))
                {
                    string output = result.StandardOutput;

                    if (output.IndexOf("Success and Failure", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        passed = true;
                        currentValue = "Success and Failure";
                    }
                    else if (output.IndexOf("Success", StringComparison.OrdinalIgnoreCase) >= 0
                        && output.IndexOf("Failure", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        passed = true;
                        currentValue = "Success and Failure";
                    }
                    else if (output.IndexOf("Success", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        currentValue = "Success only (Failure auditing not enabled)";
                    }
                    else if (output.IndexOf("Failure", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        currentValue = "Failure only (Success auditing not enabled)";
                    }
                    else if (output.IndexOf("No Auditing", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        currentValue = "No Auditing";
                    }
                    else
                    {
                        currentValue = "Unknown status from auditpol output";
                    }
                }
                else if (!string.IsNullOrEmpty(result.StandardError))
                {
                    currentValue = "auditpol error: " + result.StandardError.Trim();
                }

                AddCheck(
                    "Audit Policy Change Auditing",
                    "Audit Policy Change subcategory must be configured for Success and Failure to track policy modifications",
                    passed,
                    currentValue,
                    "Success and Failure",
                    "Enable via: auditpol /set /subcategory:\"Audit Policy Change\" /success:enable /failure:enable. Or via Group Policy: Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Policy Change > Audit Audit Policy Change.",
                    nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss, sox: Sox,
                    intuneRecommendation: "Devices > Configuration profiles > Settings catalog > Local Policies Audit > 'Audit Policy Change' set to 'Success and Failure'. Alternatively, use Endpoint Security > Account protection to enforce audit policies."
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    "Audit Policy Change Auditing",
                    "Audit Policy Change subcategory must be configured for Success and Failure to track policy modifications",
                    false,
                    "Error: " + ex.Message,
                    "Success and Failure",
                    "Ensure auditpol.exe is accessible and the scanner has administrative privileges.",
                    nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss, sox: Sox
                );
            }
        }

        private void CheckSoftwareRestriction()
        {
            try
            {
                bool policyExists = RegistryHelper.KeyExists(
                    @"HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers");

                bool passed = false;
                string currentValue;

                if (policyExists)
                {
                    int defaultLevel = RegistryHelper.GetDword(
                        @"HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers",
                        "DefaultLevel");

                    // DefaultLevel: 0 = Disallowed (most restrictive), 262144 = Unrestricted
                    switch (defaultLevel)
                    {
                        case 0:
                            passed = true;
                            currentValue = "Software Restriction Policies configured with Disallowed default level (most restrictive)";
                            break;
                        case 131072:
                            passed = true;
                            currentValue = "Software Restriction Policies configured with Basic User default level";
                            break;
                        case 262144:
                            currentValue = "Software Restriction Policies configured but default level is Unrestricted";
                            break;
                        default:
                            currentValue = "Software Restriction Policies configured with default level: " + defaultLevel;
                            passed = defaultLevel >= 0 && defaultLevel < 262144;
                            break;
                    }
                }
                else
                {
                    currentValue = "Software Restriction Policies not configured";
                }

                AddCheck(
                    "Software Restriction Policies",
                    "Software Restriction Policies or AppLocker must be configured to control unauthorized software execution",
                    passed,
                    currentValue,
                    "Software restriction policies configured with restrictive default level",
                    "Configure Software Restriction Policies via Group Policy: Computer Configuration > Windows Settings > Security Settings > Software Restriction Policies. Set the default security level to Disallowed and create rules for allowed software. Consider migrating to AppLocker for enhanced control.",
                    nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss, sox: Sox,
                    intuneRecommendation: "Endpoint Security > Application control > Create a Windows Defender Application Control policy. Use managed installer rules or configure AppLocker via Devices > Configuration profiles > Settings catalog > AppLocker."
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    "Software Restriction Policies",
                    "Software Restriction Policies or AppLocker must be configured to control unauthorized software execution",
                    false,
                    "Error: " + ex.Message,
                    "Software restriction policies configured with restrictive default level",
                    "Verify registry access to HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer.",
                    nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss, sox: Sox
                );
            }
        }
    }
}
