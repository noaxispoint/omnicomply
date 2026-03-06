using System;
using System.ComponentModel.Composition;
using System.Management;
using OmniComply.Core.Engine;
using OmniComply.Core.Interfaces;
using OmniComply.Core.Helpers;

namespace OmniComply.Modules.EndpointSecurity
{
    [Export(typeof(IComplianceModule))]
    [ExportMetadata("Name", "Browser Security")]
    [ExportMetadata("Category", "Browser Security")]
    [ExportMetadata("Order", 26)]
    public class BrowserSecurityModule : ComplianceModuleBase
    {
        public override string Name => "Browser Security";
        public override string Description => "Validates browser security settings including Edge SmartScreen, site isolation, and Internet Explorer deprecation";
        public override string Category => "Browser Security";
        public override int Order => 26;

        private const string Nist = "SC-18";
        private const string Cis = "9.2";
        private const string Iso = "A.12.6.2";
        private const string PciDss = "6.2";

        protected override void RunChecks()
        {
            CheckEdgeSmartScreen();
            CheckEdgeSiteIsolation();
            CheckInternetExplorerDisabled();
        }

        private void CheckEdgeSmartScreen()
        {
            int smartScreenEnabled = RegistryHelper.GetDword(
                @"HKLM\SOFTWARE\Policies\Microsoft\Edge",
                "SmartScreenEnabled");

            bool passed = smartScreenEnabled == 1;
            string currentValue;
            switch (smartScreenEnabled)
            {
                case 0: currentValue = "Disabled (0)"; break;
                case 1: currentValue = "Enabled (1)"; break;
                default: currentValue = "Not Configured via policy (" + smartScreenEnabled + ")"; break;
            }

            AddCheck(
                "Microsoft Edge SmartScreen",
                "Microsoft Edge SmartScreen must be enabled to protect against phishing and malware",
                passed,
                currentValue,
                "Enabled (1)",
                "Enable Edge SmartScreen via Group Policy: Computer Configuration > Administrative Templates > Microsoft Edge > SmartScreen settings > Configure Microsoft Defender SmartScreen. Set to 'Enabled'. Registry: HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge\\SmartScreenEnabled = 1.",
                nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss
            );
        }

        private void CheckEdgeSiteIsolation()
        {
            int sitePerProcess = RegistryHelper.GetDword(
                @"HKLM\SOFTWARE\Policies\Microsoft\Edge",
                "SitePerProcess");

            bool passed = sitePerProcess == 1;
            string currentValue;
            switch (sitePerProcess)
            {
                case 0: currentValue = "Disabled (0)"; break;
                case 1: currentValue = "Enabled (1)"; break;
                default: currentValue = "Not Configured via policy (" + sitePerProcess + ") - browser default may apply"; break;
            }

            AddCheck(
                "Microsoft Edge Site Isolation",
                "Site isolation (Site-per-process) must be enabled in Microsoft Edge for defense against cross-site data theft",
                passed,
                currentValue,
                "Enabled (1)",
                "Enable site isolation via Group Policy: Computer Configuration > Administrative Templates > Microsoft Edge > Enable site isolation for every site. Set to 'Enabled'. Registry: HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge\\SitePerProcess = 1. Note: Modern Edge versions enable strict site isolation by default, but policy enforcement is recommended.",
                nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss
            );
        }

        private void CheckInternetExplorerDisabled()
        {
            // Check if Internet Explorer is disabled via the DISM optional feature
            // or via the IE disable policy
            bool ieDisabled = false;
            string currentValue = "Unable to determine status";

            // Check via registry if IE mode is disabled (Windows 10/11)
            int disableIE = RegistryHelper.GetDword(
                @"HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main",
                "NotifyDisableIEOptions");

            // Check if IE is removed as a Windows feature (Windows 11+)
            var dismResult = ProcessHelper.Run("dism.exe", "/Online /Get-FeatureInfo /FeatureName:Internet-Explorer-Optional-amd64", 15000);

            bool featureDisabled = false;
            if (dismResult.Success && dismResult.StandardOutput != null)
            {
                string output = dismResult.StandardOutput;
                if (output.Contains("State : Disabled") || output.Contains("State : Disable Pending"))
                {
                    featureDisabled = true;
                }
            }

            // Also check for the IE11 disable policy
            int ieDisablePolicy = RegistryHelper.GetDword(
                @"HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main",
                "DisableIE");

            if (featureDisabled)
            {
                ieDisabled = true;
                currentValue = "Internet Explorer feature is disabled";
            }
            else if (ieDisablePolicy == 1)
            {
                ieDisabled = true;
                currentValue = "Internet Explorer disabled via policy";
            }
            else if (disableIE >= 1)
            {
                ieDisabled = true;
                currentValue = "Internet Explorer disable notification configured";
            }
            else
            {
                // Feature may still be present
                if (dismResult.Success && dismResult.StandardOutput != null &&
                    dismResult.StandardOutput.Contains("State : Enabled"))
                {
                    currentValue = "Internet Explorer feature is enabled";
                }
                else
                {
                    currentValue = "Internet Explorer status could not be verified (feature may not apply to this OS edition)";
                }
            }

            AddCheck(
                "Internet Explorer Disabled",
                "Internet Explorer must be disabled as it is a deprecated browser with known security limitations",
                ieDisabled,
                currentValue,
                "Disabled or removed",
                "Disable Internet Explorer via: dism /online /Disable-Feature /FeatureName:Internet-Explorer-Optional-amd64 /NoRestart. On Windows 11, IE is disabled by default. Ensure users are redirected to Microsoft Edge. Group Policy: Computer Configuration > Administrative Templates > Windows Components > Internet Explorer > Disable Internet Explorer 11 as a standalone browser.",
                nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss
            );
        }
    }
}
