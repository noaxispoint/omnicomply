using System;
using System.ComponentModel.Composition;
using OmniComply.Core.Engine;
using OmniComply.Core.Interfaces;
using OmniComply.Core.Helpers;

namespace OmniComply.Modules.Privacy
{
    [Export(typeof(IComplianceModule))]
    [ExportMetadata("Name", "Privacy Settings")]
    [ExportMetadata("Category", "Privacy Settings")]
    [ExportMetadata("Order", 36)]
    public class PrivacySettingsModule : ComplianceModuleBase
    {
        public override string Name => "Privacy Settings";
        public override string Description => "Validates Windows telemetry level, location services, advertising ID, activity history, and OneDrive sync controls";
        public override string Category => "Privacy Settings";
        public override int Order => 36;

        private const string Nist = "N/A";
        private const string Cis = "18.1";
        private const string Iso = "N/A";
        private const string Gdpr = "Article 25, Article 5.1.c";
        private const string Ccpa = "\u00a7 1798.100";

        protected override void RunChecks()
        {
            CheckTelemetryLevel();
            CheckLocationServices();
            CheckAdvertisingId();
            CheckActivityHistory();
            CheckOneDriveSync();
        }

        private void CheckTelemetryLevel()
        {
            try
            {
                int telemetryLevel = RegistryHelper.GetDword(
                    @"HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
                    "AllowTelemetry");

                bool passed = telemetryLevel == 0 || telemetryLevel == 1;
                string currentValue;

                switch (telemetryLevel)
                {
                    case 0:
                        currentValue = "Security (0) - Minimum data collection";
                        break;
                    case 1:
                        currentValue = "Basic (1) - Limited data collection";
                        break;
                    case 2:
                        currentValue = "Enhanced (2) - Additional diagnostic data";
                        break;
                    case 3:
                        currentValue = "Full (3) - All diagnostic data collected";
                        break;
                    default:
                        currentValue = "Not configured (value: " + telemetryLevel + ")";
                        break;
                }

                AddCheck(
                    "Windows Telemetry Level",
                    "Windows telemetry must be set to Security (0) or Basic (1) to minimize data collection",
                    passed,
                    currentValue,
                    "Security (0) or Basic (1)",
                    "Configure via Group Policy: Computer Configuration > Administrative Templates > Windows Components > Data Collection and Preview Builds > Allow Diagnostic Data. Set to 'Diagnostic data off' (0) or 'Send required diagnostic data' (1).",
                    nist: Nist, cis: Cis, iso27001: Iso, gdpr: Gdpr, ccpa: Ccpa,
                    intuneRecommendation: "Devices > Configuration profiles > Settings catalog > System > Allow Telemetry. Set to 'Basic' or 'Security' depending on organizational requirements. For Windows 11, use 'Send required diagnostic data' setting."
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    "Windows Telemetry Level",
                    "Windows telemetry must be set to Security (0) or Basic (1) to minimize data collection",
                    false,
                    "Error: " + ex.Message,
                    "Security (0) or Basic (1)",
                    "Verify registry access to HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection.",
                    nist: Nist, cis: Cis, iso27001: Iso, gdpr: Gdpr, ccpa: Ccpa
                );
            }
        }

        private void CheckLocationServices()
        {
            try
            {
                int disableLocation = RegistryHelper.GetDword(
                    @"HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors",
                    "DisableLocation");

                bool passed = disableLocation == 1;
                string currentValue;

                if (disableLocation == 1)
                {
                    currentValue = "Location services disabled (DisableLocation=1)";
                }
                else if (disableLocation == 0)
                {
                    currentValue = "Location services enabled (DisableLocation=0)";
                }
                else
                {
                    currentValue = "Location policy not configured (value: " + disableLocation + ")";
                }

                AddCheck(
                    "Location Services",
                    "Location services must be disabled via policy to prevent unauthorized location tracking",
                    passed,
                    currentValue,
                    "Disabled (DisableLocation=1)",
                    "Configure via Group Policy: Computer Configuration > Administrative Templates > Windows Components > Location and Sensors > Turn off location. Set to 'Enabled'. Or set registry HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\LocationAndSensors\\DisableLocation = 1.",
                    nist: Nist, cis: Cis, iso27001: Iso, gdpr: Gdpr, ccpa: Ccpa,
                    intuneRecommendation: "Devices > Configuration profiles > Settings catalog > System > Allow Location. Set to 'Block' to prevent apps and services from accessing location data on managed devices."
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    "Location Services",
                    "Location services must be disabled via policy to prevent unauthorized location tracking",
                    false,
                    "Error: " + ex.Message,
                    "Disabled (DisableLocation=1)",
                    "Verify registry access to HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\LocationAndSensors.",
                    nist: Nist, cis: Cis, iso27001: Iso, gdpr: Gdpr, ccpa: Ccpa
                );
            }
        }

        private void CheckAdvertisingId()
        {
            try
            {
                int advertisingEnabled = RegistryHelper.GetDword(
                    @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo",
                    "Enabled");

                bool passed = advertisingEnabled == 0;
                string currentValue;

                if (advertisingEnabled == 0)
                {
                    currentValue = "Advertising ID disabled (Enabled=0)";
                }
                else if (advertisingEnabled == 1)
                {
                    currentValue = "Advertising ID enabled (Enabled=1)";
                }
                else
                {
                    currentValue = "Advertising ID not explicitly configured (value: " + advertisingEnabled + ")";
                }

                AddCheck(
                    "Advertising ID",
                    "The Windows Advertising ID must be disabled to prevent cross-app user tracking",
                    passed,
                    currentValue,
                    "Disabled (Enabled=0)",
                    "Configure via Group Policy: Computer Configuration > Administrative Templates > System > User Profiles > Turn off the advertising ID. Set to 'Enabled'. Or set registry HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo\\Enabled = 0.",
                    nist: Nist, cis: Cis, iso27001: Iso, gdpr: Gdpr, ccpa: Ccpa,
                    intuneRecommendation: "Devices > Configuration profiles > Settings catalog > Privacy > 'Let apps use advertising ID'. Set to 'Not allowed' to disable advertising ID for all users on managed devices."
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    "Advertising ID",
                    "The Windows Advertising ID must be disabled to prevent cross-app user tracking",
                    false,
                    "Error: " + ex.Message,
                    "Disabled (Enabled=0)",
                    "Verify registry access to HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo.",
                    nist: Nist, cis: Cis, iso27001: Iso, gdpr: Gdpr, ccpa: Ccpa
                );
            }
        }

        private void CheckActivityHistory()
        {
            try
            {
                int publishActivities = RegistryHelper.GetDword(
                    @"HKLM\SOFTWARE\Policies\Microsoft\Windows\System",
                    "PublishUserActivities");

                bool passed = publishActivities == 0;
                string currentValue;

                if (publishActivities == 0)
                {
                    currentValue = "Activity history publishing disabled (PublishUserActivities=0)";
                }
                else if (publishActivities == 1)
                {
                    currentValue = "Activity history publishing enabled (PublishUserActivities=1)";
                }
                else
                {
                    currentValue = "Activity history policy not configured (value: " + publishActivities + ")";
                }

                AddCheck(
                    "Activity History Publishing",
                    "Windows activity history publishing must be disabled to prevent user activity data from being sent to Microsoft",
                    passed,
                    currentValue,
                    "Disabled (PublishUserActivities=0)",
                    "Configure via Group Policy: Computer Configuration > Administrative Templates > System > OS Policies > Allow publishing of User Activities. Set to 'Disabled'. Or set registry HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\PublishUserActivities = 0.",
                    nist: Nist, cis: Cis, iso27001: Iso, gdpr: Gdpr, ccpa: Ccpa,
                    intuneRecommendation: "Devices > Configuration profiles > Settings catalog > Privacy > 'Allow Activity Feed'. Set to 'Not allowed'. Also configure 'Allow Publishing of User Activities' to 'Not allowed'."
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    "Activity History Publishing",
                    "Windows activity history publishing must be disabled to prevent user activity data from being sent to Microsoft",
                    false,
                    "Error: " + ex.Message,
                    "Disabled (PublishUserActivities=0)",
                    "Verify registry access to HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System.",
                    nist: Nist, cis: Cis, iso27001: Iso, gdpr: Gdpr, ccpa: Ccpa
                );
            }
        }

        private void CheckOneDriveSync()
        {
            try
            {
                int disableSync = RegistryHelper.GetDword(
                    @"HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive",
                    "DisableFileSyncNGSC");

                bool passed = disableSync == 1;
                string currentValue;

                if (disableSync == 1)
                {
                    currentValue = "OneDrive file sync disabled via policy (DisableFileSyncNGSC=1)";
                }
                else if (disableSync == 0)
                {
                    currentValue = "OneDrive file sync explicitly allowed (DisableFileSyncNGSC=0)";
                }
                else
                {
                    currentValue = "OneDrive file sync policy not configured (value: " + disableSync + ")";
                }

                AddCheck(
                    "OneDrive Sync Control",
                    "OneDrive file synchronization must be controlled via policy to prevent unauthorized cloud data transfers",
                    passed,
                    currentValue,
                    "Controlled via policy (DisableFileSyncNGSC=1 or organizational sync configured)",
                    "Configure via Group Policy: Computer Configuration > Administrative Templates > Windows Components > OneDrive > Prevent the usage of OneDrive for file storage. Set to 'Enabled'. If OneDrive is needed, configure tenant restrictions instead.",
                    nist: Nist, cis: Cis, iso27001: Iso, gdpr: Gdpr, ccpa: Ccpa,
                    intuneRecommendation: "Devices > Configuration profiles > Settings catalog > OneDrive > 'Prevent the usage of OneDrive for file storage'. If sync is needed, configure 'Allow syncing only on PCs joined to specific domains' and 'Block file downloads using OneDrive' for unmanaged devices."
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    "OneDrive Sync Control",
                    "OneDrive file synchronization must be controlled via policy to prevent unauthorized cloud data transfers",
                    false,
                    "Error: " + ex.Message,
                    "Controlled via policy (DisableFileSyncNGSC=1 or organizational sync configured)",
                    "Verify registry access to HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\OneDrive.",
                    nist: Nist, cis: Cis, iso27001: Iso, gdpr: Gdpr, ccpa: Ccpa
                );
            }
        }
    }
}
