using System;
using System.ComponentModel.Composition;
using System.Management;
using OmniComply.Core.Engine;
using OmniComply.Core.Interfaces;
using OmniComply.Core.Helpers;

namespace OmniComply.Modules.EndpointSecurity
{
    [Export(typeof(IComplianceModule))]
    [ExportMetadata("Name", "Removable Storage")]
    [ExportMetadata("Category", "Removable Storage")]
    [ExportMetadata("Order", 21)]
    public class RemovableStorageModule : ComplianceModuleBase
    {
        public override string Name => "Removable Storage";
        public override string Description => "Validates removable storage restrictions including USB write protection, access control, AutoRun, and BitLocker To Go requirements";
        public override string Category => "Removable Storage";
        public override int Order => 21;

        private const string Nist = "MP-7";
        private const string Cis = "10.3";
        private const string Iso = "A.8.3.1, A.11.2.9";

        protected override void RunChecks()
        {
            CheckUsbWriteProtection();
            CheckUsbAccessRestriction();
            CheckAutoRunDisabled();
            CheckBitLockerToGo();
        }

        private void CheckUsbWriteProtection()
        {
            int writeProtect = RegistryHelper.GetDword(
                @"HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies",
                "WriteProtect");

            bool passed = writeProtect == 1;
            string currentValue;
            switch (writeProtect)
            {
                case 0: currentValue = "Write access allowed (0)"; break;
                case 1: currentValue = "Write access blocked (1)"; break;
                default: currentValue = "Not Configured (" + writeProtect + ") - Write access allowed by default"; break;
            }

            AddCheck(
                "USB Write Protection",
                "Write access to USB storage devices must be blocked to prevent data exfiltration",
                passed,
                currentValue,
                "Write access blocked (1)",
                "Block USB write access by setting registry HKLM\\SYSTEM\\CurrentControlSet\\Control\\StorageDevicePolicies\\WriteProtect to 1 (DWORD). Group Policy: Computer Configuration > Administrative Templates > System > Removable Storage Access > Removable Disks: Deny write access. Set to 'Enabled'.",
                nist: Nist, cis: Cis, iso27001: Iso
            );
        }

        private void CheckUsbAccessRestriction()
        {
            int denyAll = RegistryHelper.GetDword(
                @"HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices",
                "Deny_All");

            bool passed = denyAll == 1;
            string currentValue;
            switch (denyAll)
            {
                case 0: currentValue = "Access allowed (0)"; break;
                case 1: currentValue = "All access denied (1)"; break;
                default: currentValue = "Not Configured (" + denyAll + ") - Access allowed by default"; break;
            }

            AddCheck(
                "USB Access Restriction",
                "Access to removable storage devices must be restricted to prevent unauthorized data transfer",
                passed,
                currentValue,
                "All access denied (1)",
                "Deny all removable storage access via Group Policy: Computer Configuration > Administrative Templates > System > Removable Storage Access > All Removable Storage classes: Deny all access. Set to 'Enabled'. Registry: HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\RemovableStorageDevices\\Deny_All = 1.",
                nist: Nist, cis: Cis, iso27001: Iso
            );
        }

        private void CheckAutoRunDisabled()
        {
            int noDriveTypeAutoRun = RegistryHelper.GetDword(
                @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                "NoDriveTypeAutoRun");

            // 255 (0xFF) disables AutoRun on all drive types
            bool passed = noDriveTypeAutoRun == 255;
            string currentValue;
            if (noDriveTypeAutoRun == 255)
                currentValue = "Disabled on all drive types (255/0xFF)";
            else if (noDriveTypeAutoRun > 0)
                currentValue = string.Format("Partially configured ({0}) - Not all drive types covered", noDriveTypeAutoRun);
            else if (noDriveTypeAutoRun == 0)
                currentValue = "Enabled on all drive types (0) - AutoRun is active";
            else
                currentValue = "Not Configured (" + noDriveTypeAutoRun + ") - AutoRun may be active";

            AddCheck(
                "AutoRun Disabled",
                "AutoRun must be disabled on all drive types to prevent automatic execution of malicious media",
                passed,
                currentValue,
                "Disabled on all drive types (255)",
                "Disable AutoRun via Group Policy: Computer Configuration > Administrative Templates > Windows Components > AutoPlay Policies > Turn off Autoplay. Set to 'Enabled' for 'All drives'. Registry: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoDriveTypeAutoRun = 255 (DWORD).",
                nist: Nist, cis: Cis, iso27001: Iso
            );
        }

        private void CheckBitLockerToGo()
        {
            // Check if BitLocker To Go is required for removable drives
            // Policy: Deny write access to removable drives not protected by BitLocker
            int denyWriteIfNotEncrypted = RegistryHelper.GetDword(
                @"HKLM\SOFTWARE\Policies\Microsoft\FVE",
                "RDVDenyWriteAccess");

            // Also check for the cross-organization setting
            int rdvDenyCrossOrg = RegistryHelper.GetDword(
                @"HKLM\SOFTWARE\Policies\Microsoft\FVE",
                "RDVDenyCrossOrg");

            bool passed = denyWriteIfNotEncrypted == 1;
            string currentValue;
            if (denyWriteIfNotEncrypted == 1)
            {
                currentValue = rdvDenyCrossOrg == 1
                    ? "Required (write denied to unencrypted drives, cross-org restricted)"
                    : "Required (write denied to unencrypted removable drives)";
            }
            else if (denyWriteIfNotEncrypted == 0)
            {
                currentValue = "Not Required (0) - Unencrypted removable drives are writable";
            }
            else
            {
                currentValue = "Not Configured (" + denyWriteIfNotEncrypted + ") - BitLocker To Go not enforced";
            }

            AddCheck(
                "BitLocker To Go (Removable Drive Encryption)",
                "Write access to removable drives must require BitLocker encryption",
                passed,
                currentValue,
                "Write access denied to unencrypted removable drives",
                "Require BitLocker To Go via Group Policy: Computer Configuration > Administrative Templates > Windows Components > BitLocker Drive Encryption > Removable Data Drives > Deny write access to removable drives not protected by BitLocker. Set to 'Enabled'. Registry: HKLM\\SOFTWARE\\Policies\\Microsoft\\FVE\\RDVDenyWriteAccess = 1.",
                nist: Nist, cis: Cis, iso27001: Iso
            );
        }
    }
}
