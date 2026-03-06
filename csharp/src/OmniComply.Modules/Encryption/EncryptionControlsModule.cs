using System;
using System.ComponentModel.Composition;
using System.Management;
using OmniComply.Core.Engine;
using OmniComply.Core.Interfaces;
using OmniComply.Core.Helpers;

namespace OmniComply.Modules.Encryption
{
    [Export(typeof(IComplianceModule))]
    [ExportMetadata("Name", "Encryption Controls")]
    [ExportMetadata("Category", "Encryption Controls")]
    [ExportMetadata("Order", 7)]
    public class EncryptionControlsModule : ComplianceModuleBase
    {
        public override string Name => "Encryption Controls";
        public override string Description => "Validates BitLocker encryption, TPM status, and Secure Boot configuration";
        public override string Category => "Encryption Controls";
        public override int Order => 7;

        private const string Nist = "SC-28, SC-12, SI-7";
        private const string Cis = "3.1, 3.3";
        private const string Iso = "A.10.1.1, A.10.1.2, A.12.2.1";
        private const string PciDss = "3.4, 3.5.1, 3.6.1";

        protected override void RunChecks()
        {
            CheckBitLockerProtection();
            CheckBitLockerConversion();
            CheckTpmEnabled();
            CheckTpmActivated();
            CheckTpmOwned();
            CheckSecureBoot();
        }

        private void CheckBitLockerProtection()
        {
            const string wmiNamespace = @"root\CIMV2\Security\MicrosoftVolumeEncryption";
            var volume = WmiHelper.QueryFirstWhere("Win32_EncryptableVolume", "DriveLetter='C:'", wmiNamespace);

            int protectionStatus = -1;
            string statusText = "Not Available";

            if (volume != null)
            {
                protectionStatus = WmiHelper.GetProperty(volume, "ProtectionStatus", -1);
                switch (protectionStatus)
                {
                    case 0: statusText = "Protection Off"; break;
                    case 1: statusText = "Protection On"; break;
                    case 2: statusText = "Protection Unknown"; break;
                    default: statusText = "Not Available (value: " + protectionStatus + ")"; break;
                }
            }

            bool passed = protectionStatus == 1;
            AddCheck(
                "BitLocker Protection Status",
                "BitLocker drive encryption must be enabled on the OS drive",
                passed,
                statusText,
                "Protection On",
                "Enable BitLocker on the OS drive via: manage-bde -on C: -RecoveryPassword",
                nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss,
                intuneRecommendation: "Endpoint Security > Disk encryption > Create BitLocker policy. Set 'Require device encryption' to 'Yes' and configure OS drive encryption settings with XTS-AES 256-bit."
            );
        }

        private void CheckBitLockerConversion()
        {
            const string wmiNamespace = @"root\CIMV2\Security\MicrosoftVolumeEncryption";
            var volume = WmiHelper.QueryFirstWhere("Win32_EncryptableVolume", "DriveLetter='C:'", wmiNamespace);

            int conversionStatus = -1;
            string statusText = "Not Available";

            if (volume != null)
            {
                conversionStatus = WmiHelper.GetProperty(volume, "ConversionStatus", -1);
                switch (conversionStatus)
                {
                    case 0: statusText = "Fully Decrypted"; break;
                    case 1: statusText = "Fully Encrypted"; break;
                    case 2: statusText = "Encryption In Progress"; break;
                    case 3: statusText = "Decryption In Progress"; break;
                    case 4: statusText = "Encryption Paused"; break;
                    case 5: statusText = "Decryption Paused"; break;
                    default: statusText = "Not Available (value: " + conversionStatus + ")"; break;
                }
            }

            bool passed = conversionStatus == 1;
            AddCheck(
                "BitLocker Encryption Completion",
                "OS drive must be fully encrypted with BitLocker",
                passed,
                statusText,
                "Fully Encrypted",
                "Ensure BitLocker encryption has completed on the OS drive. If paused, resume with: manage-bde -resume C:",
                nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss,
                intuneRecommendation: "Endpoint Security > Disk encryption > BitLocker policy. Monitor encryption status in device compliance and set 'Encrypt used space only' to 'No' for full disk encryption."
            );
        }

        private void CheckTpmEnabled()
        {
            const string wmiNamespace = @"root\CIMV2\Security\MicrosoftTpm";
            var tpm = WmiHelper.QueryFirst("Win32_Tpm", wmiNamespace);

            bool isEnabled = false;
            string currentValue = "TPM Not Found";

            if (tpm != null)
            {
                isEnabled = WmiHelper.GetProperty(tpm, "IsEnabled_InitialValue", false);
                currentValue = isEnabled ? "Enabled" : "Disabled";
            }

            AddCheck(
                "TPM Enabled",
                "Trusted Platform Module (TPM) must be enabled",
                isEnabled,
                currentValue,
                "Enabled",
                "Enable TPM in BIOS/UEFI firmware settings. Navigate to Security > TPM and set to Enabled.",
                nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss
            );
        }

        private void CheckTpmActivated()
        {
            const string wmiNamespace = @"root\CIMV2\Security\MicrosoftTpm";
            var tpm = WmiHelper.QueryFirst("Win32_Tpm", wmiNamespace);

            bool isActivated = false;
            string currentValue = "TPM Not Found";

            if (tpm != null)
            {
                isActivated = WmiHelper.GetProperty(tpm, "IsActivated_InitialValue", false);
                currentValue = isActivated ? "Activated" : "Not Activated";
            }

            AddCheck(
                "TPM Activated",
                "Trusted Platform Module (TPM) must be activated",
                isActivated,
                currentValue,
                "Activated",
                "Activate TPM in BIOS/UEFI firmware settings. This may require a platform-specific activation step after enabling.",
                nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss
            );
        }

        private void CheckTpmOwned()
        {
            const string wmiNamespace = @"root\CIMV2\Security\MicrosoftTpm";
            var tpm = WmiHelper.QueryFirst("Win32_Tpm", wmiNamespace);

            bool isOwned = false;
            string currentValue = "TPM Not Found";

            if (tpm != null)
            {
                isOwned = WmiHelper.GetProperty(tpm, "IsOwned_InitialValue", false);
                currentValue = isOwned ? "Owned" : "Not Owned";
            }

            AddCheck(
                "TPM Ownership",
                "Trusted Platform Module (TPM) must be owned by the operating system",
                isOwned,
                currentValue,
                "Owned",
                "Initialize TPM ownership via tpm.msc or PowerShell: Initialize-Tpm",
                nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss
            );
        }

        private void CheckSecureBoot()
        {
            int secureBootEnabled = RegistryHelper.GetDword(
                @"HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State",
                "UEFISecureBootEnabled");

            bool passed = secureBootEnabled == 1;
            string currentValue = secureBootEnabled == 1 ? "Enabled" : secureBootEnabled == 0 ? "Disabled" : "Not Available";

            AddCheck(
                "UEFI Secure Boot",
                "UEFI Secure Boot must be enabled to prevent unauthorized boot loaders",
                passed,
                currentValue,
                "Enabled",
                "Enable Secure Boot in BIOS/UEFI firmware settings. Ensure the system is booted in UEFI mode (not Legacy/CSM).",
                nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss,
                intuneRecommendation: "Devices > Compliance policies > Create policy > Windows 10 and later. Under 'Device Health', set 'Require Secure Boot' to 'Require'. Non-compliant devices will be flagged for remediation."
            );
        }
    }
}
