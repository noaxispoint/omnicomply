using System;
using System.ComponentModel.Composition;
using System.Management;
using OmniComply.Core.Engine;
using OmniComply.Core.Interfaces;
using OmniComply.Core.Helpers;

namespace OmniComply.Modules.Encryption
{
    [Export(typeof(IComplianceModule))]
    [ExportMetadata("Name", "Virtualization Based Security")]
    [ExportMetadata("Category", "Virtualization Based Security")]
    [ExportMetadata("Order", 18)]
    public class VirtualizationBasedSecurityModule : ComplianceModuleBase
    {
        public override string Name => "Virtualization Based Security";
        public override string Description => "Validates Virtualization Based Security (VBS), HVCI/Memory Integrity, and DMA protection settings";
        public override string Category => "Virtualization Based Security";
        public override int Order => 18;

        private const string Nist = "SC-3, SI-7";
        private const string Cis = "18.9.5";
        private const string Iso = "A.12.2.1";

        protected override void RunChecks()
        {
            CheckVbsEnabled();
            CheckHvciEnabled();
            CheckDmaProtection();
        }

        private void CheckVbsEnabled()
        {
            int vbsEnabled = RegistryHelper.GetDword(
                @"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard",
                "EnableVirtualizationBasedSecurity");

            bool passed = vbsEnabled == 1;
            string currentValue;
            switch (vbsEnabled)
            {
                case 0: currentValue = "Disabled (0)"; break;
                case 1: currentValue = "Enabled (1)"; break;
                default: currentValue = "Not Configured (" + vbsEnabled + ")"; break;
            }

            AddCheck(
                "Virtualization Based Security (VBS)",
                "Virtualization Based Security must be enabled to provide hardware-based isolation",
                passed,
                currentValue,
                "Enabled (1)",
                "Enable VBS via Group Policy: Computer Configuration > Administrative Templates > System > Device Guard > Turn On Virtualization Based Security. Set to 'Enabled'. Alternatively, set registry HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\EnableVirtualizationBasedSecurity to 1. Requires UEFI, Secure Boot, and hardware virtualization support.",
                nist: Nist, cis: Cis, iso27001: Iso
            );
        }

        private void CheckHvciEnabled()
        {
            int hvciEnabled = RegistryHelper.GetDword(
                @"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",
                "Enabled");

            bool passed = hvciEnabled == 1;
            string currentValue;
            switch (hvciEnabled)
            {
                case 0: currentValue = "Disabled (0)"; break;
                case 1: currentValue = "Enabled (1)"; break;
                default: currentValue = "Not Configured (" + hvciEnabled + ")"; break;
            }

            AddCheck(
                "HVCI / Memory Integrity",
                "Hypervisor-protected Code Integrity (Memory Integrity) must be enabled",
                passed,
                currentValue,
                "Enabled (1)",
                "Enable HVCI via Group Policy: Computer Configuration > Administrative Templates > System > Device Guard > Turn On Virtualization Based Security > Virtualization Based Protection of Code Integrity. Set to 'Enabled with UEFI lock'. Registry: HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity\\Enabled = 1. Also available in Windows Security > Device security > Core isolation > Memory integrity.",
                nist: Nist, cis: Cis, iso27001: Iso
            );
        }

        private void CheckDmaProtection()
        {
            int dmaPolicy = RegistryHelper.GetDword(
                @"HKLM\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection",
                "DeviceEnumerationPolicy");

            // 0 = Block all, 1 = Only after login/screen unlock, 2 = At any time (least restrictive)
            // Policy should be configured (0 or 1 preferred for security)
            bool passed = dmaPolicy == 0 || dmaPolicy == 1;
            string currentValue;
            switch (dmaPolicy)
            {
                case 0: currentValue = "Block all DMA-capable devices (0)"; break;
                case 1: currentValue = "Allow only after login/screen unlock (1)"; break;
                case 2: currentValue = "Allow at any time (2) - Least restrictive"; break;
                default: currentValue = "Not Configured (" + dmaPolicy + ")"; break;
            }

            AddCheck(
                "Kernel DMA Protection",
                "DMA protection policy must be configured to restrict external DMA-capable device access",
                passed,
                currentValue,
                "Block all (0) or Allow only after login (1)",
                "Configure DMA protection via Group Policy: Computer Configuration > Administrative Templates > System > Kernel DMA Protection > Enumeration policy for external devices incompatible with Kernel DMA Protection. Set to 'Block all' or 'Only after log in/screen unlock'. Registry: HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Kernel DMA Protection\\DeviceEnumerationPolicy.",
                nist: Nist, cis: Cis, iso27001: Iso
            );
        }
    }
}
