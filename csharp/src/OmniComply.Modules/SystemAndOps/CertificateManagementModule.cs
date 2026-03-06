using System;
using System.ComponentModel.Composition;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using OmniComply.Core.Engine;
using OmniComply.Core.Interfaces;
using OmniComply.Core.Helpers;

namespace OmniComply.Modules.SystemAndOps
{
    [Export(typeof(IComplianceModule))]
    [ExportMetadata("Name", "Certificate Management")]
    [ExportMetadata("Category", "Certificate Management")]
    [ExportMetadata("Order", 23)]
    public class CertificateManagementModule : ComplianceModuleBase
    {
        public override string Name => "Certificate Management";
        public override string Description => "Validates certificate expiration, revocation checking, and signature algorithm strength in the Local Machine certificate store";
        public override string Category => "Certificate Management";
        public override int Order => 23;

        private const string Nist = "SC-12, SC-17";
        private const string Cis = "N/A";
        private const string Iso = "A.10.1.2";
        private const string PciDss = "4.1";

        protected override void RunChecks()
        {
            CheckExpiringCertificates();
            CheckExpiredCertificates();
            CheckCertificateRevocationChecking();
            CheckWeakSignatureAlgorithms();
        }

        /// <summary>
        /// Checks the LocalMachine\My store for certificates expiring within 30 days.
        /// </summary>
        private void CheckExpiringCertificates()
        {
            try
            {
                using (var store = new X509Store(StoreName.My, StoreLocation.LocalMachine))
                {
                    store.Open(OpenFlags.ReadOnly);

                    var expiringCerts = store.Certificates
                        .Cast<X509Certificate2>()
                        .Where(c => c.NotAfter > DateTime.Now && c.NotAfter <= DateTime.Now.AddDays(30))
                        .ToList();

                    bool passed = expiringCerts.Count == 0;
                    string currentValue;

                    if (expiringCerts.Count == 0)
                    {
                        currentValue = "No certificates expiring within 30 days";
                    }
                    else
                    {
                        var certDetails = expiringCerts
                            .Select(c => string.Format("{0} (expires {1})",
                                GetCertificateDisplayName(c), c.NotAfter.ToString("yyyy-MM-dd")));
                        currentValue = string.Format("{0} certificate(s) expiring soon: {1}",
                            expiringCerts.Count, string.Join("; ", certDetails));
                    }

                    AddCheck(
                        check: "Expiring Certificates",
                        requirement: "No certificates in the Local Machine store should be expiring within 30 days",
                        passed: passed,
                        currentValue: currentValue,
                        expectedValue: "No certificates expiring within 30 days",
                        remediation: "Renew expiring certificates before they expire. Use certlm.msc to view and manage Local Machine certificates. For auto-enrolled certificates, verify auto-enrollment Group Policy is configured: Computer Configuration > Windows Settings > Security Settings > Public Key Policies > Certificate Services Client - Auto-Enrollment.",
                        nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss,
                        intuneRecommendation: "Devices > Configuration profiles > Create profile > PKCS certificate or SCEP certificate. Configure automatic certificate renewal with appropriate renewal thresholds. Monitor certificate health via Intune device compliance reports."
                    );

                    store.Close();
                }
            }
            catch (Exception ex)
            {
                AddCheck(
                    check: "Expiring Certificates",
                    requirement: "No certificates in the Local Machine store should be expiring within 30 days",
                    passed: false,
                    currentValue: "Error accessing certificate store: " + ex.Message,
                    expectedValue: "No certificates expiring within 30 days",
                    remediation: "Ensure the certificate store is accessible. Run certlm.msc as Administrator to verify store access.",
                    nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss,
                    intuneRecommendation: "Devices > Configuration profiles > Create profile > PKCS certificate or SCEP certificate. Configure automatic certificate renewal with appropriate renewal thresholds."
                );
            }
        }

        /// <summary>
        /// Checks the LocalMachine\My store for already expired certificates.
        /// </summary>
        private void CheckExpiredCertificates()
        {
            try
            {
                using (var store = new X509Store(StoreName.My, StoreLocation.LocalMachine))
                {
                    store.Open(OpenFlags.ReadOnly);

                    var expiredCerts = store.Certificates
                        .Cast<X509Certificate2>()
                        .Where(c => c.NotAfter <= DateTime.Now)
                        .ToList();

                    bool passed = expiredCerts.Count == 0;
                    string currentValue;

                    if (expiredCerts.Count == 0)
                    {
                        currentValue = "No expired certificates found";
                    }
                    else
                    {
                        var certDetails = expiredCerts
                            .Select(c => string.Format("{0} (expired {1})",
                                GetCertificateDisplayName(c), c.NotAfter.ToString("yyyy-MM-dd")));
                        currentValue = string.Format("{0} expired certificate(s): {1}",
                            expiredCerts.Count, string.Join("; ", certDetails));
                    }

                    AddCheck(
                        check: "Expired Certificates",
                        requirement: "No expired certificates should remain in the Local Machine store",
                        passed: passed,
                        currentValue: currentValue,
                        expectedValue: "No expired certificates",
                        remediation: "Remove expired certificates from the Local Machine store using certlm.msc, or renew/replace them as needed. Expired certificates can cause authentication failures and service disruptions.",
                        nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss,
                        intuneRecommendation: "Devices > Configuration profiles > Create profile > PKCS or SCEP certificate profile. Enable automatic renewal and configure certificate lifecycle management. Use Intune certificate connectors for on-premises CA integration."
                    );

                    store.Close();
                }
            }
            catch (Exception ex)
            {
                AddCheck(
                    check: "Expired Certificates",
                    requirement: "No expired certificates should remain in the Local Machine store",
                    passed: false,
                    currentValue: "Error accessing certificate store: " + ex.Message,
                    expectedValue: "No expired certificates",
                    remediation: "Ensure the certificate store is accessible. Run certlm.msc as Administrator to verify store access.",
                    nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss,
                    intuneRecommendation: "Devices > Configuration profiles > Create profile > PKCS or SCEP certificate profile. Enable automatic renewal and configure certificate lifecycle management."
                );
            }
        }

        /// <summary>
        /// Checks whether certificate revocation checking is enabled via the
        /// FEATURE_WARN_ON_SEC_CERT_REV_FAILED feature control registry key.
        /// </summary>
        private void CheckCertificateRevocationChecking()
        {
            const string regPath = @"HKLM\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WARN_ON_SEC_CERT_REV_FAILED";

            // Check for the iexplore.exe entry which controls the global revocation check behavior
            int revocationCheckEnabled = RegistryHelper.GetDword(regPath, "iexplore.exe", -1);

            bool passed;
            string currentValue;

            if (revocationCheckEnabled == -1)
            {
                // Key not present - check if the parent key exists at all
                bool keyExists = RegistryHelper.KeyExists(regPath);
                if (keyExists)
                {
                    currentValue = "Key exists but no revocation check value configured";
                    passed = false;
                }
                else
                {
                    currentValue = "Revocation check feature control not configured";
                    passed = false;
                }
            }
            else
            {
                passed = revocationCheckEnabled == 1;
                currentValue = revocationCheckEnabled == 1
                    ? "Enabled (revocation warnings active)"
                    : "Disabled (revocation warnings suppressed)";
            }

            AddCheck(
                check: "Certificate Revocation Checking",
                requirement: "Certificate revocation checking must be enabled to detect compromised certificates",
                passed: passed,
                currentValue: currentValue,
                expectedValue: "Enabled (FEATURE_WARN_ON_SEC_CERT_REV_FAILED = 1)",
                remediation: "Enable certificate revocation checking: reg add \"HKLM\\SOFTWARE\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_WARN_ON_SEC_CERT_REV_FAILED\" /v iexplore.exe /t REG_DWORD /d 1 /f. Also verify Internet Options > Advanced > Security > 'Check for server certificate revocation' is enabled.",
                nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss,
                intuneRecommendation: "Devices > Configuration profiles > Create profile > Settings catalog. Search for 'Certificate Revocation' and enable certificate revocation checking. Configure OCSP and CRL distribution points via trusted certificate profiles."
            );
        }

        /// <summary>
        /// Checks the LocalMachine\My store for certificates using weak signature
        /// algorithms (SHA1), which are considered insecure.
        /// </summary>
        private void CheckWeakSignatureAlgorithms()
        {
            try
            {
                using (var store = new X509Store(StoreName.My, StoreLocation.LocalMachine))
                {
                    store.Open(OpenFlags.ReadOnly);

                    var weakCerts = store.Certificates
                        .Cast<X509Certificate2>()
                        .Where(c => c.SignatureAlgorithm.FriendlyName != null &&
                                    c.SignatureAlgorithm.FriendlyName.IndexOf("SHA1", StringComparison.OrdinalIgnoreCase) >= 0)
                        .ToList();

                    bool passed = weakCerts.Count == 0;
                    string currentValue;

                    if (weakCerts.Count == 0)
                    {
                        currentValue = "No certificates with weak (SHA1) signature algorithms found";
                    }
                    else
                    {
                        var certDetails = weakCerts
                            .Select(c => string.Format("{0} (algorithm: {1})",
                                GetCertificateDisplayName(c), c.SignatureAlgorithm.FriendlyName));
                        currentValue = string.Format("{0} certificate(s) using SHA1: {1}",
                            weakCerts.Count, string.Join("; ", certDetails));
                    }

                    AddCheck(
                        check: "Weak Signature Algorithms (SHA1)",
                        requirement: "No certificates should use SHA1 signature algorithms, which are considered cryptographically weak",
                        passed: passed,
                        currentValue: currentValue,
                        expectedValue: "No SHA1-signed certificates",
                        remediation: "Replace SHA1-signed certificates with certificates using SHA-256 or stronger algorithms. Reissue certificates from your CA with a SHA-256 signing algorithm. Update certificate templates to require SHA-256 minimum.",
                        nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss,
                        intuneRecommendation: "Devices > Configuration profiles > Create profile > SCEP certificate or PKCS certificate. Ensure 'Hash algorithm' is set to 'SHA-2' (SHA-256 or higher). Configure certificate templates on the issuing CA to enforce SHA-256 minimum."
                    );

                    store.Close();
                }
            }
            catch (Exception ex)
            {
                AddCheck(
                    check: "Weak Signature Algorithms (SHA1)",
                    requirement: "No certificates should use SHA1 signature algorithms, which are considered cryptographically weak",
                    passed: false,
                    currentValue: "Error accessing certificate store: " + ex.Message,
                    expectedValue: "No SHA1-signed certificates",
                    remediation: "Ensure the certificate store is accessible. Run certlm.msc as Administrator to verify store access.",
                    nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss,
                    intuneRecommendation: "Devices > Configuration profiles > Create profile > SCEP certificate or PKCS certificate. Ensure 'Hash algorithm' is set to 'SHA-2' (SHA-256 or higher)."
                );
            }
        }

        /// <summary>
        /// Returns a friendly display name for a certificate, preferring Subject CN.
        /// </summary>
        private static string GetCertificateDisplayName(X509Certificate2 cert)
        {
            if (!string.IsNullOrWhiteSpace(cert.FriendlyName))
                return cert.FriendlyName;

            string subject = cert.Subject;
            if (!string.IsNullOrWhiteSpace(subject))
            {
                // Extract CN= portion if present
                int cnIndex = subject.IndexOf("CN=", StringComparison.OrdinalIgnoreCase);
                if (cnIndex >= 0)
                {
                    string cn = subject.Substring(cnIndex + 3);
                    int commaIndex = cn.IndexOf(',');
                    if (commaIndex >= 0)
                        cn = cn.Substring(0, commaIndex);
                    return cn.Trim();
                }
                return subject;
            }

            return cert.Thumbprint ?? "Unknown";
        }
    }
}
