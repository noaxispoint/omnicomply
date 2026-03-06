using System;
using System.Collections.Generic;
using Newtonsoft.Json;

namespace OmniComply.Core.Models
{
    public class FrameworkMappings
    {
        [JsonProperty("SOC2_HIPAA")]
        public string SOC2_HIPAA { get; set; }

        [JsonProperty("NIST_800_53")]
        public string NIST_800_53 { get; set; }

        [JsonProperty("CIS_Controls_v8")]
        public string CIS_Controls_v8 { get; set; }

        [JsonProperty("ISO_27001")]
        public string ISO_27001 { get; set; }

        [JsonProperty("PCI_DSS_v4")]
        public string PCI_DSS_v4 { get; set; }

        [JsonProperty("SOX_ITGC")]
        public string SOX_ITGC { get; set; }

        [JsonProperty("GDPR")]
        public string GDPR { get; set; }

        [JsonProperty("CCPA")]
        public string CCPA { get; set; }

        /// <summary>
        /// Returns true if this check maps to the given framework key.
        /// Accepts flexible names: "SOC2", "HIPAA", "SOC2_HIPAA", "NIST", "NIST_800_53", "CIS", "ISO", "PCI", "SOX", "GDPR", "CCPA".
        /// </summary>
        public bool HasFramework(string frameworkKey)
        {
            if (string.IsNullOrEmpty(frameworkKey)) return false;

            string key = frameworkKey.Trim().ToUpperInvariant()
                .Replace("-", "_").Replace(" ", "_");

            switch (key)
            {
                case "SOC2":
                case "HIPAA":
                case "SOC2_HIPAA":
                    return !string.IsNullOrEmpty(SOC2_HIPAA);
                case "NIST":
                case "NIST800":
                case "NIST_800_53":
                case "NIST80053":
                    return !string.IsNullOrEmpty(NIST_800_53);
                case "CIS":
                case "CISV8":
                case "CIS_V8":
                case "CIS_CONTROLS":
                case "CIS_CONTROLS_V8":
                    return !string.IsNullOrEmpty(CIS_Controls_v8);
                case "ISO":
                case "ISO27001":
                case "ISO_27001":
                    return !string.IsNullOrEmpty(ISO_27001);
                case "PCI":
                case "PCIDSS":
                case "PCI_DSS":
                case "PCI_DSS_V4":
                    return !string.IsNullOrEmpty(PCI_DSS_v4);
                case "SOX":
                case "SOX_ITGC":
                    return !string.IsNullOrEmpty(SOX_ITGC);
                case "GDPR":
                    return !string.IsNullOrEmpty(GDPR);
                case "CCPA":
                    return !string.IsNullOrEmpty(CCPA);
                default:
                    return false;
            }
        }

        /// <summary>
        /// Returns true if this check maps to ANY of the given frameworks.
        /// </summary>
        public bool HasAnyFramework(IEnumerable<string> frameworkKeys)
        {
            foreach (var key in frameworkKeys)
            {
                if (HasFramework(key)) return true;
            }
            return false;
        }

        /// <summary>
        /// Lists all recognized framework keys for help/validation.
        /// </summary>
        public static readonly string[] ValidFrameworkKeys = new[]
        {
            "SOC2", "HIPAA", "NIST", "CIS", "ISO", "PCI", "SOX", "GDPR", "CCPA"
        };
    }
}
