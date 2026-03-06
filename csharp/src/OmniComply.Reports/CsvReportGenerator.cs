using System.ComponentModel.Composition;
using System.IO;
using System.Text;
using OmniComply.Core.Interfaces;
using OmniComply.Core.Models;

namespace OmniComply.Reports
{
    [Export(typeof(IReportGenerator))]
    public class CsvReportGenerator : IReportGenerator
    {
        public string Format => "CSV";
        public string FileExtension => "csv";

        public void Generate(ComplianceScanResult results, string outputPath)
        {
            var sb = new StringBuilder();

            // Header row
            sb.AppendLine("\"Category\",\"Check\",\"Requirement\",\"NIST 800-53\",\"CIS v8\",\"ISO 27001\",\"PCI-DSS v4\",\"SOX ITGC\",\"GDPR\",\"CCPA\",\"Passed\",\"CurrentValue\",\"ExpectedValue\",\"Remediation\",\"IntuneRecommendation\"");

            foreach (var check in results.Checks)
            {
                sb.AppendFormat("\"{0}\",\"{1}\",\"{2}\",\"{3}\",\"{4}\",\"{5}\",\"{6}\",\"{7}\",\"{8}\",\"{9}\",\"{10}\",\"{11}\",\"{12}\",\"{13}\",\"{14}\"\r\n",
                    Escape(check.Category),
                    Escape(check.Check),
                    Escape(check.Requirement),
                    Escape(check.Frameworks != null ? check.Frameworks.NIST_800_53 : ""),
                    Escape(check.Frameworks != null ? check.Frameworks.CIS_Controls_v8 : ""),
                    Escape(check.Frameworks != null ? check.Frameworks.ISO_27001 : ""),
                    Escape(check.Frameworks != null ? check.Frameworks.PCI_DSS_v4 : ""),
                    Escape(check.Frameworks != null ? check.Frameworks.SOX_ITGC : ""),
                    Escape(check.Frameworks != null ? check.Frameworks.GDPR : ""),
                    Escape(check.Frameworks != null ? check.Frameworks.CCPA : ""),
                    check.Passed,
                    Escape(check.CurrentValue),
                    Escape(check.ExpectedValue),
                    Escape(check.Remediation),
                    Escape(check.IntuneRecommendation));
            }

            File.WriteAllText(outputPath, sb.ToString(), Encoding.UTF8);
        }

        private static string Escape(string value)
        {
            if (string.IsNullOrEmpty(value)) return "";
            return value.Replace("\"", "\"\"");
        }
    }
}
