using System;
using System.ComponentModel.Composition;
using System.IO;
using System.Linq;
using System.Text;
using System.Web;
using OmniComply.Core.Interfaces;
using OmniComply.Core.Models;

namespace OmniComply.Reports
{
    [Export(typeof(IReportGenerator))]
    public class HtmlReportGenerator : IReportGenerator
    {
        public string Format => "HTML";
        public string FileExtension => "html";

        public void Generate(ComplianceScanResult results, string outputPath)
        {
            var sb = new StringBuilder();

            sb.AppendLine("<!DOCTYPE html>");
            sb.AppendLine("<html>");
            sb.AppendLine("<head>");
            sb.AppendFormat("    <title>OmniComply Multi-Framework Compliance Report - {0}</title>\n", Encode(results.ComputerName));
            sb.AppendLine("    <style>");
            sb.AppendLine("        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }");
            sb.AppendLine("        .header { background-color: #0078d4; color: white; padding: 20px; border-radius: 5px; }");
            sb.AppendLine("        .summary { background-color: white; padding: 20px; margin: 20px 0; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }");
            sb.AppendLine("        .passed { color: #107c10; font-weight: bold; }");
            sb.AppendLine("        .failed { color: #d13438; font-weight: bold; }");
            sb.AppendLine("        table { width: 100%; border-collapse: collapse; background-color: white; margin: 20px 0; }");
            sb.AppendLine("        th { background-color: #0078d4; color: white; padding: 12px; text-align: left; }");
            sb.AppendLine("        td { padding: 10px; border-bottom: 1px solid #ddd; }");
            sb.AppendLine("        tr:hover { background-color: #f5f5f5; }");
            sb.AppendLine("        .fail-row { background-color: #fff4f4; }");
            sb.AppendLine("        .stat-box { display: inline-block; margin: 10px; padding: 15px; background-color: #f0f0f0; border-radius: 5px; }");
            sb.AppendLine("        code { background-color: #f0f0f0; padding: 2px 6px; border-radius: 3px; font-size: 0.9em; }");
            sb.AppendLine("    </style>");
            sb.AppendLine("</head>");
            sb.AppendLine("<body>");

            // Header
            sb.AppendLine("    <div class=\"header\">");
            sb.AppendLine("        <h1>OmniComply Multi-Framework Compliance Report</h1>");
            sb.AppendFormat("        <p>Computer: {0} | Date: {1}</p>\n",
                Encode(results.ComputerName), results.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"));
            sb.AppendLine("        <p style=\"font-size: 0.9em; opacity: 0.9;\">Frameworks: SOC 2, HIPAA, NIST 800-53, CIS v8, ISO 27001, PCI-DSS, SOX, GDPR, CCPA</p>");
            sb.AppendLine("    </div>");

            // Summary
            sb.AppendLine("    <div class=\"summary\">");
            sb.AppendLine("        <h2>Summary</h2>");
            sb.AppendFormat("        <div class=\"stat-box\"><strong>Total Checks:</strong> {0}</div>\n", results.TotalChecks);
            sb.AppendFormat("        <div class=\"stat-box\"><strong class=\"passed\">Passed:</strong> {0} ({1}%)</div>\n", results.PassedChecks, results.PassPercentage);
            sb.AppendFormat("        <div class=\"stat-box\"><strong class=\"failed\">Failed:</strong> {0}</div>\n", results.FailedChecks);
            sb.AppendFormat("        <div class=\"stat-box\"><strong>Overall Status:</strong> {0}</div>\n",
                results.Compliant ? "<span class=\"passed\">COMPLIANT</span>" : "<span class=\"failed\">NON-COMPLIANT</span>");
            sb.AppendLine("    </div>");

            // Failed checks table
            var failedItems = results.Checks.Where(c => !c.Passed).ToList();
            sb.AppendLine("    <h2>Failed Checks</h2>");
            sb.AppendLine("    <table>");
            sb.AppendLine("        <tr><th>Category</th><th>Check</th><th>Requirement</th><th>Current Value</th><th>Expected Value</th><th>Remediation</th></tr>");

            foreach (var item in failedItems)
            {
                sb.AppendFormat("        <tr class=\"fail-row\"><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td><code>{5}</code></td></tr>\n",
                    Encode(item.Category), Encode(item.Check), Encode(item.Requirement),
                    Encode(item.CurrentValue), Encode(item.ExpectedValue), Encode(item.Remediation));
            }

            sb.AppendLine("    </table>");

            // Intune recommendations
            var intuneItems = failedItems.Where(i => !string.IsNullOrEmpty(i.IntuneRecommendation) && i.IntuneRecommendation != "N/A").ToList();
            sb.AppendLine("    <h2>Intune Policy Recommendations</h2>");
            sb.AppendLine("    <div class=\"summary\"><p>Deploy these settings via Microsoft Intune to remediate failed checks across your fleet:</p></div>");
            sb.AppendLine("    <table>");
            sb.AppendLine("        <tr><th>Check</th><th>Intune Policy Path &amp; Configuration</th></tr>");

            if (intuneItems.Any())
            {
                foreach (var item in intuneItems)
                {
                    sb.AppendFormat("        <tr><td><strong>{0}</strong><br/><small style=\"color: #666;\">{1}</small></td><td>{2}</td></tr>\n",
                        Encode(item.Check), Encode(item.Category), item.IntuneRecommendation);
                }
            }
            else
            {
                sb.AppendLine("        <tr><td colspan=\"2\" style=\"text-align: center; padding: 20px; color: #666;\">No failed checks have Intune policy recommendations available.</td></tr>");
            }

            sb.AppendLine("    </table>");

            // Category breakdown
            sb.AppendLine("    <h2>Category Breakdown</h2>");
            sb.AppendLine("    <table>");
            sb.AppendLine("        <tr><th>Category</th><th>Passed</th><th>Failed</th><th>Total</th><th>Pass %</th></tr>");

            var categories = results.Checks.GroupBy(c => c.Category).OrderBy(g =>
            {
                var total = g.Count();
                var passed = g.Count(c => c.Passed);
                return total > 0 ? (double)passed / total : 0;
            });

            foreach (var cat in categories)
            {
                var passed = cat.Count(c => c.Passed);
                var failed = cat.Count(c => !c.Passed);
                var total = cat.Count();
                var pct = total > 0 ? Math.Round((double)passed / total * 100, 1) : 0;

                sb.AppendFormat("        <tr><td>{0}</td><td class=\"passed\">{1}</td><td class=\"failed\">{2}</td><td>{3}</td><td>{4}%</td></tr>\n",
                    Encode(cat.Key), passed, failed, total, pct);
            }

            sb.AppendLine("    </table>");
            sb.AppendLine("</body>");
            sb.AppendLine("</html>");

            File.WriteAllText(outputPath, sb.ToString(), Encoding.UTF8);
        }

        private static string Encode(string value)
        {
            if (string.IsNullOrEmpty(value)) return "";
            return value
                .Replace("&", "&amp;")
                .Replace("<", "&lt;")
                .Replace(">", "&gt;")
                .Replace("\"", "&quot;");
        }
    }
}
