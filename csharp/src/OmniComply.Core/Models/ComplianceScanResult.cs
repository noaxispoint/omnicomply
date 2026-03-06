using System;
using System.Collections.Generic;
using System.Linq;

namespace OmniComply.Core.Models
{
    public class ComplianceScanResult
    {
        public bool Compliant { get; set; }
        public List<ComplianceCheckResult> Checks { get; set; }
        public DateTime Timestamp { get; set; }
        public string ComputerName { get; set; }
        public string ScriptVersion { get; set; }
        public string WindowsVersion { get; set; }
        public string WindowsBuild { get; set; }

        public int TotalChecks => Checks.Count;
        public int PassedChecks => Checks.Count(c => c.Passed);
        public int FailedChecks => Checks.Count(c => !c.Passed);
        public double PassPercentage => TotalChecks > 0 ? Math.Round((double)PassedChecks / TotalChecks * 100, 1) : 0;

        public ComplianceScanResult()
        {
            Checks = new List<ComplianceCheckResult>();
            Compliant = true;
            Timestamp = DateTime.Now;
            ComputerName = Environment.MachineName;
            ScriptVersion = "2.0.0";
        }
    }
}
