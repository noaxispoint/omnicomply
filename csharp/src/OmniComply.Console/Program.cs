using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using OmniComply.Core.Engine;
using OmniComply.Core.Helpers;
using OmniComply.Core.Models;

namespace OmniComply.Console
{
    class Program
    {
        private const string Version = "2.0.0";

        static int Main(string[] args)
        {
            try
            {
                var options = ParseArgs(args);

                if (options.ShowHelp)
                {
                    PrintHelp();
                    return options.InvalidArgs ? 1 : 0;
                }

                // Check admin privileges
                if (!AdminHelper.IsRunningAsAdmin())
                {
                    WriteColor("ERROR: This application must be run as Administrator!", ConsoleColor.Red);
                    WriteColor("Please right-click and select 'Run as Administrator'", ConsoleColor.Yellow);
                    return 1;
                }

                PrintBanner();

                // Verify prerequisites
                WriteSubHeader("Verifying Prerequisites");
                WriteColor("  Running with Administrator privileges", ConsoleColor.Green);

                // Create output directory
                if (!options.SkipReports && !Directory.Exists(options.OutputDirectory))
                {
                    Directory.CreateDirectory(options.OutputDirectory);
                    WriteColor("  Created output directory: " + options.OutputDirectory, ConsoleColor.Green);
                }

                System.Console.WriteLine();
                WriteColor("Starting compliance checks...", ConsoleColor.Cyan);
                System.Console.WriteLine();

                // Initialize engine and run checks
                using (var engine = new ComplianceEngine())
                {
                    // Subscribe to progress events
                    engine.ModuleStarted += (s, e) =>
                    {
                        WriteColor(string.Format("[{0}/{1}] Running {2}...", e.ModuleIndex, e.TotalModules, e.ModuleName), ConsoleColor.Cyan);
                    };

                    engine.CheckCompleted += (s, e) =>
                    {
                        if (e.Check.Passed)
                            WriteColor("  [PASS] " + e.Check.Check, ConsoleColor.Green);
                        else
                            WriteColor("  [FAIL] " + e.Check.Check + " - Current: " + e.Check.CurrentValue, ConsoleColor.Red);
                    };

                    ComplianceScanResult scanResult;

                    if (options.QuickCheck)
                    {
                        WriteHeader("OMNICOMPLY QUICK CHECK");
                        scanResult = engine.RunAllChecks();
                    }
                    else if (!string.IsNullOrEmpty(options.ModuleName))
                    {
                        scanResult = engine.RunModule(options.ModuleName);
                    }
                    else
                    {
                        scanResult = engine.RunAllChecks();
                    }

                    // Filter by frameworks if specified
                    if (options.Frameworks.Count > 0)
                    {
                        System.Console.WriteLine();
                        WriteColor("Filtering results for frameworks: " + string.Join(", ", options.Frameworks), ConsoleColor.Yellow);

                        scanResult.Checks = scanResult.Checks
                            .Where(c => c.Frameworks != null && c.Frameworks.HasAnyFramework(options.Frameworks))
                            .ToList();
                        scanResult.Compliant = scanResult.Checks.All(c => c.Passed);
                    }

                    // Print summary
                    PrintSummary(scanResult);

                    // Print failed checks
                    PrintFailedChecks(scanResult);

                    // Print category breakdown
                    PrintCategoryBreakdown(scanResult);

                    // Generate reports
                    if (!options.SkipReports)
                    {
                        WriteHeader("GENERATING REPORTS");
                        try
                        {
                            engine.GenerateReports(scanResult, options.OutputDirectory);
                            var fullPath = Path.GetFullPath(options.OutputDirectory);
                            WriteColor("Reports saved to: " + fullPath, ConsoleColor.Cyan);

                            foreach (var file in Directory.GetFiles(fullPath, "OmniComply-Report-*"))
                            {
                                WriteColor("  " + Path.GetFileName(file), ConsoleColor.Green);
                            }
                        }
                        catch (Exception ex)
                        {
                            WriteColor("Failed to generate reports: " + ex.Message, ConsoleColor.Red);
                        }
                    }

                    // Next steps
                    PrintNextSteps(scanResult);

                    return scanResult.Compliant ? 0 : 1;
                }
            }
            catch (Exception ex)
            {
                WriteColor("Fatal error: " + ex.Message, ConsoleColor.Red);
                WriteColor(ex.StackTrace, ConsoleColor.DarkRed);
                return 1;
            }
        }

        private static void PrintBanner()
        {
            System.Console.WriteLine();
            WriteHeader("OMNICOMPLY v" + Version + " - Universal Compliance Validator");
            WriteColor("Computer: " + Environment.MachineName, ConsoleColor.White);
            WriteColor("OS: " + WmiHelper.GetOsCaption() + " (Build " + WmiHelper.GetOsBuildNumber() + ")", ConsoleColor.White);

            int cpuArch = WmiHelper.GetProcessorArchitecture();
            string archName;
            switch (cpuArch)
            {
                case 0: archName = "x86 (32-bit)"; break;
                case 5: archName = "ARM (32-bit)"; break;
                case 9: archName = "x64 (64-bit)"; break;
                case 12: archName = "ARM64 (64-bit)"; break;
                default: archName = "Unknown (" + cpuArch + ")"; break;
            }
            WriteColor("Architecture: " + archName, ConsoleColor.White);

            if (cpuArch == 5 || cpuArch == 12)
            {
                System.Console.WriteLine();
                WriteColor("  ARM ARCHITECTURE DETECTED", ConsoleColor.Yellow);
                WriteColor("  Some checks may behave differently on ARM devices", ConsoleColor.Yellow);
            }

            WriteColor("Date: " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), ConsoleColor.White);
            WriteColor("User: " + Environment.UserName, ConsoleColor.White);
        }

        private static void PrintSummary(ComplianceScanResult result)
        {
            WriteHeader("COMPLIANCE SUMMARY");
            WriteColor("Total Checks Performed: " + result.TotalChecks, ConsoleColor.White);
            WriteColor(string.Format("Passed: {0} ({1}%)", result.PassedChecks, result.PassPercentage), ConsoleColor.Green);
            WriteColor("Failed: " + result.FailedChecks, ConsoleColor.Red);
            System.Console.WriteLine();

            if (result.Compliant)
            {
                WriteColor("  RESULT: FULLY COMPLIANT", ConsoleColor.Green);
            }
            else
            {
                WriteColor("  RESULT: NON-COMPLIANT", ConsoleColor.Red);
            }
        }

        private static void PrintFailedChecks(ComplianceScanResult result)
        {
            var failedItems = result.Checks.Where(c => !c.Passed).ToList();
            if (!failedItems.Any())
            {
                WriteHeader("FAILED CHECKS SUMMARY");
                WriteColor("No failed checks! All controls are compliant.", ConsoleColor.Green);
                return;
            }

            WriteHeader("FAILED CHECKS SUMMARY");

            var grouped = failedItems.GroupBy(c => c.Category);
            foreach (var group in grouped)
            {
                System.Console.WriteLine();
                WriteColor("Category: " + group.Key, ConsoleColor.Yellow);
                WriteColor(new string('=', 80), ConsoleColor.Yellow);

                foreach (var item in group)
                {
                    System.Console.WriteLine();
                    WriteColor("  Check: " + item.Check, ConsoleColor.White);
                    WriteColor("  Requirement: " + item.Requirement, ConsoleColor.Gray);
                    System.Console.Write("  Current: ");
                    WriteColor(item.CurrentValue, ConsoleColor.Red);
                    System.Console.Write("  Expected: ");
                    WriteColor(item.ExpectedValue, ConsoleColor.Green);
                    System.Console.Write("  Remediation: ");
                    WriteColor(item.Remediation, ConsoleColor.Cyan);
                }
            }
        }

        private static void PrintCategoryBreakdown(ComplianceScanResult result)
        {
            WriteHeader("CATEGORY BREAKDOWN");

            var categories = result.Checks.GroupBy(c => c.Category)
                .Select(g => new
                {
                    Category = g.Key,
                    Passed = g.Count(c => c.Passed),
                    Failed = g.Count(c => !c.Passed),
                    Total = g.Count(),
                    PassPct = g.Count() > 0 ? Math.Round((double)g.Count(c => c.Passed) / g.Count() * 100, 1) : 0
                })
                .OrderBy(c => c.PassPct);

            WriteColor(string.Format("{0,-40} {1,8} {2,8} {3,8} {4,10}",
                "Category", "Passed", "Failed", "Total", "Pass %"), ConsoleColor.White);
            WriteColor(new string('-', 76), ConsoleColor.Gray);

            foreach (var cat in categories)
            {
                var color = cat.PassPct == 100 ? ConsoleColor.Green : cat.PassPct >= 50 ? ConsoleColor.Yellow : ConsoleColor.Red;
                WriteColor(string.Format("{0,-40} {1,8} {2,8} {3,8} {4,9}%",
                    cat.Category.Length > 40 ? cat.Category.Substring(0, 37) + "..." : cat.Category,
                    cat.Passed, cat.Failed, cat.Total, cat.PassPct), color);
            }
        }

        private static void PrintNextSteps(ComplianceScanResult result)
        {
            WriteHeader("NEXT STEPS");
            if (result.FailedChecks > 0)
            {
                WriteColor("1. Review the failed checks above", ConsoleColor.Yellow);
                WriteColor("2. Prioritize remediation based on risk and compliance requirements", ConsoleColor.Yellow);
                WriteColor("3. Re-run this compliance check to verify fixes", ConsoleColor.Yellow);
            }
            else
            {
                WriteColor("Congratulations! All compliance checks passed.", ConsoleColor.Green);
                WriteColor("  Run regular compliance checks (monthly recommended)", ConsoleColor.Gray);
                WriteColor("  Monitor for configuration drift", ConsoleColor.Gray);
            }
            System.Console.WriteLine();
        }

        private static void WriteHeader(string text)
        {
            System.Console.WriteLine();
            WriteColor("========================================", ConsoleColor.Cyan);
            WriteColor(text, ConsoleColor.Cyan);
            WriteColor("========================================", ConsoleColor.Cyan);
            System.Console.WriteLine();
        }

        private static void WriteSubHeader(string text)
        {
            System.Console.WriteLine();
            WriteColor(text, ConsoleColor.Yellow);
            WriteColor(new string('-', text.Length), ConsoleColor.Yellow);
        }

        private static void WriteColor(string text, ConsoleColor color)
        {
            var prev = System.Console.ForegroundColor;
            System.Console.ForegroundColor = color;
            System.Console.WriteLine(text);
            System.Console.ForegroundColor = prev;
        }

        private static Options ParseArgs(string[] args)
        {
            var options = new Options();

            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i].ToLowerInvariant())
                {
                    case "--help":
                    case "-h":
                    case "/?":
                        options.ShowHelp = true;
                        break;
                    case "--output-dir":
                    case "-o":
                        if (i + 1 < args.Length) options.OutputDirectory = args[++i];
                        break;
                    case "--skip-reports":
                        options.SkipReports = true;
                        break;
                    case "--quick-check":
                    case "-q":
                        options.QuickCheck = true;
                        break;
                    case "--module":
                    case "-m":
                        if (i + 1 < args.Length) options.ModuleName = args[++i];
                        break;
                    case "--frameworks":
                    case "-f":
                        if (i + 1 < args.Length)
                        {
                            var frameworks = args[++i].Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                            foreach (var fw in frameworks)
                            {
                                var trimmed = fw.Trim();
                                if (!string.IsNullOrEmpty(trimmed))
                                    options.Frameworks.Add(trimmed);
                            }
                        }
                        break;
                    default:
                        WriteColor("Unknown argument: " + args[i], ConsoleColor.Red);
                        System.Console.WriteLine();
                        options.ShowHelp = true;
                        options.InvalidArgs = true;
                        break;
                }
            }

            return options;
        }

        private static void PrintHelp()
        {
            System.Console.WriteLine("OmniComply v" + Version + " - Universal Multi-Framework Compliance Validator");
            System.Console.WriteLine();
            System.Console.WriteLine("Usage: OmniComply.exe [options]");
            System.Console.WriteLine();
            System.Console.WriteLine("Options:");
            System.Console.WriteLine("  --help, -h            Show this help message");
            System.Console.WriteLine("  --output-dir, -o DIR  Set report output directory (default: .\\reports)");
            System.Console.WriteLine("  --skip-reports        Skip report generation (console output only)");
            System.Console.WriteLine("  --quick-check, -q     Run quick check (critical controls only)");
            System.Console.WriteLine("  --module, -m NAME     Run a specific module by name");
            System.Console.WriteLine("  --frameworks, -f LIST Filter results to specific frameworks (comma-separated)");
            System.Console.WriteLine();
            System.Console.WriteLine("Frameworks: SOC2, HIPAA, NIST, CIS, ISO, PCI, SOX, GDPR, CCPA");
            System.Console.WriteLine();
            System.Console.WriteLine("Examples:");
            System.Console.WriteLine("  OmniComply.exe --frameworks SOC2,HIPAA");
            System.Console.WriteLine("  OmniComply.exe -f GDPR,CCPA --skip-reports");
            System.Console.WriteLine("  OmniComply.exe -f PCI -o C:\\reports\\pci-audit");
        }

        private class Options
        {
            public string OutputDirectory = ".\\reports";
            public bool SkipReports;
            public bool QuickCheck;
            public string ModuleName;
            public bool ShowHelp;
            public List<string> Frameworks = new List<string>();
            public bool InvalidArgs;
        }
    }
}
