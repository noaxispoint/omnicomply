using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using OmniComply.Core.Engine;
using OmniComply.Core.Helpers;
using OmniComply.Core.Models;

namespace OmniComply.Wpf.ViewModels
{
    public class MainViewModel : ViewModelBase
    {
        private ComplianceEngine _engine;
        private ComplianceScanResult _scanResult;

        private bool _isScanning;
        private string _statusText;
        private string _currentModuleName;
        private int _progressValue;
        private int _progressMax;
        private int _totalChecks;
        private int _passedChecks;
        private int _failedChecks;
        private double _passPercentage;
        private bool _isCompliant;
        private bool _hasScanResults;
        private string _computerName;
        private string _windowsVersion;
        private string _selectedFrameworkFilter;
        private string _selectedCategoryFilter;
        private ComplianceCheckResult _selectedCheck;

        public MainViewModel()
        {
            Checks = new ObservableCollection<ComplianceCheckResult>();
            FailedChecks = new ObservableCollection<ComplianceCheckResult>();
            CategorySummaries = new ObservableCollection<CategorySummary>();
            FrameworkFilters = new ObservableCollection<string> { "All Frameworks", "SOC 2 / HIPAA", "NIST 800-53", "CIS v8", "ISO 27001", "PCI-DSS v4", "SOX ITGC", "GDPR", "CCPA" };
            CategoryFilters = new ObservableCollection<string> { "All Categories" };
            SelectedFrameworkFilter = "All Frameworks";
            SelectedCategoryFilter = "All Categories";

            RunScanCommand = new RelayCommand(async () => await RunScanAsync(), () => !IsScanning);
            ExportReportsCommand = new RelayCommand(async () => await ExportReportsAsync(), () => HasScanResults && !IsScanning);
            RunRemediationCommand = new RelayCommand(async () => await RunRemediationAsync(), () => HasScanResults && FailedChecks.Count > 0 && !IsScanning);

            ComputerName = Environment.MachineName;
            WindowsVersion = WmiHelper.GetOsCaption();
            StatusText = "Ready. Click 'Run Scan' to begin compliance validation.";
        }

        // Collections
        public ObservableCollection<ComplianceCheckResult> Checks { get; }
        public ObservableCollection<ComplianceCheckResult> FailedChecks { get; }
        public ObservableCollection<CategorySummary> CategorySummaries { get; }
        public ObservableCollection<string> FrameworkFilters { get; }
        public ObservableCollection<string> CategoryFilters { get; }

        // Commands
        public ICommand RunScanCommand { get; }
        public ICommand ExportReportsCommand { get; }
        public ICommand RunRemediationCommand { get; }

        // Properties
        public bool IsScanning { get { return _isScanning; } set { SetProperty(ref _isScanning, value); } }
        public string StatusText { get { return _statusText; } set { SetProperty(ref _statusText, value); } }
        public string CurrentModuleName { get { return _currentModuleName; } set { SetProperty(ref _currentModuleName, value); } }
        public int ProgressValue { get { return _progressValue; } set { SetProperty(ref _progressValue, value); } }
        public int ProgressMax { get { return _progressMax; } set { SetProperty(ref _progressMax, value); } }
        public int TotalChecks { get { return _totalChecks; } set { SetProperty(ref _totalChecks, value); } }
        public int PassedChecks_ { get { return _passedChecks; } set { SetProperty(ref _passedChecks, value); } }
        public int FailedChecks_ { get { return _failedChecks; } set { SetProperty(ref _failedChecks, value); } }
        public double PassPercentage { get { return _passPercentage; } set { SetProperty(ref _passPercentage, value); } }
        public bool IsCompliant { get { return _isCompliant; } set { SetProperty(ref _isCompliant, value); } }
        public bool HasScanResults { get { return _hasScanResults; } set { SetProperty(ref _hasScanResults, value); } }
        public string ComputerName { get { return _computerName; } set { SetProperty(ref _computerName, value); } }
        public string WindowsVersion { get { return _windowsVersion; } set { SetProperty(ref _windowsVersion, value); } }
        public ComplianceCheckResult SelectedCheck { get { return _selectedCheck; } set { SetProperty(ref _selectedCheck, value); } }

        public string SelectedFrameworkFilter
        {
            get { return _selectedFrameworkFilter; }
            set { SetProperty(ref _selectedFrameworkFilter, value); ApplyFilters(); }
        }

        public string SelectedCategoryFilter
        {
            get { return _selectedCategoryFilter; }
            set { SetProperty(ref _selectedCategoryFilter, value); ApplyFilters(); }
        }

        private async Task RunScanAsync()
        {
            IsScanning = true;
            StatusText = "Initializing compliance engine...";
            Checks.Clear();
            FailedChecks.Clear();
            CategorySummaries.Clear();

            try
            {
                await Task.Run(() =>
                {
                    _engine = new ComplianceEngine();

                    _engine.ModuleStarted += (s, e) =>
                    {
                        Application.Current.Dispatcher.Invoke(() =>
                        {
                            CurrentModuleName = e.ModuleName;
                            ProgressMax = e.TotalModules;
                            ProgressValue = e.ModuleIndex;
                            StatusText = string.Format("[{0}/{1}] Running {2}...", e.ModuleIndex, e.TotalModules, e.ModuleName);
                        });
                    };

                    _engine.CheckCompleted += (s, e) =>
                    {
                        Application.Current.Dispatcher.Invoke(() =>
                        {
                            Checks.Add(e.Check);
                            if (!e.Check.Passed) FailedChecks.Add(e.Check);
                        });
                    };

                    _scanResult = _engine.RunAllChecks();
                });

                // Update summary
                TotalChecks = _scanResult.TotalChecks;
                PassedChecks_ = _scanResult.PassedChecks;
                FailedChecks_ = _scanResult.FailedChecks;
                PassPercentage = _scanResult.PassPercentage;
                IsCompliant = _scanResult.Compliant;
                HasScanResults = true;

                // Build category summaries
                var groups = _scanResult.Checks.GroupBy(c => c.Category);
                foreach (var g in groups.OrderBy(x => x.Count(c => c.Passed) * 100.0 / x.Count()))
                {
                    CategorySummaries.Add(new CategorySummary
                    {
                        Category = g.Key,
                        Passed = g.Count(c => c.Passed),
                        Failed = g.Count(c => !c.Passed),
                        Total = g.Count(),
                        PassPercentage = Math.Round(g.Count(c => c.Passed) * 100.0 / g.Count(), 1)
                    });
                }

                // Update category filters
                CategoryFilters.Clear();
                CategoryFilters.Add("All Categories");
                foreach (var cat in groups.Select(g => g.Key).OrderBy(c => c))
                    CategoryFilters.Add(cat);

                StatusText = string.Format("Scan complete. {0}/{1} checks passed ({2}%)",
                    PassedChecks_, TotalChecks, PassPercentage);
            }
            catch (Exception ex)
            {
                StatusText = "Scan failed: " + ex.Message;
                MessageBox.Show("Scan failed: " + ex.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                IsScanning = false;
            }
        }

        private async Task ExportReportsAsync()
        {
            if (_scanResult == null) return;

            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                Title = "Select output directory for reports",
                FileName = "SelectFolder",
                Filter = "Directory|*.directory",
                CheckFileExists = false
            };

            // Use folder browser approach: just use a fixed reports directory
            var outputDir = Path.Combine(Environment.CurrentDirectory, "reports");

            StatusText = "Generating reports...";
            try
            {
                await Task.Run(() => _engine.GenerateReports(_scanResult, outputDir));
                StatusText = "Reports saved to: " + Path.GetFullPath(outputDir);
                MessageBox.Show("Reports saved to:\n" + Path.GetFullPath(outputDir), "Reports Generated",
                    MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                StatusText = "Report generation failed: " + ex.Message;
            }
        }

        private async Task RunRemediationAsync()
        {
            var result = MessageBox.Show(
                "This will apply system changes to fix failed compliance checks.\n\n" +
                "WARNING: Some changes may require a system restart.\n\n" +
                "Do you want to continue?",
                "Confirm Remediation",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (result != MessageBoxResult.Yes) return;

            StatusText = "Running remediation actions...";
            IsScanning = true;

            try
            {
                await Task.Run(() =>
                {
                    foreach (var action in _engine.RemediationActions)
                    {
                        Application.Current.Dispatcher.Invoke(() =>
                            StatusText = "Remediating: " + action.Value.Name);
                        action.Value.Execute();
                    }
                });

                StatusText = "Remediation complete. Run a new scan to verify.";
                MessageBox.Show("Remediation complete.\nPlease run a new scan to verify the fixes.",
                    "Remediation Complete", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                StatusText = "Remediation failed: " + ex.Message;
            }
            finally
            {
                IsScanning = false;
            }
        }

        private void ApplyFilters()
        {
            if (_scanResult == null) return;

            Checks.Clear();
            foreach (var check in _scanResult.Checks)
            {
                if (SelectedCategoryFilter != "All Categories" && check.Category != SelectedCategoryFilter)
                    continue;

                if (SelectedFrameworkFilter != "All Frameworks" && !MatchesFramework(check, SelectedFrameworkFilter))
                    continue;

                Checks.Add(check);
            }
        }

        private static bool MatchesFramework(ComplianceCheckResult check, string framework)
        {
            if (check.Frameworks == null) return false;
            switch (framework)
            {
                case "NIST 800-53": return !string.IsNullOrEmpty(check.Frameworks.NIST_800_53);
                case "CIS v8": return !string.IsNullOrEmpty(check.Frameworks.CIS_Controls_v8);
                case "ISO 27001": return !string.IsNullOrEmpty(check.Frameworks.ISO_27001);
                case "PCI-DSS v4": return !string.IsNullOrEmpty(check.Frameworks.PCI_DSS_v4);
                case "SOX ITGC": return !string.IsNullOrEmpty(check.Frameworks.SOX_ITGC);
                case "GDPR": return !string.IsNullOrEmpty(check.Frameworks.GDPR);
                case "CCPA": return !string.IsNullOrEmpty(check.Frameworks.CCPA);
                default: return true;
            }
        }
    }

    public class CategorySummary
    {
        public string Category { get; set; }
        public int Passed { get; set; }
        public int Failed { get; set; }
        public int Total { get; set; }
        public double PassPercentage { get; set; }
    }
}
