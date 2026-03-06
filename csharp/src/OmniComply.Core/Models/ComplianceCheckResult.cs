namespace OmniComply.Core.Models
{
    public class ComplianceCheckResult
    {
        public string Category { get; set; }
        public string Check { get; set; }
        public string Requirement { get; set; }
        public FrameworkMappings Frameworks { get; set; }
        public bool Passed { get; set; }
        public string CurrentValue { get; set; }
        public string ExpectedValue { get; set; }
        public string Remediation { get; set; }
        public string IntuneRecommendation { get; set; }

        public ComplianceCheckResult()
        {
            Frameworks = new FrameworkMappings();
            IntuneRecommendation = "N/A";
        }
    }
}
