using OmniComply.Core.Models;

namespace OmniComply.Core.Interfaces
{
    public interface IReportGenerator
    {
        string Format { get; }
        string FileExtension { get; }
        void Generate(ComplianceScanResult results, string outputPath);
    }
}
