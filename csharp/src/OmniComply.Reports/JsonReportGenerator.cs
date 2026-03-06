using System.ComponentModel.Composition;
using System.IO;
using Newtonsoft.Json;
using OmniComply.Core.Interfaces;
using OmniComply.Core.Models;

namespace OmniComply.Reports
{
    [Export(typeof(IReportGenerator))]
    public class JsonReportGenerator : IReportGenerator
    {
        public string Format => "JSON";
        public string FileExtension => "json";

        public void Generate(ComplianceScanResult results, string outputPath)
        {
            var settings = new JsonSerializerSettings
            {
                Formatting = Formatting.Indented,
                NullValueHandling = NullValueHandling.Include
            };

            var json = JsonConvert.SerializeObject(results, settings);
            File.WriteAllText(outputPath, json, System.Text.Encoding.UTF8);
        }
    }
}
