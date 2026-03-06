using System;
using System.Diagnostics;
using System.Text;

namespace OmniComply.Core.Helpers
{
    public class ProcessResult
    {
        public int ExitCode { get; set; }
        public string StandardOutput { get; set; }
        public string StandardError { get; set; }
        public bool Success => ExitCode == 0;
    }

    public static class ProcessHelper
    {
        public static ProcessResult Run(string fileName, string arguments, int timeoutMs = 30000)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = arguments,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                };

                var stdout = new StringBuilder();
                var stderr = new StringBuilder();

                using (var process = new Process())
                {
                    process.StartInfo = psi;
                    process.OutputDataReceived += (s, e) =>
                    {
                        if (e.Data != null) stdout.AppendLine(e.Data);
                    };
                    process.ErrorDataReceived += (s, e) =>
                    {
                        if (e.Data != null) stderr.AppendLine(e.Data);
                    };

                    process.Start();
                    process.BeginOutputReadLine();
                    process.BeginErrorReadLine();

                    if (!process.WaitForExit(timeoutMs))
                    {
                        try { process.Kill(); } catch { }
                        return new ProcessResult
                        {
                            ExitCode = -1,
                            StandardOutput = stdout.ToString(),
                            StandardError = "Process timed out"
                        };
                    }

                    // Ensure async reads complete
                    process.WaitForExit();

                    return new ProcessResult
                    {
                        ExitCode = process.ExitCode,
                        StandardOutput = stdout.ToString(),
                        StandardError = stderr.ToString()
                    };
                }
            }
            catch (Exception ex)
            {
                return new ProcessResult
                {
                    ExitCode = -1,
                    StandardOutput = string.Empty,
                    StandardError = ex.Message
                };
            }
        }

        public static ProcessResult RunAuditpol(string arguments)
        {
            return Run("auditpol.exe", arguments);
        }

        public static ProcessResult RunSecedit(string arguments)
        {
            return Run("secedit.exe", arguments);
        }

        public static ProcessResult RunNetSh(string arguments)
        {
            return Run("netsh.exe", arguments);
        }

        public static ProcessResult RunCmd(string command)
        {
            return Run("cmd.exe", "/c " + command);
        }
    }
}
