namespace OmniComply.Core.Models
{
    public class RemediationResult
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public string Details { get; set; }
        public bool RequiresReboot { get; set; }

        public static RemediationResult Succeeded(string message, bool requiresReboot = false)
        {
            return new RemediationResult
            {
                Success = true,
                Message = message,
                RequiresReboot = requiresReboot
            };
        }

        public static RemediationResult Failed(string message, string details = null)
        {
            return new RemediationResult
            {
                Success = false,
                Message = message,
                Details = details
            };
        }
    }
}
