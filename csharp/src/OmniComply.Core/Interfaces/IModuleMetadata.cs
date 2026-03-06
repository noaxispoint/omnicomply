namespace OmniComply.Core.Interfaces
{
    public interface IModuleMetadata
    {
        string Name { get; }
        string Category { get; }
        int Order { get; }
    }
}
