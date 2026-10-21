namespace BlackWallFixture;

internal static class Program
{
    internal const string Marker = "BLACKWALL_INERT_DOTNET_FIXTURE";
    internal const string Endpoint = "https://dotnet.fixture.invalid/api";
    internal const string Configuration = "campaign=dotnet-inert";

    private static int Main()
    {
        // Deliberately inert: preserve constants in IL without any external I/O.
        return Marker.Length + Endpoint.Length + Configuration.Length == 0 ? 1 : 0;
    }
}
