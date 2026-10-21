namespace BlackWallFixture;

[System.Reflection.Obfuscation(Exclude = false, ApplyToMembers = true)]
internal static class _
{
    internal const string Marker = "BLACKWALL_INERT_DOTNET_OBFUSCATED_FIXTURE";
    internal const string Endpoint = "https://dotnet-obfuscated.fixture.invalid/api";
    internal const string Configuration = "campaign=dotnet-obfuscated-inert";

    private static string lI() => Endpoint;

    private static int Il(string І) => І.Length;

    private static int Main()
    {
        // Confusable/short identifiers exercise metadata handling only.
        return Il(Marker) + Il(lI()) + Il(Configuration) == 0 ? 1 : 0;
    }
}
