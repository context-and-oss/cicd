namespace NoLock.Lib;

public static class Fetcher
{
    public static string Describe() => typeof(System.Net.Http.HttpClient).FullName ?? "unknown";
}
