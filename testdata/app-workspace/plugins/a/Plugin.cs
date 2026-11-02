using Newtonsoft.Json;

public static class Plugin
{
    public static string Answer() => JsonConvert.SerializeObject(42);
}
