if (Plugin.Answer() != "42")
{
    throw new InvalidOperationException("Plugin result was incorrect");
}
Console.WriteLine("Plugin assertion passed");
