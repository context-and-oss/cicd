using Newtonsoft.Json;

var payload = JsonConvert.SerializeObject(new { ok = true });
Console.WriteLine(payload);
