using System.Text.Json;

namespace BlueIPRouter.Core.Models;

public enum IpcCommandType
{
    GetStatus,
    Apply,
    RemoveAll,
    KillSwitchOff,
    DetectVpn
}

public sealed class IpcRequest
{
    public IpcCommandType Command { get; set; }
    public List<RouteRule>? Rules { get; set; }
    public KillSwitchConfig? KillSwitch { get; set; }
    public List<BlockEntry>? BlockList { get; set; }
}

public sealed class HelperStatus
{
    public string Version { get; set; } = BirPaths.AppVersion;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
    public List<ManagedRoute> AppliedRoutes { get; set; } = [];
    public Dictionary<Guid, RuleStatus> RuleStatuses { get; set; } = [];
    public KillSwitchStatus KillSwitch { get; set; } = new();
    public BlockListStatus BlockList { get; set; } = new();
    public List<string> Errors { get; set; } = [];
}

public sealed class IpcResponse
{
    public bool Ok { get; set; }
    public string? Error { get; set; }
    public HelperStatus? Status { get; set; }
}

public static class BirJson
{
    public static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public static T? Load<T>(string path)
    {
        if (!File.Exists(path)) return default;
        try
        {
            var json = File.ReadAllText(path);
            return JsonSerializer.Deserialize<T>(json, Options);
        }
        catch
        {
            return default;
        }
    }

    public static void Save<T>(string path, T value)
    {
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(value, Options));
        File.Move(tmp, path, overwrite: true);
    }
}
