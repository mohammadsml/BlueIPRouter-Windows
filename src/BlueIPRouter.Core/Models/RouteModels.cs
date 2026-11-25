using System.Text.Json.Serialization;
using BlueIPRouter.Core.Utils;

namespace BlueIPRouter.Core.Models;

public enum RouteViaKind
{
    InterfaceRouter,
    InterfaceDirect,
    SpecificGateway
}

public sealed record RouteVia
{
    public RouteViaKind Kind { get; init; } = RouteViaKind.InterfaceRouter;
    public string? InterfaceName { get; init; }
    public string? GatewayIp { get; init; }

    [JsonIgnore]
    public string ModeLabel => Kind switch
    {
        RouteViaKind.InterfaceRouter => "Interface router",
        RouteViaKind.InterfaceDirect => "Direct on interface",
        RouteViaKind.SpecificGateway => "Specific gateway",
        _ => "Unknown"
    };

    public string? ValidationError() => Kind switch
    {
        RouteViaKind.InterfaceRouter or RouteViaKind.InterfaceDirect =>
            string.IsNullOrWhiteSpace(InterfaceName) ? "Choose a valid interface" : null,
        RouteViaKind.SpecificGateway =>
            IpUtils.IsValidIPv4(GatewayIp) ? null : "Gateway must be an IPv4 address",
        _ => "Invalid route mode"
    };
}

public sealed record RouteRule
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public string Name { get; set; } = string.Empty;
    public List<string> Destinations { get; set; } = [];
    public RouteVia Via { get; set; } = new();
    public bool Enabled { get; set; } = true;
    public bool Persistent { get; set; } = true;
    public string Notes { get; set; } = string.Empty;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
    public bool KeepRoutesOnRemove { get; set; }

    public List<string> Validate()
    {
        var errors = new List<string>();
        if (string.IsNullOrWhiteSpace(Name)) errors.Add("Name is required");
        if (Destinations.Count == 0) errors.Add("Add at least one IP, network or domain");
        foreach (var d in Destinations)
        {
            if (DestinationParser.Parse(d) is null)
                errors.Add($"“{d}” is not a valid IPv4 address, CIDR network or domain");
        }
        if (Via.ValidationError() is { } viaErr) errors.Add(viaErr);
        return errors;
    }

    public bool SameContent(RouteRule other) =>
        Id == other.Id &&
        Name == other.Name &&
        Destinations.SequenceEqual(other.Destinations) &&
        Via == other.Via &&
        Enabled == other.Enabled &&
        Persistent == other.Persistent &&
        Notes == other.Notes &&
        KeepRoutesOnRemove == other.KeepRoutesOnRemove;
}

public enum DestinationKind { Host, Network, Domain }

public sealed record ParsedDestination(DestinationKind Kind, string Address, int Prefix = 32);

public static class DestinationParser
{
    public static ParsedDestination? Parse(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        var s = raw.Trim().ToLowerInvariant();
        int slash = s.IndexOf('/');
        if (slash >= 0)
        {
            var addr = s[..slash];
            if (!IpUtils.IsValidIPv4(addr) || !int.TryParse(s[(slash + 1)..], out int prefix) || prefix is < 1 or > 32)
                return null;
            if (prefix == 32)
                return new ParsedDestination(DestinationKind.Host, IpUtils.FormatIPv4UInt32(IpUtils.ParseIPv4UInt32(addr)), 32);
            uint masked = IpUtils.ParseIPv4UInt32(addr) & IpUtils.MaskFromPrefix(prefix);
            return new ParsedDestination(DestinationKind.Network, IpUtils.FormatIPv4UInt32(masked), prefix);
        }
        if (IpUtils.IsValidIPv4(s))
            return new ParsedDestination(DestinationKind.Host, IpUtils.FormatIPv4UInt32(IpUtils.ParseIPv4UInt32(s)), 32);
        if (IpUtils.IsValidDomain(s))
            return new ParsedDestination(DestinationKind.Domain, s.TrimEnd('.'), 32);
        return null;
    }
}

public sealed record ManagedRoute(
    Guid RuleId,
    string RuleName,
    string Destination,
    int Prefix,
    string? Gateway,
    string? InterfaceName,
    uint InterfaceIndex,
    ulong InterfaceLuid,
    string? Domain,
    bool KeepOnRemove)
{
    [JsonIgnore]
    public bool IsHost => Prefix == 32;

    [JsonIgnore]
    public string DestinationLabel => IsHost ? Destination : $"{Destination}/{Prefix}";

    [JsonIgnore]
    public string NextHopLabel => !string.IsNullOrEmpty(Gateway) ? Gateway : (InterfaceName ?? $"if#{InterfaceIndex}");
}

public enum RuleState { Applied, Waiting, Partial, Failed, Disabled }

public sealed class RuleStatus
{
    public Guid RuleId { get; set; }
    public RuleState State { get; set; } = RuleState.Disabled;
    public List<string> Messages { get; set; } = [];
    public Dictionary<string, List<string>> Resolved { get; set; } = [];
    public int LiveCount { get; set; }
    public int ExpectedCount { get; set; }
}

public sealed class RouteEntry
{
    public string Id { get; set; } = string.Empty;
    public string Family { get; set; } = "IPv4";
    public string Destination { get; set; } = string.Empty;
    public int Prefix { get; set; }
    public string Gateway { get; set; } = string.Empty;
    public uint InterfaceIndex { get; set; }
    public string InterfaceName { get; set; } = string.Empty;
    public uint Metric { get; set; }
    public string Protocol { get; set; } = string.Empty;
    public bool IsDefault => Destination == "0.0.0.0" && Prefix == 0 || Destination == "::" && Prefix == 0;
    public string DestinationLabel => $"{Destination}/{Prefix}";
}

public sealed class RouteLookup
{
    public string RouteTo { get; set; } = string.Empty;
    public string Destination { get; set; } = string.Empty;
    public int Prefix { get; set; }
    public string? Gateway { get; set; }
    public uint InterfaceIndex { get; set; }
    public string? InterfaceName { get; set; }
    public uint Metric { get; set; }
}
