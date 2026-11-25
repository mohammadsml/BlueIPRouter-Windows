using BlueIPRouter.Core.Utils;

namespace BlueIPRouter.Core.Models;

public sealed record BlockList
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public string Name { get; set; } = string.Empty;
    public List<string> Entries { get; set; } = [];
    public bool Enabled { get; set; } = true;
    public string? SourceUrl { get; set; }

    public static readonly Guid TelegramId = Guid.Parse("7E1E6A00-0000-4000-8000-000000000001");
    public const string TelegramSourceUrl = "https://core.telegram.org/resources/cidr.txt";

    public static BlockList CreateTelegramDefault() => new()
    {
        Id = TelegramId,
        Name = "Telegram",
        Enabled = true,
        SourceUrl = TelegramSourceUrl,
        Entries =
        [
            "91.108.56.0/22", "91.108.4.0/22", "91.108.8.0/22", "91.108.16.0/22", "91.108.12.0/22",
            "149.154.160.0/20", "91.105.192.0/23", "91.108.20.0/22", "185.76.151.0/24", "95.161.64.0/20",
            "2001:b28:f23d::/48", "2001:b28:f23f::/48", "2001:67c:4e8::/48", "2001:b28:f23c::/48", "2a0a:f280::/32"
        ]
    };
}

public enum KillSwitchMode
{
    /// <summary>Block only the listed destinations on the guarded interfaces.</summary>
    Destinations,
    /// <summary>Block everything on the guarded interfaces except what is explicitly allowed.</summary>
    FullSystem
}

public sealed class KillSwitchConfig
{
    public bool Enabled { get; set; }
    public KillSwitchMode Mode { get; set; } = KillSwitchMode.Destinations;
    public List<string> Interfaces { get; set; } = [];
    public List<BlockList> BlockLists { get; set; } = [BlockList.CreateTelegramDefault()];
    public List<string> Allow { get; set; } = [];
    public bool AllowLocalNetworks { get; set; } = true;
    public bool AllowRuleDestinations { get; set; } = true;
    public bool AllowDns { get; set; } = true;
    public bool AllowDhcp { get; set; } = true;
    public bool LearnVpnServers { get; set; } = true;

    public List<string> Validate()
    {
        var errors = new List<string>();
        if (Interfaces.Count == 0) errors.Add("Choose at least one interface to guard");
        foreach (var list in BlockLists)
        {
            foreach (var entry in list.Entries)
            {
                if (IpUtils.NormalizeCidr(entry) is null && !IpUtils.IsValidDomain(entry))
                    errors.Add($"{list.Name}: “{entry}” is not a CIDR, IP or domain");
            }
        }
        foreach (var entry in Allow)
        {
            if (IpUtils.NormalizeCidr(entry) is null && !IpUtils.IsValidDomain(entry))
                errors.Add($"Allow list: “{entry}” is not a CIDR, IP or domain");
        }
        return errors;
    }
}

public sealed class KillSwitchStatus
{
    public bool Active { get; set; }
    public KillSwitchMode Mode { get; set; }
    public List<string> Interfaces { get; set; } = [];
    public List<string> Blocked { get; set; } = [];
    public List<string> Allowed { get; set; } = [];
    public List<string> DnsServers { get; set; } = [];
    public List<string> LearnedServers { get; set; } = [];
    public bool WfpActive { get; set; }
    public List<string> Errors { get; set; } = [];
}

public sealed class BlockEntry
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Value { get; set; } = string.Empty;
    public bool Enabled { get; set; } = true;
    public string Notes { get; set; } = string.Empty;
}

public sealed class BlockListStatus
{
    public bool Active { get; set; }
    public List<string> Denied { get; set; } = [];
    public List<string> Errors { get; set; } = [];
}
