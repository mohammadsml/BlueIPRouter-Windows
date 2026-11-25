namespace BlueIPRouter.Core.Models;

public enum InterfaceKind
{
    Wifi,
    Ethernet,
    Tunnel,
    Ppp,
    Loopback,
    Other
}

public sealed class InterfaceAddress
{
    public string Address { get; set; } = string.Empty;
    public int PrefixLength { get; set; }
}

public sealed class InterfaceSnapshot
{
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string AdapterGuid { get; set; } = string.Empty;
    public uint Index { get; set; }
    public ulong Luid { get; set; }
    public InterfaceKind Kind { get; set; }
    public bool IsUp { get; set; }
    public bool IsLoopback { get; set; }
    public bool IsTunnel { get; set; }
    public uint Mtu { get; set; }
    public string? MacAddress { get; set; }
    public List<InterfaceAddress> Ipv4 { get; set; } = [];
    public List<InterfaceAddress> Ipv6 { get; set; } = [];
    public List<string> Gateways { get; set; } = [];
    public List<string> DnsServers { get; set; } = [];
    public ulong RxBytes { get; set; }
    public ulong TxBytes { get; set; }
    public ulong RxPackets { get; set; }
    public ulong TxPackets { get; set; }

    public string? PrimaryIpv4 => Ipv4.FirstOrDefault()?.Address;
    public string? PrimaryGateway => Gateways.FirstOrDefault();
    public bool IsVpn => Kind is InterfaceKind.Tunnel or InterfaceKind.Ppp;
}

public sealed class LiveConnection
{
    public int Pid { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public string Protocol { get; set; } = "TCP";
    public string LocalIp { get; set; } = string.Empty;
    public int LocalPort { get; set; }
    public string RemoteIp { get; set; } = string.Empty;
    public int RemotePort { get; set; }
    public string State { get; set; } = string.Empty;
    public string? InterfaceName { get; set; }
}
