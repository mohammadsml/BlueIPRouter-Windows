using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using BlueIPRouter.Core.Models;

namespace BlueIPRouter.Core.Windows;

/// <summary>
/// Direct Win32 IP Helper (iphlpapi.dll) wrapper for reading and modifying the Windows routing table.
/// </summary>
public static unsafe class Win32Routing
{
    private const ushort AF_INET = 2;
    private const ushort AF_INET6 = 23;
    private const ushort AF_UNSPEC = 0;

    public static List<RouteEntry> GetRoutingTable(List<InterfaceSnapshot>? interfaces = null, string? familyFilter = null)
    {
        interfaces ??= Win32Interfaces.GetSnapshot();
        var byIndex = interfaces.Where(i => i.Index > 0).ToDictionary(i => i.Index, i => i.Name);

        ushort family = familyFilter switch
        {
            "IPv4" => AF_INET,
            "IPv6" => AF_INET6,
            _ => AF_UNSPEC
        };

        uint err = GetIpForwardTable2(family, out IntPtr tablePtr);
        if (err != 0 || tablePtr == IntPtr.Zero) return [];

        try
        {
            var table = (MIB_IPFORWARD_TABLE2*)tablePtr;
            int count = (int)table->NumEntries;
            var entries = new List<RouteEntry>(count);
            var rowPtr = (MIB_IPFORWARD_ROW2*)((byte*)tablePtr + Marshal.OffsetOf<MIB_IPFORWARD_TABLE2>(nameof(MIB_IPFORWARD_TABLE2.Table)).ToInt32());

            for (int i = 0; i < count; i++)
            {
                var row = rowPtr[i];
                string dest = FormatSockAddr(row.DestinationPrefix.Prefix);
                string gw = FormatSockAddr(row.NextHop);
                bool isV4 = row.DestinationPrefix.Prefix.si_family == AF_INET;
                string ifName = byIndex.TryGetValue(row.InterfaceIndex, out var n) ? n : $"if#{row.InterfaceIndex}";

                entries.Add(new RouteEntry
                {
                    Id = $"{(isV4 ? "v4" : "v6")}-{i}",
                    Family = isV4 ? "IPv4" : "IPv6",
                    Destination = dest,
                    Prefix = row.DestinationPrefix.PrefixLength,
                    Gateway = gw,
                    InterfaceIndex = row.InterfaceIndex,
                    InterfaceName = ifName,
                    Metric = row.Metric,
                    Protocol = row.Protocol.ToString()
                });
            }

            return entries;
        }
        finally
        {
            FreeMibTable(tablePtr);
        }
    }

    public static RouteLookup? LookupBestRoute(string destinationIp, List<InterfaceSnapshot>? interfaces = null)
    {
        if (!IPAddress.TryParse(destinationIp, out var ip)) return null;
        interfaces ??= Win32Interfaces.GetSnapshot();
        var byIndex = interfaces.Where(i => i.Index > 0).ToDictionary(i => i.Index, i => i.Name);

        var destAddr = ToSockAddrInet(ip);
        uint err = GetBestRoute2(IntPtr.Zero, 0, IntPtr.Zero, ref destAddr, 0, out var bestRow, out _);
        if (err != 0) return null;

        string dest = FormatSockAddr(bestRow.DestinationPrefix.Prefix);
        string gw = FormatSockAddr(bestRow.NextHop);
        string ifName = byIndex.TryGetValue(bestRow.InterfaceIndex, out var n) ? n : $"if#{bestRow.InterfaceIndex}";

        return new RouteLookup
        {
            RouteTo = destinationIp,
            Destination = dest,
            Prefix = bestRow.DestinationPrefix.PrefixLength,
            Gateway = gw is "0.0.0.0" or "::" ? null : gw,
            InterfaceIndex = bestRow.InterfaceIndex,
            InterfaceName = ifName,
            Metric = bestRow.Metric
        };
    }

    public static bool IsRouteInstalled(ManagedRoute route, RouteLookup? lookup)
    {
        if (lookup is null) return false;
        if (lookup.Destination != route.Destination || lookup.Prefix != route.Prefix) return false;
        if (!string.IsNullOrEmpty(route.Gateway))
            return lookup.Gateway == route.Gateway;
        return lookup.InterfaceIndex == route.InterfaceIndex;
    }

    public static (bool Ok, string? Error) AddRoute(ManagedRoute route)
    {
        if (!IPAddress.TryParse(route.Destination, out var destIp) || destIp.AddressFamily != AddressFamily.InterNetwork)
            return (false, $"Invalid IPv4 destination: {route.Destination}");

        InitializeIpForwardEntry(out var row);
        row.InterfaceLuid = route.InterfaceLuid;
        row.InterfaceIndex = route.InterfaceIndex;
        row.DestinationPrefix.Prefix = ToSockAddrInet(destIp);
        row.DestinationPrefix.PrefixLength = (byte)route.Prefix;
        row.Metric = 5; // Low metric so our explicit route wins over default/VPN routes.

        if (!string.IsNullOrEmpty(route.Gateway) && IPAddress.TryParse(route.Gateway, out var gwIp))
            row.NextHop = ToSockAddrInet(gwIp);
        else
            row.NextHop = ToSockAddrInet(IPAddress.Any);

        uint err = CreateIpForwardEntry2(ref row);
        // 5010 = ERROR_OBJECT_ALREADY_EXISTS
        if (err == 0 || err == 5010) return (true, null);
        return (false, $"CreateIpForwardEntry2 failed with Win32 error {err}");
    }

    public static (bool Ok, string? Error) DeleteRoute(ManagedRoute route)
    {
        if (!IPAddress.TryParse(route.Destination, out var destIp))
            return (false, $"Invalid destination: {route.Destination}");

        InitializeIpForwardEntry(out var row);
        row.InterfaceLuid = route.InterfaceLuid;
        row.InterfaceIndex = route.InterfaceIndex;
        row.DestinationPrefix.Prefix = ToSockAddrInet(destIp);
        row.DestinationPrefix.PrefixLength = (byte)route.Prefix;

        if (!string.IsNullOrEmpty(route.Gateway) && IPAddress.TryParse(route.Gateway, out var gwIp))
            row.NextHop = ToSockAddrInet(gwIp);
        else
            row.NextHop = ToSockAddrInet(IPAddress.Any);

        uint err = DeleteIpForwardEntry2(ref row);
        // 1168 = ERROR_NOT_FOUND
        if (err == 0 || err == 1168) return (true, null);
        return (false, $"DeleteIpForwardEntry2 failed with Win32 error {err}");
    }

    private static SOCKADDR_INET ToSockAddrInet(IPAddress ip)
    {
        var addr = new SOCKADDR_INET();
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            addr.si_family = AF_INET;
            var bytes = ip.GetAddressBytes();
            addr.Ipv4Addr = BitConverter.ToUInt32(bytes, 0);
        }
        else
        {
            addr.si_family = AF_INET6;
            var bytes = ip.GetAddressBytes();
            Marshal.Copy(bytes, 0, (IntPtr)addr.Ipv6Bytes, 16);
        }
        return addr;
    }

    private static string FormatSockAddr(SOCKADDR_INET addr)
    {
        if (addr.si_family == AF_INET)
        {
            return new IPAddress(addr.Ipv4Addr).ToString();
        }
        if (addr.si_family == AF_INET6)
        {
            var bytes = new byte[16];
            Marshal.Copy((IntPtr)addr.Ipv6Bytes, bytes, 0, 16);
            return new IPAddress(bytes).ToString();
        }
        return "0.0.0.0";
    }

    [StructLayout(LayoutKind.Explicit, Size = 28)]
    private struct SOCKADDR_INET
    {
        [FieldOffset(0)] public ushort si_family;
        [FieldOffset(4)] public uint Ipv4Addr;
        [FieldOffset(8)] public fixed byte Ipv6Bytes[16];
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IP_ADDRESS_PREFIX
    {
        public SOCKADDR_INET Prefix;
        public byte PrefixLength;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_IPFORWARD_ROW2
    {
        public ulong InterfaceLuid;
        public uint InterfaceIndex;
        public IP_ADDRESS_PREFIX DestinationPrefix;
        public SOCKADDR_INET NextHop;
        public byte SitePrefixLength;
        public uint ValidLifetime;
        public uint PreferredLifetime;
        public uint Metric;
        public int Protocol;
        public byte Loopback;
        public byte AutoconfigureAddress;
        public byte Publish;
        public byte Immortal;
        public uint Age;
        public uint Origin;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_IPFORWARD_TABLE2
    {
        public uint NumEntries;
        public MIB_IPFORWARD_ROW2 Table;
    }

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint GetIpForwardTable2(ushort family, out IntPtr table);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern void FreeMibTable(IntPtr memory);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern void InitializeIpForwardEntry(out MIB_IPFORWARD_ROW2 row);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint CreateIpForwardEntry2(ref MIB_IPFORWARD_ROW2 row);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint DeleteIpForwardEntry2(ref MIB_IPFORWARD_ROW2 row);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint GetBestRoute2(
        IntPtr interfaceLuid,
        uint interfaceIndex,
        IntPtr sourceAddress,
        ref SOCKADDR_INET destinationAddress,
        uint addressSortOptions,
        out MIB_IPFORWARD_ROW2 bestRoute,
        out SOCKADDR_INET bestSourceAddress);
}
