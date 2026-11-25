using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using BlueIPRouter.Core.Models;

namespace BlueIPRouter.Core.Windows;

public static class Win32Interfaces
{
    public static List<InterfaceSnapshot> GetSnapshot()
    {
        var result = new List<InterfaceSnapshot>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            var props = nic.GetIPProperties();
            var ipv4 = new List<InterfaceAddress>();
            var ipv6 = new List<InterfaceAddress>();

            foreach (var uni in props.UnicastAddresses)
            {
                if (uni.Address.AddressFamily == AddressFamily.InterNetwork)
                {
                    ipv4.Add(new InterfaceAddress
                    {
                        Address = uni.Address.ToString(),
                        PrefixLength = uni.PrefixLength
                    });
                }
                else if (uni.Address.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    var addrStr = uni.Address.ToString().Split('%')[0];
                    ipv6.Add(new InterfaceAddress
                    {
                        Address = addrStr,
                        PrefixLength = uni.PrefixLength
                    });
                }
            }

            uint index = 0;
            ulong luid = 0;
            try
            {
                if (nic.Supports(NetworkInterfaceComponent.IPv4))
                {
                    var v4Props = props.GetIPv4Properties();
                    index = (uint)v4Props.Index;
                }
                else if (nic.Supports(NetworkInterfaceComponent.IPv6))
                {
                    var v6Props = props.GetIPv6Properties();
                    index = (uint)v6Props.Index;
                }
            }
            catch
            {
                // Some virtual adapters throw if IPv4/IPv6 properties are unavailable.
            }

            if (index > 0)
            {
                ConvertInterfaceIndexToLuid(index, out luid);
            }

            var stats = nic.GetIPStatistics();
            uint mtu = 0;
            try
            {
                if (nic.Supports(NetworkInterfaceComponent.IPv4))
                    mtu = (uint)props.GetIPv4Properties().Mtu;
            }
            catch { }

            var macBytes = nic.GetPhysicalAddress().GetAddressBytes();
            string? mac = macBytes.Length == 6
                ? string.Join(":", macBytes.Select(b => b.ToString("x2")))
                : null;

            var kind = Classify(nic);

            result.Add(new InterfaceSnapshot
            {
                Name = nic.Name,
                Description = nic.Description,
                AdapterGuid = nic.Id,
                Index = index,
                Luid = luid,
                Kind = kind,
                IsUp = nic.OperationalStatus == OperationalStatus.Up,
                IsLoopback = nic.NetworkInterfaceType == NetworkInterfaceType.Loopback,
                IsTunnel = kind is InterfaceKind.Tunnel or InterfaceKind.Ppp,
                Mtu = mtu,
                MacAddress = mac,
                Ipv4 = ipv4,
                Ipv6 = ipv6,
                Gateways = props.GatewayAddresses
                    .Where(g => g.Address.AddressFamily == AddressFamily.InterNetwork)
                    .Select(g => g.Address.ToString())
                    .Distinct()
                    .ToList(),
                DnsServers = props.DnsAddresses
                    .Select(d => d.ToString().Split('%')[0])
                    .Distinct()
                    .ToList(),
                RxBytes = (ulong)Math.Max(0, stats.BytesReceived),
                TxBytes = (ulong)Math.Max(0, stats.BytesSent),
                RxPackets = (ulong)Math.Max(0, stats.UnicastPacketsReceived),
                TxPackets = (ulong)Math.Max(0, stats.UnicastPacketsSent)
            });
        }
        return result;
    }

    private static InterfaceKind Classify(NetworkInterface nic)
    {
        if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback)
            return InterfaceKind.Loopback;
        if (nic.NetworkInterfaceType == NetworkInterfaceType.Wireless80211)
            return InterfaceKind.Wifi;
        if (nic.NetworkInterfaceType == NetworkInterfaceType.Ppp)
            return InterfaceKind.Ppp;
        if (nic.NetworkInterfaceType == NetworkInterfaceType.Tunnel)
            return InterfaceKind.Tunnel;

        var desc = nic.Description.ToLowerInvariant();
        var name = nic.Name.ToLowerInvariant();
        if (desc.Contains("wintun") || desc.Contains("wireguard") || desc.Contains("tap-windows") ||
            desc.Contains("openvpn") || desc.Contains("sing-box") || desc.Contains("xray") ||
            desc.Contains("cisco") || desc.Contains("vpn") || name.Contains("tun") || name.Contains("wg"))
        {
            return InterfaceKind.Tunnel;
        }

        if (nic.NetworkInterfaceType is NetworkInterfaceType.Ethernet or NetworkInterfaceType.GigabitEthernet)
            return InterfaceKind.Ethernet;

        return InterfaceKind.Other;
    }

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint ConvertInterfaceIndexToLuid(uint interfaceIndex, out ulong interfaceLuid);
}
