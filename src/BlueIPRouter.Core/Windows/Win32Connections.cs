using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using BlueIPRouter.Core.Models;

namespace BlueIPRouter.Core.Windows;

public static class Win32Connections
{
    public static readonly HashSet<string> VpnCoreNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "xray", "sing-box", "v2ray", "happd", "hiddify", "clash", "mihomo",
        "tun2socks", "trojan", "hysteria", "openvpn", "wireguard"
    };

    public static List<LiveConnection> GetTcpConnections(List<InterfaceSnapshot> interfaces)
    {
        var byAddress = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var iface in interfaces)
        {
            foreach (var a in iface.Ipv4) byAddress[a.Address] = iface.Name;
            foreach (var a in iface.Ipv6) byAddress[a.Address] = iface.Name;
        }

        var result = new List<LiveConnection>();
        var processNames = new Dictionary<int, string>();

        int size = 0;
        _ = GetExtendedTcpTable(IntPtr.Zero, ref size, true, 2 /* AF_INET */, 5 /* TCP_TABLE_OWNER_PID_ALL */, 0);
        if (size <= 0) return result;

        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(buffer, ref size, true, 2, 5, 0) != 0)
                return result;

            int count = Marshal.ReadInt32(buffer);
            IntPtr rowPtr = buffer + 4;
            int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

            for (int i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                rowPtr += rowSize;

                string localIp = new IPAddress(row.localAddr).ToString();
                string remoteIp = new IPAddress(row.remoteAddr).ToString();
                if (remoteIp is "0.0.0.0" or "127.0.0.1") continue;

                int localPort = ((row.localPort & 0xFF) << 8) | ((row.localPort >> 8) & 0xFF);
                int remotePort = ((row.remotePort & 0xFF) << 8) | ((row.remotePort >> 8) & 0xFF);

                if (!processNames.TryGetValue(row.owningPid, out var procName))
                {
                    procName = SafeGetProcessName(row.owningPid);
                    processNames[row.owningPid] = procName;
                }

                byAddress.TryGetValue(localIp, out var ifName);

                result.Add(new LiveConnection
                {
                    Pid = row.owningPid,
                    ProcessName = procName,
                    Protocol = "TCP",
                    LocalIp = localIp,
                    LocalPort = localPort,
                    RemoteIp = remoteIp,
                    RemotePort = remotePort,
                    State = FormatTcpState(row.state),
                    InterfaceName = ifName
                });
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return result;
    }

    public static List<string> DetectVpnServerIps(List<InterfaceSnapshot> interfaces)
    {
        var conns = GetTcpConnections(interfaces);
        return conns
            .Where(c => VpnCoreNames.Contains(c.ProcessName))
            .Select(c => c.RemoteIp)
            .Distinct()
            .OrderBy(ip => ip)
            .ToList();
    }

    private static string SafeGetProcessName(int pid)
    {
        if (pid <= 4) return "System";
        try
        {
            using var p = Process.GetProcessById(pid);
            return p.ProcessName;
        }
        catch
        {
            return $"pid:{pid}";
        }
    }

    private static string FormatTcpState(uint state) => state switch
    {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RCVD",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => state.ToString()
    };

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint state;
        public uint localAddr;
        public int localPort;
        public uint remoteAddr;
        public int remotePort;
        public int owningPid;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref int pdwSize,
        bool bOrder,
        int ulAf,
        int tableClass,
        uint reserved);
}
