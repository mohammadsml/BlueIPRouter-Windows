using System.Net;
using System.Net.Sockets;

namespace BlueIPRouter.Core.Utils;

public static class IpUtils
{
    public static bool IsValidIPv4(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        return IPAddress.TryParse(value.Trim(), out var ip) && ip.AddressFamily == AddressFamily.InterNetwork;
    }

    public static bool IsValidIPv6(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        return IPAddress.TryParse(value.Trim(), out var ip) && ip.AddressFamily == AddressFamily.InterNetworkV6;
    }

    public static bool IsValidDomain(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        var s = value.Trim().TrimEnd('.').ToLowerInvariant();
        if (s.Length is 0 or > 253) return false;
        if (IsValidIPv4(s) || IsValidIPv6(s)) return false;
        var labels = s.Split('.');
        if (labels.Length < 2) return false;
        foreach (var label in labels)
        {
            if (label.Length is 0 or > 63) return false;
            if (label.StartsWith('-') || label.EndsWith('-')) return false;
            if (!label.All(c => char.IsAsciiLetterOrDigit(c) || c == '-')) return false;
        }
        return true;
    }

    public static uint ParseIPv4UInt32(string ip)
    {
        var bytes = IPAddress.Parse(ip).GetAddressBytes();
        return ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
    }

    public static string FormatIPv4UInt32(uint value)
    {
        return $"{(value >> 24) & 0xFF}.{(value >> 16) & 0xFF}.{(value >> 8) & 0xFF}.{value & 0xFF}";
    }

    public static uint MaskFromPrefix(int prefix)
    {
        if (prefix <= 0) return 0;
        if (prefix >= 32) return 0xFFFFFFFF;
        return 0xFFFFFFFF << (32 - prefix);
    }

    public static int PrefixFromMask(string mask)
    {
        if (!IsValidIPv4(mask)) return 32;
        uint m = ParseIPv4UInt32(mask);
        int count = 0;
        for (int i = 31; i >= 0; i--)
        {
            if ((m & (1u << i)) != 0) count++;
            else break;
        }
        return count;
    }

    public static string? NormalizeCidr(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        var s = raw.Trim().ToLowerInvariant();
        var parts = s.Split('/', 2);
        var addr = parts[0];

        if (IsValidIPv4(addr))
        {
            int prefix = parts.Length == 2 ? (int.TryParse(parts[1], out var p) ? p : -1) : 32;
            if (prefix is < 0 or > 32) return null;
            uint net = ParseIPv4UInt32(addr) & MaskFromPrefix(prefix);
            return $"{FormatIPv4UInt32(net)}/{prefix}";
        }

        if (IsValidIPv6(addr))
        {
            int prefix = parts.Length == 2 ? (int.TryParse(parts[1], out var p) ? p : -1) : 128;
            if (prefix is < 0 or > 128) return null;
            return $"{IPAddress.Parse(addr)}/{prefix}";
        }

        return null;
    }

    public static bool CidrContains(string cidr, string ip)
    {
        var parts = cidr.Split('/', 2);
        if (parts.Length != 2 || !int.TryParse(parts[1], out int prefix)) return false;

        if (IsValidIPv4(parts[0]) && IsValidIPv4(ip))
        {
            uint net = ParseIPv4UInt32(parts[0]);
            uint target = ParseIPv4UInt32(ip);
            uint mask = MaskFromPrefix(prefix);
            return (net & mask) == (target & mask);
        }

        if (IsValidIPv6(parts[0]) && IsValidIPv6(ip))
        {
            var a = IPAddress.Parse(parts[0]).GetAddressBytes();
            var b = IPAddress.Parse(ip).GetAddressBytes();
            int bits = prefix;
            for (int i = 0; i < 16 && bits > 0; i++)
            {
                byte mask = bits >= 8 ? (byte)0xFF : (byte)(0xFF << (8 - bits));
                if ((a[i] & mask) != (b[i] & mask)) return false;
                bits -= 8;
            }
            return true;
        }

        return false;
    }
}
