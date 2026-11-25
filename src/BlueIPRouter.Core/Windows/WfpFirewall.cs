using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using BlueIPRouter.Core.Models;
using BlueIPRouter.Core.Utils;

namespace BlueIPRouter.Core.Windows;

/// <summary>
/// Windows Filtering Platform (WFP) engine wrapper for enforcing the Kill Switch and Block List
/// in the Windows kernel, analogous to pf anchors on macOS.
/// </summary>
public static unsafe class WfpFirewall
{
    private static readonly Guid ProviderGuid = Guid.Parse("B10E1900-0001-4000-8000-000000000001");
    private static readonly Guid SubLayerGuid = Guid.Parse("B10E1900-0001-4000-8000-000000000002");

    // FWPM_LAYER_ALE_AUTH_CONNECT_V4 / V6
    private static readonly Guid LayerAuthConnectV4 = Guid.Parse("c38d57d1-05a7-4c33-904f-7fbceee60e82");
    private static readonly Guid LayerAuthConnectV6 = Guid.Parse("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");

    // Condition keys
    private static readonly Guid CondIpRemoteAddress = Guid.Parse("c35a604d-d22b-4e1a-91b4-68f674ee674b");
    private static readonly Guid CondIpLocalInterface = Guid.Parse("4cd62a49-59c3-4969-b7f3-bda5d32890a4");

    private const uint RPC_C_AUTHN_WINNT = 10;
    private const uint FWP_ACTION_BLOCK = 0x00000001 | 0x00001000;
    private const uint FWP_ACTION_PERMIT = 0x00000002 | 0x00001000;
    private const uint FWP_MATCH_EQUAL = 0;
    private const uint FWP_DATA_TYPE_UINT64 = 6;
    private const uint FWP_DATA_TYPE_V4_ADDR_MASK = 259;
    private const uint FWPM_FILTER_FLAG_NONE = 0;

    private static readonly object Sync = new();
    private static readonly List<ulong> ActiveFilterIds = [];

    public static (bool Ok, List<string> Errors) Apply(
        KillSwitchConfig config,
        List<InterfaceSnapshot> interfaces,
        List<string> blockedCidrs,
        List<string> allowedCidrs,
        List<string> deniedCidrs)
    {
        var errors = new List<string>();
        lock (Sync)
        {
            uint openErr = FwpmEngineOpen0(null, RPC_C_AUTHN_WINNT, IntPtr.Zero, IntPtr.Zero, out IntPtr engine);
            if (openErr != 0 || engine == IntPtr.Zero)
            {
                errors.Add($"FwpmEngineOpen0 failed: 0x{openErr:X8} (requires Administrator / LocalSystem)");
                return (false, errors);
            }

            try
            {
                EnsureProviderAndSubLayer(engine);
                ClearFiltersInternal(engine);

                // 1. Global Block List (denied on all interfaces)
                foreach (var cidr in deniedCidrs.Distinct())
                {
                    if (!AddV4CidrFilter(engine, "BlueIPRouter Deny", null, cidr, permit: false, weight: 15, out var id, out var err))
                    {
                        if (err != null) errors.Add(err);
                    }
                    else ActiveFilterIds.Add(id);
                }

                if (!config.Enabled)
                    return (errors.Count == 0, errors);

                var guardedLuids = interfaces
                    .Where(i => config.Interfaces.Contains(i.Name, StringComparer.OrdinalIgnoreCase) && i.Luid != 0)
                    .Select(i => i.Luid)
                    .Distinct()
                    .ToList();

                if (guardedLuids.Count == 0)
                {
                    errors.Add("No active guarded interface LUIDs found for Kill Switch.");
                    return (false, errors);
                }

                foreach (ulong luid in guardedLuids)
                {
                    if (config.Mode == KillSwitchMode.Destinations)
                    {
                        foreach (var cidr in blockedCidrs.Distinct())
                        {
                            if (!AddV4CidrFilter(engine, "BlueIPRouter KS Block", luid, cidr, permit: false, weight: 10, out var id, out var err))
                            {
                                if (err != null) errors.Add(err);
                            }
                            else ActiveFilterIds.Add(id);
                        }
                    }
                    else
                    {
                        // FullSystem mode: permit explicit allow-list on guarded interface, then block all else on guarded interface.
                        foreach (var cidr in allowedCidrs.Distinct())
                        {
                            if (AddV4CidrFilter(engine, "BlueIPRouter KS Allow", luid, cidr, permit: true, weight: 12, out var id, out _))
                                ActiveFilterIds.Add(id);
                        }

                        if (!AddInterfaceBlockAllFilter(engine, "BlueIPRouter KS BlockAll", luid, weight: 1, out var blockId, out var blockErr))
                        {
                            if (blockErr != null) errors.Add(blockErr);
                        }
                        else ActiveFilterIds.Add(blockId);
                    }
                }

                return (errors.Count == 0, errors);
            }
            finally
            {
                FwpmEngineClose0(engine);
            }
        }
    }

    public static void ClearAll()
    {
        lock (Sync)
        {
            uint openErr = FwpmEngineOpen0(null, RPC_C_AUTHN_WINNT, IntPtr.Zero, IntPtr.Zero, out IntPtr engine);
            if (openErr != 0 || engine == IntPtr.Zero) return;
            try
            {
                ClearFiltersInternal(engine);
            }
            finally
            {
                FwpmEngineClose0(engine);
            }
        }
    }

    private static void ClearFiltersInternal(IntPtr engine)
    {
        foreach (var id in ActiveFilterIds)
        {
            FwpmFilterDeleteById0(engine, id);
        }
        ActiveFilterIds.Clear();
    }

    private static void EnsureProviderAndSubLayer(IntPtr engine)
    {
        var providerName = "BlueIPRouter";
        var subLayerName = "BlueIPRouter Firewall Sublayer";
        fixed (char* pName = providerName)
        fixed (char* sName = subLayerName)
        {
            var provider = new FWPM_PROVIDER0
            {
                providerKey = ProviderGuid,
                displayData = new FWPM_DISPLAY_DATA0 { name = (IntPtr)pName }
            };
            FwpmProviderAdd0(engine, ref provider, IntPtr.Zero);

            var subLayer = new FWPM_SUBLAYER0
            {
                subLayerKey = SubLayerGuid,
                displayData = new FWPM_DISPLAY_DATA0 { name = (IntPtr)sName },
                providerKey = ProviderGuid,
                weight = 0xFFFF
            };
            FwpmSubLayerAdd0(engine, ref subLayer, IntPtr.Zero);
        }
    }

    private static bool AddV4CidrFilter(
        IntPtr engine,
        string name,
        ulong? interfaceLuid,
        string cidr,
        bool permit,
        byte weight,
        out ulong filterId,
        out string? error)
    {
        filterId = 0;
        error = null;

        var parts = cidr.Split('/', 2);
        if (parts.Length != 2 || !IpUtils.IsValidIPv4(parts[0]) || !int.TryParse(parts[1], out int prefix))
            return false; // Skip IPv6 in v4-only helper pass

        uint addr = IpUtils.ParseIPv4UInt32(parts[0]);
        uint mask = IpUtils.MaskFromPrefix(prefix);

        var addrMask = new FWP_V4_ADDR_AND_MASK { addr = addr, mask = mask };
        var conds = new List<FWPM_FILTER_CONDITION0>();

        IntPtr addrMaskPtr = Marshal.AllocHGlobal(Marshal.SizeOf<FWP_V4_ADDR_AND_MASK>());
        IntPtr luidPtr = IntPtr.Zero;
        try
        {
            Marshal.StructureToPtr(addrMask, addrMaskPtr, false);
            conds.Add(new FWPM_FILTER_CONDITION0
            {
                fieldKey = CondIpRemoteAddress,
                matchType = FWP_MATCH_EQUAL,
                conditionValue = new FWP_CONDITION_VALUE0
                {
                    type = FWP_DATA_TYPE_V4_ADDR_MASK,
                    valuePtr = addrMaskPtr
                }
            });

            if (interfaceLuid.HasValue)
            {
                luidPtr = Marshal.AllocHGlobal(sizeof(ulong));
                Marshal.WriteInt64(luidPtr, (long)interfaceLuid.Value);
                conds.Add(new FWPM_FILTER_CONDITION0
                {
                    fieldKey = CondIpLocalInterface,
                    matchType = FWP_MATCH_EQUAL,
                    conditionValue = new FWP_CONDITION_VALUE0
                    {
                        type = FWP_DATA_TYPE_UINT64,
                        valuePtr = luidPtr
                    }
                });
            }

            return AddFilterInternal(engine, name, LayerAuthConnectV4, conds.ToArray(), permit, weight, out filterId, out error);
        }
        finally
        {
            Marshal.FreeHGlobal(addrMaskPtr);
            if (luidPtr != IntPtr.Zero) Marshal.FreeHGlobal(luidPtr);
        }
    }

    private static bool AddInterfaceBlockAllFilter(
        IntPtr engine,
        string name,
        ulong interfaceLuid,
        byte weight,
        out ulong filterId,
        out string? error)
    {
        IntPtr luidPtr = Marshal.AllocHGlobal(sizeof(ulong));
        try
        {
            Marshal.WriteInt64(luidPtr, (long)interfaceLuid);
            var cond = new FWPM_FILTER_CONDITION0
            {
                fieldKey = CondIpLocalInterface,
                matchType = FWP_MATCH_EQUAL,
                conditionValue = new FWP_CONDITION_VALUE0
                {
                    type = FWP_DATA_TYPE_UINT64,
                    valuePtr = luidPtr
                }
            };
            return AddFilterInternal(engine, name, LayerAuthConnectV4, [cond], permit: false, weight, out filterId, out error);
        }
        finally
        {
            Marshal.FreeHGlobal(luidPtr);
        }
    }

    private static bool AddFilterInternal(
        IntPtr engine,
        string name,
        Guid layerKey,
        FWPM_FILTER_CONDITION0[] conditions,
        bool permit,
        byte weight,
        out ulong filterId,
        out string? error)
    {
        filterId = 0;
        error = null;
        int condSize = Marshal.SizeOf<FWPM_FILTER_CONDITION0>();
        IntPtr condArrayPtr = Marshal.AllocHGlobal(condSize * conditions.Length);
        try
        {
            for (int i = 0; i < conditions.Length; i++)
                Marshal.StructureToPtr(conditions[i], condArrayPtr + (i * condSize), false);

            fixed (char* pName = name)
            {
                var filter = new FWPM_FILTER0
                {
                    filterKey = Guid.NewGuid(),
                    displayData = new FWPM_DISPLAY_DATA0 { name = (IntPtr)pName },
                    flags = FWPM_FILTER_FLAG_NONE,
                    providerKey = IntPtr.Zero,
                    layerKey = layerKey,
                    subLayerKey = SubLayerGuid,
                    weight = new FWP_VALUE0 { type = 1 /* UINT8 */, uint8 = weight },
                    numFilterConditions = (uint)conditions.Length,
                    filterCondition = condArrayPtr,
                    action = new FWPM_ACTION0 { type = permit ? FWP_ACTION_PERMIT : FWP_ACTION_BLOCK }
                };

                uint err = FwpmFilterAdd0(engine, ref filter, IntPtr.Zero, out filterId);
                if (err != 0)
                {
                    error = $"FwpmFilterAdd0 ({name}) failed: 0x{err:X8}";
                    return false;
                }
                return true;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(condArrayPtr);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FWPM_DISPLAY_DATA0 { public IntPtr name; public IntPtr description; }

    [StructLayout(LayoutKind.Sequential)]
    private struct FWPM_PROVIDER0
    {
        public Guid providerKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public uint flags;
        public IntPtr providerDataSize;
        public IntPtr providerData;
        public IntPtr serviceName;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FWPM_SUBLAYER0
    {
        public Guid subLayerKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public uint flags;
        public Guid providerKey;
        public IntPtr providerDataSize;
        public IntPtr providerData;
        public ushort weight;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FWP_V4_ADDR_AND_MASK { public uint addr; public uint mask; }

    [StructLayout(LayoutKind.Explicit, Size = 16)]
    private struct FWP_VALUE0
    {
        [FieldOffset(0)] public uint type;
        [FieldOffset(8)] public byte uint8;
    }

    [StructLayout(LayoutKind.Explicit, Size = 16)]
    private struct FWP_CONDITION_VALUE0
    {
        [FieldOffset(0)] public uint type;
        [FieldOffset(8)] public IntPtr valuePtr;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FWPM_FILTER_CONDITION0
    {
        public Guid fieldKey;
        public uint matchType;
        public FWP_CONDITION_VALUE0 conditionValue;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FWPM_ACTION0 { public uint type; public Guid filterType; }

    [StructLayout(LayoutKind.Sequential)]
    private struct FWPM_FILTER0
    {
        public Guid filterKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public uint flags;
        public IntPtr providerKey;
        public IntPtr providerDataSize;
        public IntPtr providerData;
        public Guid layerKey;
        public Guid subLayerKey;
        public FWP_VALUE0 weight;
        public uint numFilterConditions;
        public IntPtr filterCondition;
        public FWPM_ACTION0 action;
        public ulong rawContext;
        public IntPtr reserved;
        public ulong filterId;
        public FWP_VALUE0 effectiveWeight;
    }

    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)]
    private static extern uint FwpmEngineOpen0(string? serverName, uint authnService, IntPtr authIdentity, IntPtr session, out IntPtr engineHandle);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmEngineClose0(IntPtr engineHandle);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmProviderAdd0(IntPtr engineHandle, ref FWPM_PROVIDER0 provider, IntPtr sd);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmSubLayerAdd0(IntPtr engineHandle, ref FWPM_SUBLAYER0 subLayer, IntPtr sd);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmFilterAdd0(IntPtr engineHandle, ref FWPM_FILTER0 filter, IntPtr sd, out ulong id);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmFilterDeleteById0(IntPtr engineHandle, ulong id);
}
