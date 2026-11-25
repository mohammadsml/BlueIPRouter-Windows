namespace BlueIPRouter.Core.Models;

/// <summary>
/// Shared file locations and constants used by both the WPF UI and the Windows Service.
/// </summary>
public static class BirPaths
{
    public const string AppVersion = "1.0.0";
    public const string ServiceName = "BlueIPRouterService";
    public const string ServiceDisplayName = "BlueIPRouter Background Service";
    public const string PipeName = "BlueIPRouterServicePipe";

    /// <summary>
    /// System-wide directory (ProgramData) for persistent rules, kill switch config, and service logs.
    /// </summary>
    public static string SystemDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "BlueIPRouter");

    public static string PersistentRulesPath => Path.Combine(SystemDir, "rules.json");
    public static string KillSwitchConfigPath => Path.Combine(SystemDir, "killswitch.json");
    public static string BlockListPath => Path.Combine(SystemDir, "blocklist.json");
    public static string DnsCachePath => Path.Combine(SystemDir, "dns-cache.json");
    public static string LearnedServersPath => Path.Combine(SystemDir, "learned-vpn-servers.json");
    public static string AppliedStatePath => Path.Combine(SystemDir, "applied.json");
    public static string StatusPath => Path.Combine(SystemDir, "status.json");
    public static string LogPath => Path.Combine(SystemDir, "service.log");

    /// <summary>
    /// Per-user AppData directory for drafts, profiles, and UI preferences.
    /// </summary>
    public static string UserDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "BlueIPRouter");

    public static string DraftRulesPath => Path.Combine(UserDir, "draft-rules.json");
    public static string DraftKillSwitchPath => Path.Combine(UserDir, "draft-killswitch.json");
}
