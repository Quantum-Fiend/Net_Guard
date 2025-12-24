using System.Runtime.InteropServices;

namespace NetGuard.Core.NativeInterop;

/// <summary>
/// P/Invoke declarations for the native NetGuard C core DLL
/// </summary>
public static class NativeApi
{
    private const string DllName = "netguard_core";

    #region Structures

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    public struct MarshaledAlert
    {
        public ulong Timestamp;
        public int AttackType;
        public int Severity;
        public uint SrcIp;
        public uint DstIp;
        public ushort SrcPort;
        public ushort DstPort;
        public byte Protocol;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string Description;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string RuleName;
        public double Confidence;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct MarshaledStats
    {
        public ulong PacketsCaptured;
        public ulong PacketsDropped;
        public ulong PacketsProcessed;
        public ulong BytesCaptured;
        public ulong TcpPackets;
        public ulong UdpPackets;
        public ulong IcmpPackets;
        public ulong OtherPackets;
        public ulong AlertsGenerated;
        public ulong PortScansDetected;
        public ulong SignaturesMatched;
        public ulong AnomaliesDetected;
        public uint ActiveFlows;
        public ulong TotalFlows;
        public double PacketsPerSecond;
        public double BytesPerSecond;
        public ulong UptimeSeconds;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    public struct MarshaledDevice
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string Name;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 512)]
        public string Description;
        public uint IpAddress;
        public uint Netmask;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
        public byte[] MacAddress;
        public int IsLoopback;
        public int IsUp;
    }

    #endregion

    #region Initialization

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
    public static extern int NetGuard_Initialize();

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
    public static extern void NetGuard_Shutdown();

    #endregion

    #region Capture Control

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Ansi)]
    public static extern int NetGuard_StartCapture(string deviceName, string? bpfFilter);

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
    public static extern int NetGuard_StopCapture();

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
    public static extern int NetGuard_IsRunning();

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
    public static extern void NetGuard_SetPromiscuous(int enabled);

    #endregion

    #region Device Enumeration

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
    public static extern int NetGuard_GetDevices(
        [Out] MarshaledDevice[] devices, 
        int maxCount);

    #endregion

    #region Statistics

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
    public static extern int NetGuard_GetStatistics(out MarshaledStats stats);

    #endregion

    #region Alerts

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
    public static extern int NetGuard_GetPendingAlertCount();

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
    public static extern int NetGuard_GetNextAlert(out MarshaledAlert alert);

    #endregion

    #region Detection Configuration

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
    public static extern void NetGuard_EnablePortScanDetection(int enabled);

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
    public static extern void NetGuard_EnableSignatureDetection(int enabled);

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
    public static extern void NetGuard_EnableAnomalyDetection(int enabled);

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
    public static extern void NetGuard_EnableTLSFingerprinting(int enabled);

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Ansi)]
    public static extern int NetGuard_LoadRules(string filePath);

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
    public static extern int NetGuard_GetRuleCount();

    #endregion

    #region Anomaly Detection

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
    public static extern int NetGuard_TrainBaseline(int durationSeconds);

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
    public static extern int NetGuard_IsBaselineReady();

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
    public static extern double NetGuard_GetAnomalyScore();

    #endregion

    #region Utility

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
    [return: MarshalAs(UnmanagedType.LPStr)]
    public static extern string NetGuard_GetVersion();

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
    [return: MarshalAs(UnmanagedType.LPStr)]
    public static extern string NetGuard_GetLastError();

    #endregion
}
