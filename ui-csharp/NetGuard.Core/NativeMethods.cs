using System;
using System.Runtime.InteropServices;

namespace NetGuard.Core
{
    // Structs matching C definitions
    [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Ansi)]
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

    [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Ansi)]
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

    public static class NativeMethods
    {
        private const string DllName = "netguard_core.dll";

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        public static extern int NetGuard_Initialize();

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        public static extern void NetGuard_Shutdown();

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        public static extern int NetGuard_StartCapture(string deviceName, string bpfFilter);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        public static extern int NetGuard_StopCapture();

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        public static extern int NetGuard_IsRunning();

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        public static extern void NetGuard_SetPromiscuous(int enabled);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        public static extern void NetGuard_EnablePortScanDetection(int enabled);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        public static extern void NetGuard_EnableSignatureDetection(int enabled);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        public static extern void NetGuard_EnableAnomalyDetection(int enabled);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        public static extern void NetGuard_EnableTLSFingerprinting(int enabled);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        public static extern int NetGuard_LoadRules(string filePath);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        public static extern int NetGuard_GetRuleCount();

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        public static extern int NetGuard_TrainBaseline(int durationSeconds);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        public static extern int NetGuard_IsBaselineReady();

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        public static extern double NetGuard_GetAnomalyScore();

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        public static extern IntPtr NetGuard_GetVersion(); // Returns char*

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        public static extern IntPtr NetGuard_GetLastError(); // Returns char*

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        public static extern int NetGuard_GetPendingAlertCount();

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        public static extern int NetGuard_GetNextAlert(ref MarshaledAlert alert);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        public static extern int NetGuard_StartPcap(string filepath);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        public static extern int NetGuard_StopPcap();

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        public static extern int NetGuard_GetStatistics(ref MarshaledStats stats);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        public static extern int NetGuard_GetDevices([In, Out] MarshaledDevice[] devices, int maxCount);
    }
}
