namespace NetGuard.Core.Models;

public enum AlertSeverity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}

public enum AttackType
{
    None = 0,
    PortScanSyn = 1,
    PortScanFin = 2,
    PortScanNull = 3,
    PortScanXmas = 4,
    PortScanUdp = 5,
    DosSynFlood = 10,
    DosUdpFlood = 11,
    DosIcmpFlood = 12,
    SignatureMatch = 20,
    AnomalyRate = 30,
    AnomalyEntropy = 31,
    AnomalyBehavior = 32,
    TlsSuspicious = 40,
    DataExfiltration = 50
}

public enum ProtocolType
{
    Unknown = 0,
    Tcp = 6,
    Udp = 17,
    Icmp = 1
}

public class Alert
{
    public DateTime Timestamp { get; set; }
    public AttackType AttackType { get; set; }
    public AlertSeverity Severity { get; set; }
    public string SourceIp { get; set; } = string.Empty;
    public string DestinationIp { get; set; } = string.Empty;
    public int SourcePort { get; set; }
    public int DestinationPort { get; set; }
    public ProtocolType Protocol { get; set; }
    public string Description { get; set; } = string.Empty;
    public string RuleName { get; set; } = string.Empty;
    public double Confidence { get; set; }

    public string SeverityColor => Severity switch
    {
        AlertSeverity.Critical => "#FF1744",
        AlertSeverity.High => "#FF5722",
        AlertSeverity.Medium => "#FFC107",
        AlertSeverity.Low => "#4CAF50",
        _ => "#2196F3"
    };

    public static string IpToString(uint ip)
    {
        return $"{(ip >> 24) & 0xFF}.{(ip >> 16) & 0xFF}.{(ip >> 8) & 0xFF}.{ip & 0xFF}";
    }
}

public class NetworkDevice
{
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string IpAddress { get; set; } = string.Empty;
    public string MacAddress { get; set; } = string.Empty;
    public bool IsLoopback { get; set; }
    public bool IsUp { get; set; }

    public string DisplayName => string.IsNullOrEmpty(Description) ? Name : Description;
}

public class CaptureStatistics
{
    public ulong PacketsCaptured { get; set; }
    public ulong PacketsDropped { get; set; }
    public ulong PacketsProcessed { get; set; }
    public ulong BytesCaptured { get; set; }
    public ulong TcpPackets { get; set; }
    public ulong UdpPackets { get; set; }
    public ulong IcmpPackets { get; set; }
    public ulong OtherPackets { get; set; }
    public ulong AlertsGenerated { get; set; }
    public ulong PortScansDetected { get; set; }
    public ulong SignaturesMatched { get; set; }
    public ulong AnomaliesDetected { get; set; }
    public uint ActiveFlows { get; set; }
    public ulong TotalFlows { get; set; }
    public double PacketsPerSecond { get; set; }
    public double BytesPerSecond { get; set; }
    public ulong UptimeSeconds { get; set; }

    public string FormattedBytes => FormatBytes(BytesCaptured);
    public string FormattedBps => FormatBytes((ulong)BytesPerSecond) + "/s";

    private static string FormatBytes(ulong bytes)
    {
        string[] suffixes = { "B", "KB", "MB", "GB", "TB" };
        int i = 0;
        double size = bytes;
        while (size >= 1024 && i < suffixes.Length - 1)
        {
            size /= 1024;
            i++;
        }
        return $"{size:F2} {suffixes[i]}";
    }
}

public class DetectionRule
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Pattern { get; set; } = string.Empty;
    public ProtocolType Protocol { get; set; }
    public int Port { get; set; }
    public AlertSeverity Severity { get; set; }
    public bool Enabled { get; set; } = true;
}
