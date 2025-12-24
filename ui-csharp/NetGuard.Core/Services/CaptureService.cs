using NetGuard.Core.NativeInterop;
using NetGuard.Core.Models;

namespace NetGuard.Core.Services;

public class CaptureService : IDisposable
{
    private bool _initialized;
    private bool _capturing;
    private readonly Timer? _statsTimer;
    private readonly Timer? _alertTimer;

    public event EventHandler<CaptureStatistics>? StatisticsUpdated;
    public event EventHandler<Alert>? AlertReceived;
    public event EventHandler<bool>? CaptureStateChanged;

    public bool IsInitialized => _initialized;
    public bool IsCapturing => _capturing;

    public CaptureService()
    {
        _statsTimer = new Timer(UpdateStatistics, null, Timeout.Infinite, Timeout.Infinite);
        _alertTimer = new Timer(CheckAlerts, null, Timeout.Infinite, Timeout.Infinite);
    }

    public bool Initialize()
    {
        if (_initialized) return true;

        int result = NativeApi.NetGuard_Initialize();
        _initialized = result == 0;
        return _initialized;
    }

    public List<NetworkDevice> GetNetworkDevices()
    {
        var devices = new List<NetworkDevice>();
        var nativeDevices = new NativeApi.MarshaledDevice[32];
        
        int count = NativeApi.NetGuard_GetDevices(nativeDevices, 32);
        
        for (int i = 0; i < count; i++)
        {
            var nd = nativeDevices[i];
            devices.Add(new NetworkDevice
            {
                Name = nd.Name,
                Description = nd.Description,
                IpAddress = Alert.IpToString(nd.IpAddress),
                MacAddress = nd.MacAddress != null ? BitConverter.ToString(nd.MacAddress) : "",
                IsLoopback = nd.IsLoopback != 0,
                IsUp = nd.IsUp != 0
            });
        }
        
        return devices;
    }

    public bool StartCapture(string deviceName, string? bpfFilter = null)
    {
        if (!_initialized || _capturing) return false;

        NativeApi.NetGuard_SetPromiscuous(1);
        int result = NativeApi.NetGuard_StartCapture(deviceName, bpfFilter);
        
        if (result == 0)
        {
            _capturing = true;
            _statsTimer?.Change(0, 500);
            _alertTimer?.Change(0, 100);
            CaptureStateChanged?.Invoke(this, true);
        }
        
        return _capturing;
    }

    public bool StopCapture()
    {
        if (!_capturing) return true;

        int result = NativeApi.NetGuard_StopCapture();
        _capturing = false;
        _statsTimer?.Change(Timeout.Infinite, Timeout.Infinite);
        _alertTimer?.Change(Timeout.Infinite, Timeout.Infinite);
        CaptureStateChanged?.Invoke(this, false);
        
        return result == 0;
    }

    public CaptureStatistics GetStatistics()
    {
        NativeApi.MarshaledStats stats;
        NativeApi.NetGuard_GetStatistics(out stats);
        
        return new CaptureStatistics
        {
            PacketsCaptured = stats.PacketsCaptured,
            PacketsDropped = stats.PacketsDropped,
            PacketsProcessed = stats.PacketsProcessed,
            BytesCaptured = stats.BytesCaptured,
            TcpPackets = stats.TcpPackets,
            UdpPackets = stats.UdpPackets,
            IcmpPackets = stats.IcmpPackets,
            OtherPackets = stats.OtherPackets,
            AlertsGenerated = stats.AlertsGenerated,
            PortScansDetected = stats.PortScansDetected,
            SignaturesMatched = stats.SignaturesMatched,
            AnomaliesDetected = stats.AnomaliesDetected,
            ActiveFlows = stats.ActiveFlows,
            TotalFlows = stats.TotalFlows,
            PacketsPerSecond = stats.PacketsPerSecond,
            BytesPerSecond = stats.BytesPerSecond,
            UptimeSeconds = stats.UptimeSeconds
        };
    }

    public void EnablePortScanDetection(bool enabled) =>
        NativeApi.NetGuard_EnablePortScanDetection(enabled ? 1 : 0);

    public void EnableSignatureDetection(bool enabled) =>
        NativeApi.NetGuard_EnableSignatureDetection(enabled ? 1 : 0);

    public void EnableAnomalyDetection(bool enabled) =>
        NativeApi.NetGuard_EnableAnomalyDetection(enabled ? 1 : 0);

    public void EnableTlsFingerprinting(bool enabled) =>
        NativeApi.NetGuard_EnableTLSFingerprinting(enabled ? 1 : 0);

    public bool LoadRules(string filePath)
    {
        int result = NativeApi.NetGuard_LoadRules(filePath);
        return result == 0;
    }

    public int GetRuleCount() => NativeApi.NetGuard_GetRuleCount();

    public void TrainBaseline(int durationSeconds) =>
        NativeApi.NetGuard_TrainBaseline(durationSeconds);

    public bool IsBaselineReady() => NativeApi.NetGuard_IsBaselineReady() != 0;

    public double GetAnomalyScore() => NativeApi.NetGuard_GetAnomalyScore();

    public string GetVersion() => NativeApi.NetGuard_GetVersion();

    public string GetLastError() => NativeApi.NetGuard_GetLastError();

    private void UpdateStatistics(object? state)
    {
        if (!_capturing) return;
        var stats = GetStatistics();
        StatisticsUpdated?.Invoke(this, stats);
    }

    private void CheckAlerts(object? state)
    {
        if (!_capturing) return;

        int count = NativeApi.NetGuard_GetPendingAlertCount();
        while (count > 0)
        {
            NativeApi.MarshaledAlert na;
            if (NativeApi.NetGuard_GetNextAlert(out na) != 0)
            {
                var alert = new Alert
                {
                    Timestamp = DateTimeOffset.FromUnixTimeMilliseconds((long)(na.Timestamp / 1000)).DateTime,
                    AttackType = (AttackType)na.AttackType,
                    Severity = (AlertSeverity)na.Severity,
                    SourceIp = Alert.IpToString(na.SrcIp),
                    DestinationIp = Alert.IpToString(na.DstIp),
                    SourcePort = na.SrcPort,
                    DestinationPort = na.DstPort,
                    Protocol = (ProtocolType)na.Protocol,
                    Description = na.Description,
                    RuleName = na.RuleName,
                    Confidence = na.Confidence
                };
                
                AlertReceived?.Invoke(this, alert);
            }
            count--;
        }
    }

    public void Dispose()
    {
        _statsTimer?.Dispose();
        _alertTimer?.Dispose();
        
        if (_capturing) StopCapture();
        if (_initialized) NativeApi.NetGuard_Shutdown();
    }
}
