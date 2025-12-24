using NetGuard.Core;
using System;
using System.Collections.Generic;
using System.Linq;

namespace NetGuard.UI.Services
{
    public class AnomalyService
    {
        public event EventHandler<MarshaledAlert> AnomalyDetected;

        // Configuration
        private const int MovingAverageWindowSize = 10; // Samples
        private const double ThresholdMultiplier = 3.0; // 300% spike
        private const ulong MinPacketThreshold = 100; // Minimum pps to trigger

        private readonly Queue<ulong> _packetRateHistory = new Queue<ulong>();
        private DateTime _lastAnomalyTime = DateTime.MinValue;
        private readonly TimeSpan _cooldown = TimeSpan.FromSeconds(30);

        public void ProcessStats(MarshaledStats stats)
        {
            ulong currentRate = stats.PacketsPerSecond;

            // Calculate Moving Average
            double movingAverage = 0;
            if (_packetRateHistory.Count > 0)
            {
                movingAverage = _packetRateHistory.Average(x => (double)x);
            }

            // Update History
            _packetRateHistory.Enqueue(currentRate);
            if (_packetRateHistory.Count > MovingAverageWindowSize)
            {
                _packetRateHistory.Dequeue();
            }

            // Check for Anomaly
            // Need enough history and minimal traffic level
            if (_packetRateHistory.Count >= MovingAverageWindowSize && currentRate > MinPacketThreshold)
            {
                if (currentRate > movingAverage * ThresholdMultiplier)
                {
                    // Rate Limit Alerts
                    if ((DateTime.Now - _lastAnomalyTime) > _cooldown)
                    {
                        var alert = new MarshaledAlert
                        {
                            Timestamp = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                            Severity = 4, // HIGH
                            AttackType = 99, // Custom type for Anomaly
                            Protocol = "TRAFFIC",
                            SrcIp = 0, // Unknown source for aggregate spike
                            DstIp = 0,
                            SrcPort = 0,
                            DstPort = 0,
                            RuleName = "Traffic Spike Detected",
                            Description = $"Sudden surge in traffic: {currentRate} pps (Baseline: {movingAverage:F1} pps)",
                            Confidence = 0.85f
                        };

                        AnomalyDetected?.Invoke(this, alert);
                        _lastAnomalyTime = DateTime.Now;
                    }
                }
            }
        }
    }
}
