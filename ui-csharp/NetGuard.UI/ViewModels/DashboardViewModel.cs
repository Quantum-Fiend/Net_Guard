using CommunityToolkit.Mvvm.ComponentModel;
using NetGuard.Core;
using System.Collections.ObjectModel;
using System.Windows.Threading;
using System;
using NetGuard.UI.Services;
using System.Threading.Tasks;
using LiveChartsCore;
using LiveChartsCore.SkiaSharpView;
using System.Collections.Generic;
using CommunityToolkit.Mvvm.Input;
using System.Windows;

namespace NetGuard.UI.ViewModels
{
    public partial class DashboardViewModel : ObservableObject
    {
        private readonly PacketEngine _engine;
        private readonly AlertRepository _alertRepo;
        private readonly FirewallService _firewallService;

        [ObservableProperty]
        private ulong _totalPackets;

        [ObservableProperty]
        private ulong _bytesCaptured;

        [ObservableProperty]
        private double _packetsPerSecond;

        [ObservableProperty]
        private double _bytesPerSecond;
        
        [ObservableProperty]
        private ulong _alertsCount;

        [ObservableProperty]
        private ulong _activeFlows;

        [ObservableProperty]
        private ISeries[] _protocolSeries;
        
        public ObservableCollection<AlertViewModel> RecentAlerts { get; } = new();

        public DashboardViewModel(PacketEngine engine, AlertRepository alertRepo, FirewallService firewallService)
        {
            _engine = engine;
            _alertRepo = alertRepo;
            _firewallService = firewallService;
            _engine.StatsUpdated += OnStatsUpdated;
            _engine.AlertReceived += OnAlertReceived;
        }

        private void OnStatsUpdated(object sender, MarshaledStats stats)
        {
            // Marshal back to UI thread
            System.Windows.Application.Current.Dispatcher.Invoke(() =>
            {
                TotalPackets = stats.PacketsCaptured;
                BytesCaptured = stats.BytesCaptured;
                PacketsPerSecond = stats.PacketsPerSecond;
                BytesPerSecond = stats.BytesPerSecond;
                AlertsCount = stats.AlertsGenerated;
                ActiveFlows = stats.ActiveFlows;

                // Update charts
                ProtocolSeries = new ISeries[]
                {
                    new PieSeries<ulong> { Values = new[] { stats.TcpPackets }, Name = "TCP" },
                    new PieSeries<ulong> { Values = new[] { stats.UdpPackets }, Name = "UDP" },
                    new PieSeries<ulong> { Values = new[] { stats.IcmpPackets }, Name = "ICMP" },
                    new PieSeries<ulong> { Values = new[] { stats.OtherPackets }, Name = "Other" }
                };
            });
        }

        private void OnAlertReceived(object sender, MarshaledAlert alert)
        {
             System.Windows.Application.Current.Dispatcher.Invoke(() =>
             {
                 var vm = new AlertViewModel(alert);
                 RecentAlerts.Insert(0, vm);
                 if (RecentAlerts.Count > 100)
                 {
                     RecentAlerts.RemoveAt(RecentAlerts.Count - 1);
                 }

                 // Persist to DB
                 if (_alertRepo != null)
                 {
                     string src = vm.Source.ToString(); // Basic optimization
                     string dst = vm.Destination.ToString(); 
                     Task.Run(() => _alertRepo.AddAlertAsync(alert, src, dst));
                 }
             });
        }

        [RelayCommand]
        private async Task BlockIp(AlertViewModel alert)
        {
            if (alert == null) return;
            
            bool result = await _firewallService.BlockIpAddressAsync(alert.Source);
            if (result)
            {
                MessageBox.Show($"Blocked IP: {alert.Source}", "Active Response", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                MessageBox.Show($"Failed to block IP: {alert.Source}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }

    public class AlertViewModel
    {
        public string Timestamp { get; }
        public string Severity { get; }
        public string Type { get; }
        public string Source { get; }
        public string Destination { get; }
        public string Description { get; }

        public AlertViewModel(MarshaledAlert alert)
        {
            // Convert timestamp (assuming unix timestamp or similar, but C struct had uint64, 
            // usually typical unix ts in seconds or microseconds. Let's assume seconds for now or Handle appropriately)
            DateTime dateTime = DateTimeOffset.FromUnixTimeSeconds((long)alert.Timestamp).LocalDateTime;
            Timestamp = dateTime.ToString("HH:mm:ss");

            Severity = GetSeverityString(alert.Severity);
            Type = GetAttackTypeString(alert.AttackType);
            
            // Should convert IP ints to strings
            Source = $"{(alert.SrcIp & 0xFF)}.{(alert.SrcIp >> 8) & 0xFF}.{(alert.SrcIp >> 16) & 0xFF}.{(alert.SrcIp >> 24) & 0xFF}:{alert.SrcPort}";
            Destination = $"{(alert.DstIp & 0xFF)}.{(alert.DstIp >> 8) & 0xFF}.{(alert.DstIp >> 16) & 0xFF}.{(alert.DstIp >> 24) & 0xFF}:{alert.DstPort}";
            
            Description = alert.Description;
        }

        private string GetSeverityString(int severity)
        {
            return severity switch
            {
                1 => "INFO",
                2 => "LOW",
                3 => "MEDIUM",
                4 => "HIGH",
                5 => "CRITICAL",
                _ => "UNKNOWN"
            };
        }

        private string GetAttackTypeString(int type)
        {
            // Mapping based on ipc_bridge.c / detection_engine.c enums if I had them.
            // Assuming 0=Signature, 1=PortScan, etc. based on ipc_bridge.c
            return "Alert"; 
        }
    }
}
