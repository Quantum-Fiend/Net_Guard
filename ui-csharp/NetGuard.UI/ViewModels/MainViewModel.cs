using CommunityToolkit.Mvvm.ComponentModel;
using NetGuard.UI.Services;
using NetGuard.Core;
using System;
using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Threading;

namespace NetGuard.UI.ViewModels
{
    public partial class MainViewModel : ObservableObject, IDisposable
    {
        private readonly PacketEngine _engine;
        private readonly DispatcherTimer _timer;
        private readonly DatabaseService _dbService;
        private readonly AlertRepository _alertRepo;

        [ObservableProperty]
        private object _currentView;

        [ObservableProperty]
        [NotifyCanExecuteChangedFor(nameof(StartCaptureCommand))]
        [NotifyCanExecuteChangedFor(nameof(StopCaptureCommand))]
        private bool _isCapturing;

        [ObservableProperty]
        private bool _isPcapRecording;
        
        [ObservableProperty]
        private string _statusMessage = "Ready";

        [ObservableProperty]
        private string _notificationMessage;

        [ObservableProperty]
        private bool _isNotificationVisible;

        [ObservableProperty]
        private string _notificationColor = "#dd2c00"; // Red default

        private DispatcherTimer _notificationTimer;
        
        public DashboardViewModel DashboardVM { get; }
        public RulesViewModel RulesVM { get; }
        public SettingsViewModel SettingsVM { get; }
        public ForensicsViewModel ForensicsVM { get; }
        private readonly EmailService _emailService;
        private readonly FirewallService _firewallService;
        private readonly AnomalyService _anomalyService;
        private readonly MLService _mlService; // Added MLService field

        public MainViewModel()
        {
            _engine = new PacketEngine();
            try
            {
                _dbService = new DatabaseService();
                _alertRepo = new AlertRepository(_dbService);
            }
            catch (Exception ex)
            {
                StatusMessage = $"DB Error: {ex.Message}";
                // Fallback or exit? For now just log status
            }

            try
            {
                _engine.Initialize();
                
                // Load default rules
                string rulesPath = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "rules", "malware_signatures.json");
                if (System.IO.File.Exists(rulesPath))
                {
                    _engine.LoadRules(rulesPath);
                    StatusMessage = "Rules loaded successfully.";
                }
                
                // Original subscription, kept for now
                // _engine.AlertReceived += OnAlertReceived; 
            }
            catch (Exception ex)
            {
                StatusMessage = $"Initialization Failed: {ex.Message}";
            }

            _firewallService = new FirewallService();
            DashboardVM = new DashboardViewModel(_engine, _alertRepo, _firewallService);
            RulesVM = new RulesViewModel();
            SettingsVM = new SettingsViewModel(_alertRepo);
            ForensicsVM = new ForensicsViewModel(_alertRepo);
            _emailService = new EmailService(SettingsVM);
            _anomalyService = new AnomalyService();
            _mlService = new MLService(); // Instantiate MLService

            _engine.StatsUpdated += OnStatsUpdated; // Subscribed to OnStatsUpdated
            _engine.AlertReceived += OnAlertReceived; // Kept original subscription
            _anomalyService.AnomalyDetected += (s, alert) => OnAlertReceived(s, alert); // Kept original subscription
            _mlService.AnomalyDetected += OnAlertReceived; // Subscribe MLService anomalies to existing alert handler
            
            CurrentView = DashboardVM;

            _timer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(1)
            };
            _timer.Tick += Timer_Tick;
            _timer.Start();

            // Original subscription removed, now handled by OnStatsUpdated
            // _engine.StatsUpdated += (s, stats) => _anomalyService.ProcessStats(stats);
        }

        [ObservableProperty] // Added for OnStatsUpdated
        private MarshaledStats _stats; // Added for OnStatsUpdated

        private void OnStatsUpdated(object sender, MarshaledStats stats)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                Stats = stats;
                _anomalyService.ProcessStats(stats); // Changed from UpdateStats to ProcessStats based on original code
                _mlService.AddSample(stats); // Train/Predict
                if (IsCapturing && _timer.IsEnabled && (DateTime.Now.Second % 10 == 0)) 
                {
                     // Periodically train model in background task if needed, or just let AddSample handle it
                     Task.Run(() => _mlService.TrainModel());
                }
            });
        }

        private void Timer_Tick(object sender, EventArgs e)
        {
            IsCapturing = _engine.IsRunning;
            if (IsCapturing)
            {
                StatusMessage = "Capturing...";
            }
            else if (StatusMessage == "Capturing...")
            {
                StatusMessage = "Stopped";
            }
        }

        private void OnAlertReceived(object sender, MarshaledAlert alert)
        {
            // Only notify for High/Critical
            if (alert.Severity >= 3) // 3=Medium, 4=High, 5=Critical
            {
                System.Windows.Application.Current.Dispatcher.Invoke(() =>
                {
                    NotificationMessage = $"ALERT: {alert.RuleName ?? "Threat Detected"} ({alert.Description})";
                    NotificationColor = alert.Severity >= 5 ? "#D32F2F" : "#F57C00"; // Red or Orange
                    IsNotificationVisible = true;
                    
                    if (_notificationTimer == null)
                    {
                        _notificationTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(5) };
                        _notificationTimer.Tick += (s, e) => 
                        { 
                            IsNotificationVisible = false; 
                            _notificationTimer.Stop(); 
                        };
                    }
                    _notificationTimer.Stop();
                    _notificationTimer.Start();
                });

                // Send email (fire and forget)
                if (alert.Severity >= 4) // High/Critical
                {
                    Task.Run(() => _emailService.SendAlertAsync(alert));
                }
            }
        }

        [RelayCommand]
        private void ToggleCapture()
        {
            if (IsCapturing)
            {
                _engine.StopCapture();
                IsCapturing = false;
                StatusMessage = "Capture Stopped";
                
                // Also stop PCAP if running
                if (IsPcapRecording)
                {
                    _engine.StopPcap();
                    IsPcapRecording = false;
                }
            }
            else
            {
                try
                {
                    // For now, auto-select first device or default
                    // In future, pass selected device
                    var devices = _engine.GetDevices();
                    if (devices.Count > 0)
                    {
                        // Use the Friendly Name or Name, depending on what's available. 
                        // Device names in Windows (e.g., \Device\NPF_...) are needed by Npcap.
                        // The MarshaledDevice.Name field comes from pcap_findalldevs->name.
                        // MarshaledDevice.Description is the friendly name.
                        string deviceName = devices[0].Name; 
                        _engine.StartCapture(deviceName);
                        IsCapturing = true;
                        StatusMessage = $"Started capture on {devices[0].Description ?? deviceName}";
                    }
                    else
                    {
                        StatusMessage = "No network devices found.";
                    }
                }
                catch (Exception ex)
                {
                    StatusMessage = $"Error starting capture: {ex.Message}";
                }
            }
        }

        [RelayCommand]
        private void TogglePcapRecording()
        {
            if (IsPcapRecording)
            {
                _engine.StopPcap();
                IsPcapRecording = false;
                StatusMessage = "PCAP recording stopped.";
            }
            else
            {
                try
                {
                    // Ensure capture is running before starting PCAP recording
                    if (!IsCapturing)
                    {
                        StatusMessage = "Start live capture before recording PCAP.";
                        return;
                    }

                    string pcapFilePath = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "captures", $"capture_{DateTime.Now:yyyyMMdd_HHmmss}.pcap");
                    System.IO.Directory.CreateDirectory(System.IO.Path.GetDirectoryName(pcapFilePath));
                    _engine.StartPcap(pcapFilePath);
                    IsPcapRecording = true;
                    StatusMessage = $"PCAP recording started to {System.IO.Path.GetFileName(pcapFilePath)}";
                }
                catch (Exception ex)
                {
                    StatusMessage = $"Error starting PCAP recording: {ex.Message}";
                }
            }
        }

        [RelayCommand]
        private void ShowDashboard() => CurrentView = DashboardVM;

        [RelayCommand]
        private void ShowRules() => CurrentView = RulesVM;

        [RelayCommand]
        private void ShowSettings() => CurrentView = SettingsVM;

        [RelayCommand]
        private void ShowForensics() => CurrentView = ForensicsVM;

        public void Dispose()
        {
            _timer.Stop();
            _engine.Dispose();
        }
    }
}
