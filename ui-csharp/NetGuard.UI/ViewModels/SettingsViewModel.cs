using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using System;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using System.Text;
using NetGuard.UI.Services;
using NetGuard.Core; // For native methods if needed, mostly for enums if we used them

namespace NetGuard.UI.ViewModels
{
    public partial class SettingsViewModel : ObservableObject
    {
        private const string SettingsFile = "settings.json";
        private readonly string _settingsPath;
        private readonly AlertRepository _alertRepo;

        [ObservableProperty]
        private string _smtpHost = "smtp.example.com";

        [ObservableProperty]
        private int _smtpPort = 587;

        [ObservableProperty]
        private string _smtpUsername = "";

        [ObservableProperty]
        private string _smtpPassword = ""; // In a real app, use SecureString or DPAPI

        [ObservableProperty]
        private string _fromAddress = "netguard@example.com";

        [ObservableProperty]
        private string _toAddress = "admin@example.com";

        [ObservableProperty]
        private bool _enableEmailAlerts;

        [ObservableProperty]
        private string _statusMessage = "";

        // Default constructor for design-time or framework requirements if needed, 
        // but since we are manually instantiating in MainViewModel, we can modify the constructor.
        // Ideally we'd use DI. For now updates MainVM to pass repo.
        public SettingsViewModel(AlertRepository alertRepo)
        {
            _alertRepo = alertRepo;
            string appData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            _settingsPath = Path.Combine(appData, "NetGuard", SettingsFile);
            LoadSettings();
        }

        public SettingsViewModel() : this(null) { } // Fallback

        [RelayCommand]
        private void SaveSettings()
        {
            try
            {
                var settings = new AppSettings
                {
                    SmtpHost = SmtpHost,
                    SmtpPort = SmtpPort,
                    SmtpUsername = SmtpUsername,
                    SmtpPassword = SmtpPassword,
                    FromAddress = FromAddress,
                    ToAddress = ToAddress,
                    EnableEmailAlerts = EnableEmailAlerts
                };

                string json = JsonSerializer.Serialize(settings, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_settingsPath, json);
                StatusMessage = "Settings saved successfully.";
            }
            catch (Exception ex)
            {
                StatusMessage = $"Error saving settings: {ex.Message}";
            }
        }

        [RelayCommand]
        private async Task ExportAlerts()
        {
            if (_alertRepo == null)
            {
                StatusMessage = "Repository not available.";
                return;
            }

            try
            {
                var alerts = await _alertRepo.GetAlertsForExportAsync();
                var sb = new StringBuilder();
                sb.AppendLine("Timestamp,Severity,Type,Source,Destination,Protocol,Rule,Description");
                
                foreach (var a in alerts)
                {
                    string time = DateTimeOffset.FromUnixTimeSeconds(a.Timestamp).LocalDateTime.ToString("yyyy-MM-dd HH:mm:ss");
                    string src = $"{a.SrcIp}:{a.SrcPort}";
                    string dst = $"{a.DstIp}:{a.DstPort}";
                    // Escape CSV injection/commas
                    string desc = a.Description.Replace(",", ";").Replace("\n", " ");
                    
                    sb.AppendLine($"{time},{a.Severity},{a.AttackType},{src},{dst},{a.Protocol},{a.RuleName},{desc}");
                }

                string fileName = $"alerts_export_{DateTime.Now:yyyyMMdd_HHmmss}.csv";
                string docsPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
                string filePath = Path.Combine(docsPath, fileName);
                
                await File.WriteAllTextAsync(filePath, sb.ToString());
                StatusMessage = $"Exported to Documents\\{fileName}";
            }
            catch (Exception ex)
            {
                StatusMessage = $"Export failed: {ex.Message}";
            }
        }

        private void LoadSettings()
        {
            try
            {
                if (File.Exists(_settingsPath))
                {
                    string json = File.ReadAllText(_settingsPath);
                    var settings = JsonSerializer.Deserialize<AppSettings>(json);
                    if (settings != null)
                    {
                        SmtpHost = settings.SmtpHost;
                        SmtpPort = settings.SmtpPort;
                        SmtpUsername = settings.SmtpUsername;
                        SmtpPassword = settings.SmtpPassword;
                        FromAddress = settings.FromAddress;
                        ToAddress = settings.ToAddress;
                        EnableEmailAlerts = settings.EnableEmailAlerts;
                    }
                }
            }
            catch
            {
                // Ignore load errors, use defaults
            }
        }
    }

    public class AppSettings
    {
        public string SmtpHost { get; set; }
        public int SmtpPort { get; set; }
        public string SmtpUsername { get; set; }
        public string SmtpPassword { get; set; }
        public string FromAddress { get; set; }
        public string ToAddress { get; set; }
        public bool EnableEmailAlerts { get; set; }
    }
}
