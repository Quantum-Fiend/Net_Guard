using NetGuard.Core;
using NetGuard.UI.ViewModels;
using System;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;

namespace NetGuard.UI.Services
{
    public class EmailService
    {
        private readonly SettingsViewModel _settings;

        public EmailService(SettingsViewModel settings)
        {
            _settings = settings;
        }

        public async Task SendAlertAsync(MarshaledAlert alert)
        {
            if (!_settings.EnableEmailAlerts) return;

            try
            {
                using (var client = new SmtpClient(_settings.SmtpHost, _settings.SmtpPort))
                using (var message = new MailMessage())
                {
                    client.EnableSsl = true;
                    if (!string.IsNullOrEmpty(_settings.SmtpUsername))
                    {
                        client.Credentials = new NetworkCredential(_settings.SmtpUsername, _settings.SmtpPassword);
                    }

                    message.From = new MailAddress(_settings.FromAddress);
                    message.To.Add(_settings.ToAddress);
                    message.Subject = $"[NetGuard] {GetSeverityString(alert.Severity)} Alert: {alert.RuleName}";
                    message.Body = $@"
                        Net_Guard Security Alert
                        ------------------------
                        Timestamp: {DateTimeOffset.FromUnixTimeSeconds((long)alert.Timestamp).LocalDateTime}
                        Severity: {GetSeverityString(alert.Severity)}
                        Type: {alert.AttackType}
                        
                        Source: {FormatIp(alert.SrcIp)}:{alert.SrcPort}
                        Destination: {FormatIp(alert.DstIp)}:{alert.DstPort}
                        Protocol: {alert.Protocol}
                        
                        Description:
                        {alert.Description}
                        
                        Confidence: {alert.Confidence * 100:F1}%
                    ";

                    await client.SendMailAsync(message);
                }
            }
            catch (Exception)
            {
                // Log or handle email failure
                // For now, suppress to avoid crashing UI
            }
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

        private string FormatIp(uint ip)
        {
            return $"{(ip & 0xFF)}.{(ip >> 8) & 0xFF}.{(ip >> 16) & 0xFF}.{(ip >> 24) & 0xFF}";
        }
    }
}
