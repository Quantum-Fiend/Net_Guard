using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetGuard.UI.Services;
using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;

namespace NetGuard.UI.ViewModels
{
    public partial class ForensicsViewModel : ObservableObject
    {
        private readonly AlertRepository _alertRepo;

        [ObservableProperty]
        private string _searchText;

        [ObservableProperty]
        private int _selectedSeverityIndex = 0; // 0=All

        [ObservableProperty]
        private DateTime _startDate = DateTime.Today.AddDays(-7);

        [ObservableProperty]
        private DateTime _endDate = DateTime.Today;

        public ObservableCollection<AlertViewModel> FilteredAlerts { get; } = new();

        public ForensicsViewModel(AlertRepository alertRepo)
        {
            _alertRepo = alertRepo;
        }

        public ForensicsViewModel() { }

        [RelayCommand]
        private async Task Search()
        {
            if (_alertRepo == null) return;

            FilteredAlerts.Clear();

            // Fetch all (inefficient for large DBs, but fine for prototype)
            // In production, push filters to SQL
            var allAlerts = await _alertRepo.GetAllAlertsAsync();

            var query = allAlerts.AsEnumerable();

            // Date Filter
            long startTs = ((DateTimeOffset)StartDate).ToUnixTimeSeconds();
            long endTs = ((DateTimeOffset)EndDate.AddDays(1)).ToUnixTimeSeconds();
            query = query.Where(a => a.Timestamp >= (ulong)startTs && a.Timestamp < (ulong)endTs);

            // Severity Filter
            if (SelectedSeverityIndex > 0)
            {
                // 1=Info, 2=Low, etc. Map index to severity logic if needed
                // Assuming Index 1 = Severity 0 (Info), Index 5 = Severity 4 (Critical)
                // Let's assume UI has "All", "Info", "Low"...
                int severity = SelectedSeverityIndex - 1;
                query = query.Where(a => a.Severity == severity);
            }

            // Text Filter
            if (!string.IsNullOrWhiteSpace(SearchText))
            {
                string lower = SearchText.ToLower();
                query = query.Where(a => 
                    a.Description.ToLower().Contains(lower) || 
                    a.RuleName.ToLower().Contains(lower) ||
                    // Check IPs (requires int conversion or stored string)
                    // For now, let's assume Description contains relevant info or check basic
                   true // Skip IP check if internal representation is complex here
                );
            }

            foreach (var alert in query.OrderByDescending(a => a.Timestamp))
            {
                FilteredAlerts.Add(new AlertViewModel(alert));
            }
        }
    }
}
