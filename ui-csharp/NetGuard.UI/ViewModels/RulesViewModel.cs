using CommunityToolkit.Mvvm.ComponentModel;
using System.Collections.ObjectModel;
using System.IO;
using System.Text.Json;
using System.Collections.Generic;
using System;

namespace NetGuard.UI.ViewModels
{
    public partial class RulesViewModel : ObservableObject
    {
        [ObservableProperty]
        private ObservableCollection<RuleItem> _rules = new();

        public RulesViewModel()
        {
            LoadRules();
        }

        private void LoadRules()
        {
            try
            {
                string rulesDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "rules");
                if (Directory.Exists(rulesDir))
                {
                    foreach (var file in Directory.GetFiles(rulesDir, "*.json"))
                    {
                        string json = File.ReadAllText(file);
                        var doc = JsonDocument.Parse(json);
                        if (doc.RootElement.TryGetProperty("rules", out var rulesElement))
                        {
                            foreach (var rule in rulesElement.EnumerateArray())
                            {
                                var item = new RuleItem
                                {
                                    Name = GetString(rule, "name"),
                                    Pattern = GetString(rule, "pattern"),
                                    Protocol = GetString(rule, "protocol"),
                                    Severity = GetString(rule, "severity"),
                                    SourceFile = Path.GetFileName(file)
                                };
                                Rules.Add(item);
                            }
                        }
                    }
                }
            }
            catch
            {
                // Handle parsing errors
            }
        }

        private string GetString(JsonElement element, string prop)
        {
            return element.TryGetProperty(prop, out var val) ? val.GetString() ?? "" : "";
        }
    }

    public class RuleItem
    {
        public string Name { get; set; } = "";
        public string Pattern { get; set; } = "";
        public string Protocol { get; set; } = "";
        public string Severity { get; set; } = "";
        public string SourceFile { get; set; } = "";
    }
}
