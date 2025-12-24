using Microsoft.ML;
using Microsoft.ML.Data;
using NetGuard.Core;
using NetGuard.UI.Services;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace NetGuard.UI.Services
{
    public class MLService
    {
        private readonly MLContext _mlContext;
        private ITransformer _model;
        private const string ModelPath = "traffic_model.zip";
        private readonly List<TrafficData> _trainingData = new List<TrafficData>();
        
        public event EventHandler<MarshaledAlert> AnomalyDetected;

        public class TrafficData
        {
            [LoadColumn(0)] public float PacketsPerSecond { get; set; }
            [LoadColumn(1)] public float BytesPerSecond { get; set; }
            [LoadColumn(2)] public float Entropy { get; set; }
        }

        public class ClusterPrediction
        {
            [ColumnName("PredictedLabel")] public uint PredictedClusterId;
            [ColumnName("Score")] public float[] Distances;
        }

        public MLService()
        {
            _mlContext = new MLContext(seed: 0);
            LoadModel();
        }

        public void AddSample(MarshaledStats stats)
        {
            // Collect data for retraining
            _trainingData.Add(new TrafficData
            {
                PacketsPerSecond = (float)stats.PacketsPerSecond,
                BytesPerSecond = (float)stats.BytesPerSecond,
                Entropy = 0.5f // Placeholder if not computed by C core yet
            });

            // If we have a model, predict
            if (_model != null)
            {
                var input = new TrafficData
                {
                    PacketsPerSecond = (float)stats.PacketsPerSecond,
                    BytesPerSecond = (float)stats.BytesPerSecond,
                    Entropy = 0.5f
                };

                var predictionEngine = _mlContext.Model.CreatePredictionEngine<TrafficData, ClusterPrediction>(_model);
                var prediction = predictionEngine.Predict(input);

                // Simple anomaly detection: If distance to nearest centroid is very large
                float minDistance = prediction.Distances.Min();
                if (minDistance > 5000) // Threshold dependent on scaling
                {
                    // Trigger Alert
                    var alert = new MarshaledAlert
                    {
                        Timestamp = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                        Severity = 3, // High
                        AttackType = 100, // ML Anomaly
                        RuleName = "ML Traffic Anomaly",
                        Description = $"Unusual traffic cluster detected (Dist: {minDistance:F0})",
                        Confidence = 0.9f
                    };
                    AnomalyDetected?.Invoke(this, alert);
                }
            }
        }

        public void TrainModel()
        {
            if (_trainingData.Count < 50) return; // Need minimum samples

            var dataView = _mlContext.Data.LoadFromEnumerable(_trainingData);

            var pipeline = _mlContext.Transforms.Concatenate("Features", "PacketsPerSecond", "BytesPerSecond", "Entropy")
                .Append(_mlContext.Clustering.Trainers.KMeans(featureColumnName: "Features", numberOfClusters: 3));

            _model = pipeline.Fit(dataView);
            _mlContext.Model.Save(_model, dataView.Schema, ModelPath);
            
            // Clear old training data to avoid unbounded growth or keep sliding window
            if (_trainingData.Count > 10000) _trainingData.Clear();
        }

        private void LoadModel()
        {
            if (File.Exists(ModelPath))
            {
                DataViewSchema schema;
                _model = _mlContext.Model.Load(ModelPath, out schema);
            }
        }
    }
}
