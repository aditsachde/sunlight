package ctlog

import (
	"reflect"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type metrics struct {
	ReqCount    *prometheus.CounterVec
	ReqInFlight *prometheus.GaugeVec
	ReqDuration *prometheus.SummaryVec

	SeqCount        *prometheus.CounterVec
	SeqSize         prometheus.Summary
	SeqDuration     prometheus.Summary
	SeqTiles        prometheus.Counter
	SeqDataTileSize prometheus.Counter

	TreeTime prometheus.Gauge
	TreeSize prometheus.Gauge

	ConfigRoots prometheus.Gauge
	ConfigStart prometheus.Gauge
	ConfigEnd   prometheus.Gauge

	Issuers prometheus.Gauge
}

func initMetrics() metrics {
	return metrics{
		ReqInFlight: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "http_in_flight_requests",
				Help: "Requests currently being served, by endpoint.",
			},
			[]string{"endpoint"},
		),
		ReqCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "http_requests_total",
				Help: "HTTP requests served, by endpoint and response code.",
			},
			[]string{"endpoint", "code"},
		),
		ReqDuration: prometheus.NewSummaryVec(
			prometheus.SummaryOpts{
				Name:       "http_request_duration_seconds",
				Help:       "HTTP request serving latencies in seconds, by endpoint.",
				Objectives: map[float64]float64{0.5: 0.05, 0.75: 0.025, 0.9: 0.01, 0.99: 0.001},
				MaxAge:     1 * time.Minute,
				AgeBuckets: 6,
			},
			[]string{"endpoint"},
		),

		SeqCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "sequencing_rounds_total",
				Help: "Number of sequencing rounds, by whether they are successful.",
			},
			[]string{"result"},
		),
		SeqSize: prometheus.NewSummary(
			prometheus.SummaryOpts{
				Name:       "sequencing_pool_entries",
				Help:       "Number of entries in the pools being sequenced.",
				Objectives: map[float64]float64{0.5: 0.05, 0.99: 0.001},
				MaxAge:     1 * time.Minute,
				AgeBuckets: 6,
			},
		),
		SeqDuration: prometheus.NewSummary(
			prometheus.SummaryOpts{
				Name:       "sequencing_duration_seconds",
				Help:       "Duration of sequencing rounds, successful or not.",
				Objectives: map[float64]float64{0.5: 0.05, 0.75: 0.025, 0.9: 0.01, 0.99: 0.001},
				MaxAge:     1 * time.Minute,
				AgeBuckets: 6,
			},
		),
		SeqTiles: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "sequencing_uploaded_tiles_total",
				Help: "Number of tiles uploaded in successful rounds, including partials.",
			},
		),
		SeqDataTileSize: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "sequencing_data_tiles_bytes_total",
				Help: "Size of data tiles uploaded in successful rounds, ignoring partials overlap.",
			},
		),

		TreeTime: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "tree_timestamp_seconds",
				Help: "Timestamp of the latest published tree head.",
			},
		),
		TreeSize: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "tree_size_leaves_total",
				Help: "Size of the latest published tree head.",
			},
		),

		ConfigRoots: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "config_roots_total",
				Help: "Number of accepted roots.",
			},
		),
		ConfigStart: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "config_notafter_start_timestamp_seconds",
				Help: "Start of the NotAfter accepted period.",
			},
		),
		ConfigEnd: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "config_notafter_end_timestamp_seconds",
				Help: "End of the NotAfter accepted period.",
			},
		),

		Issuers: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "issuers_certs_total",
				Help: "Number of certificates in the issuers bundle.",
			},
		),
	}
}

func (l *Log) Metrics() []prometheus.Collector {
	var collectors []prometheus.Collector
	for i := 0; i < reflect.ValueOf(l.m).NumField(); i++ {
		collectors = append(collectors, reflect.ValueOf(l.m).Field(i).Interface().(prometheus.Collector))
	}
	return append(collectors, l.c.Backend.Metrics()...)
}