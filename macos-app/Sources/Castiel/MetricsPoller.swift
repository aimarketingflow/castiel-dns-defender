//
//  MetricsPoller.swift
//  Polls the DAD Prometheus metrics endpoint and parses key metrics.
//

import Foundation
import SwiftUI

struct DadMetrics: Codable {
    var totalQueries: Double = 0
    var cacheHits: Double = 0
    var cacheMisses: Double = 0
    var rateLimited: Double = 0
    var blockedByReason: [String: Double] = [:]
    var queryDuration: Double = 0

    var cacheHitRate: Double {
        let total = cacheHits + cacheMisses
        return total > 0 ? (cacheHits / total) * 100 : 0
    }
}

class MetricsPoller: ObservableObject {
    @Published var metrics = DadMetrics()
    @Published var isPolling = false
    @Published var history: [MetricSnapshot] = []
    @Published var lastUpdated: Date?
    @Published var isNetworkOffline = false

    private var timer: Timer?
    private let maxHistory = 60
    private var endpointURL = "http://127.0.0.1:9090/metrics"
    private var userRequestedPolling = false

    struct MetricSnapshot: Identifiable {
        let id = UUID()
        let timestamp: Date
        let totalQueries: Double
        let blocked: Double
        let rateLimited: Double
    }

    func startPolling(endpoint: String = "http://127.0.0.1:9090/metrics") {
        stopPolling()
        endpointURL = endpoint
        userRequestedPolling = true

        NetworkMonitor.shared.onStateChange { [weak self] state in
            self?.handleNetworkChange(state)
        }

        if NetworkMonitor.shared.state == .offline {
            isNetworkOffline = true
            isPolling = false
            return
        }

        startTimer(endpoint: endpoint)
    }

    private func startTimer(endpoint: String) {
        isPolling = true
        isNetworkOffline = false

        timer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { _ in
            self.poll(endpoint: endpoint)
        }
        poll(endpoint: endpoint)
    }

    private func handleNetworkChange(_ state: NetworkState) {
        if state == .offline {
            if isPolling {
                timer?.invalidate()
                timer = nil
                isPolling = false
                isNetworkOffline = true
            }
        } else if state == .online {
            if userRequestedPolling && !isPolling {
                startTimer(endpoint: endpointURL)
            }
        }
    }

    func stopPolling() {
        timer?.invalidate()
        timer = nil
        isPolling = false
        userRequestedPolling = false
    }

    private func poll(endpoint: String) {
        guard let url = URL(string: endpoint) else { return }

        URLSession.shared.dataTask(with: url) { [weak self] data, _, error in
            guard let data = data, let text = String(data: data, encoding: .utf8) else { return }

            var m = DadMetrics()
            m.totalQueries = self?.extractMetric(text, name: "dad_total_queries") ?? 0
            m.cacheHits = self?.extractMetric(text, name: "dad_cache_hits") ?? 0
            m.cacheMisses = self?.extractMetric(text, name: "dad_cache_misses") ?? 0
            m.rateLimited = self?.extractMetric(text, name: "dad_rate_limited_queries") ?? 0
            m.queryDuration = self?.extractHistogramMean(text, name: "dad_query_duration_seconds") ?? 0

            // Parse blocked queries by reason
            m.blockedByReason = self?.extractLabeledMetrics(text, name: "dad_blocked_queries") ?? [:]

            DispatchQueue.main.async {
                self?.metrics = m
                self?.lastUpdated = Date()

                let blocked = m.blockedByReason.values.reduce(0, +)
                let snapshot = MetricSnapshot(
                    timestamp: Date(),
                    totalQueries: m.totalQueries,
                    blocked: blocked,
                    rateLimited: m.rateLimited
                )
                self?.history.append(snapshot)
                if (self?.history.count ?? 0) > self?.maxHistory ?? 60 {
                    self?.history.removeFirst()
                }
            }
        }.resume()
    }

    // Parse a simple counter: `metric_name value` or `metric_name{} value`
    private func extractMetric(_ text: String, name: String) -> Double {
        let pattern = "\(name)[^{]*\\s+(\\d+\\.?\\d*)"
        guard let regex = try? NSRegularExpression(pattern: pattern),
              let match = regex.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)),
              let range = Range(match.range(at: 1), in: text),
              let val = Double(text[range]) else { return 0 }
        return val
    }

    // Parse histogram mean from _sum / _count
    private func extractHistogramMean(_ text: String, name: String) -> Double {
        let sum = extractMetric(text, name: "\(name)_sum")
        let count = extractMetric(text, name: "\(name)_count")
        return count > 0 ? sum / count : 0
    }

    // Parse labeled metrics: `metric_name{label="value"} number`
    private func extractLabeledMetrics(_ text: String, name: String) -> [String: Double] {
        var result: [String: Double] = [:]
        let pattern = "\(name)\\{[^}]*reason=\"([^\"]+)\"[^}]*\\}\\s+(\\d+\\.?\\d*)"
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return [:] }

        let nsText = text as NSString
        regex.enumerateMatches(in: text, range: NSRange(location: 0, length: nsText.length)) { match, _, _ in
            guard let match = match else { return }
            let labelRange = match.range(at: 1)
            let valueRange = match.range(at: 2)
            let label = nsText.substring(with: labelRange)
            let valueStr = nsText.substring(with: valueRange)
            if let val = Double(valueStr) {
                result[label] = val
            }
        }
        return result
    }
}
