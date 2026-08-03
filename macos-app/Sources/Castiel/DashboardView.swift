//
//  DashboardView.swift
//  Real-time metrics dashboard with stat cards and mini charts.
//

import SwiftUI

struct DashboardView: View {
    @EnvironmentObject var metrics: MetricsPoller
    @EnvironmentObject var daemon: DaemonManager

    var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                // Status banner
                StatusBanner()
                    .environmentObject(daemon)

                // Metric cards
                LazyVGrid(columns: [
                    GridItem(.flexible()),
                    GridItem(.flexible()),
                    GridItem(.flexible()),
                ], spacing: 16) {
                    MetricCard(
                        title: "Total Queries",
                        value: formatNumber(metrics.metrics.totalQueries),
                        icon: "arrow.up.arrow.down",
                        color: .blue
                    )
                    MetricCard(
                        title: "Blocked",
                        value: formatNumber(metrics.metrics.blockedByReason.values.reduce(0, +)),
                        icon: "hand.raised.fill",
                        color: .red
                    )
                    MetricCard(
                        title: "Rate Limited",
                        value: formatNumber(metrics.metrics.rateLimited),
                        icon: "speedometer",
                        color: .orange
                    )
                    MetricCard(
                        title: "Cache Hit Rate",
                        value: String(format: "%.1f%%", metrics.metrics.cacheHitRate),
                        icon: "internaldrive",
                        color: .green
                    )
                    MetricCard(
                        title: "Avg Query Time",
                        value: String(format: "%.2fms", metrics.metrics.queryDuration * 1000),
                        icon: "clock",
                        color: .purple
                    )
                    MetricCard(
                        title: "DoH Status",
                        value: daemon.dohStatus.rawValue,
                        icon: "lock.shield",
                        color: daemon.dohStatus == .enabled ? .green : .red
                    )
                }

                // Query timeline chart
                QueryChart(history: metrics.history)
                    .frame(height: 180)
                    .padding()
                    .background(Color(nsColor: .controlBackgroundColor))
                    .cornerRadius(8)

                // Blocked by reason breakdown
                if !metrics.metrics.blockedByReason.isEmpty {
                    BlockedBreakdown(reasons: metrics.metrics.blockedByReason)
                        .padding()
                        .background(Color(nsColor: .controlBackgroundColor))
                        .cornerRadius(8)
                }

                if let lastUpdated = metrics.lastUpdated {
                    Text("Last updated: \(lastUpdated.formatted(date: .omitted, time: .standard))")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
            .padding()
        }
        .navigationTitle("Dashboard")
    }

    private func formatNumber(_ n: Double) -> String {
        if n >= 1_000_000 { return String(format: "%.1fM", n / 1_000_000) }
        if n >= 1_000 { return String(format: "%.1fK", n / 1_000) }
        return String(format: "%.0f", n)
    }
}

// MARK: - Status Banner

struct StatusBanner: View {
    @EnvironmentObject var daemon: DaemonManager
    @ObservedObject private var netMonitor = NetworkMonitor.shared

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text("Castiel")
                    .font(.title2)
                    .fontWeight(.bold)
                HStack(spacing: 8) {
                    Text(daemon.status == .running
                         ? "Protecting your DNS — daemon running"
                         : "Daemon is not running")
                        .font(.caption)
                        .foregroundColor(.secondary)

                    if netMonitor.state == .offline {
                        Label("Offline", systemImage: "wifi.slash")
                            .font(.caption)
                            .foregroundColor(.orange)
                    } else if netMonitor.state == .online {
                        Label(netMonitor.interfaceType, systemImage: "wifi")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }
            }
            Spacer()
            if daemon.status == .running {
                Image(systemName: "shield.checkered")
                    .font(.system(size: 40))
                    .foregroundColor(.green)
            } else {
                Image(systemName: "shield.slash")
                    .font(.system(size: 40))
                    .foregroundColor(.gray)
            }
        }
        .padding()
        .background(
            LinearGradient(colors: [
                daemon.status == .running ? Color.green.opacity(0.1) : Color.gray.opacity(0.1),
                Color.clear
            ], startPoint: .topLeading, endPoint: .bottomTrailing)
        )
        .cornerRadius(8)
    }
}

// MARK: - Metric Card

struct MetricCard: View {
    let title: String
    let value: String
    let icon: String
    let color: Color

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Image(systemName: icon)
                    .foregroundColor(color)
                    .font(.title3)
                Spacer()
            }
            Text(value)
                .font(.system(size: 28, weight: .bold, design: .rounded))
                .foregroundColor(.primary)
            Text(title)
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .padding()
        .background(Color(nsColor: .controlBackgroundColor))
        .cornerRadius(8)
    }
}

// MARK: - Query Chart

struct QueryChart: View {
    let history: [MetricsPoller.MetricSnapshot]

    var body: some View {
        VStack(alignment: .leading) {
            Text("Query Timeline")
                .font(.headline)
                .padding(.bottom, 8)

            if history.isEmpty {
                Text("Waiting for data...")
                    .foregroundColor(.secondary)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                GeometryReader { geo in
                    ZStack {
                        // Grid lines
                        VStack {
                            ForEach(0..<4) { i in
                                Rectangle()
                                    .fill(Color.gray.opacity(0.1))
                                    .frame(height: 1)
                                Spacer()
                            }
                        }

                        // Lines
                        let maxQ = max(history.map { $0.totalQueries }.max() ?? 1, 1)
                        let maxB = max(history.map { $0.blocked }.max() ?? 1, 1)
                        let maxR = max(history.map { $0.rateLimited }.max() ?? 1, 1)
                        let maxVal = max(maxQ, maxB, maxR)

                        // Total queries line
                        Path { path in
                            let stepX = geo.size.width / CGFloat(max(history.count - 1, 1))
                            for (i, snap) in history.enumerated() {
                                let x = CGFloat(i) * stepX
                                let y = geo.size.height - CGFloat(snap.totalQueries / maxVal) * geo.size.height
                                if i == 0 {
                                    path.move(to: CGPoint(x: x, y: y))
                                } else {
                                    path.addLine(to: CGPoint(x: x, y: y))
                                }
                            }
                        }
                        .stroke(Color.blue, lineWidth: 2)

                        // Blocked line
                        Path { path in
                            let stepX = geo.size.width / CGFloat(max(history.count - 1, 1))
                            for (i, snap) in history.enumerated() {
                                let x = CGFloat(i) * stepX
                                let y = geo.size.height - CGFloat(snap.blocked / maxVal) * geo.size.height
                                if i == 0 {
                                    path.move(to: CGPoint(x: x, y: y))
                                } else {
                                    path.addLine(to: CGPoint(x: x, y: y))
                                }
                            }
                        }
                        .stroke(Color.red, lineWidth: 2)

                        // Rate limited line
                        Path { path in
                            let stepX = geo.size.width / CGFloat(max(history.count - 1, 1))
                            for (i, snap) in history.enumerated() {
                                let x = CGFloat(i) * stepX
                                let y = geo.size.height - CGFloat(snap.rateLimited / maxVal) * geo.size.height
                                if i == 0 {
                                    path.move(to: CGPoint(x: x, y: y))
                                } else {
                                    path.addLine(to: CGPoint(x: x, y: y))
                                }
                            }
                        }
                        .stroke(Color.orange, lineWidth: 2)
                    }
                }

                // Legend
                HStack(spacing: 16) {
                    LegendItem(color: .blue, label: "Queries")
                    LegendItem(color: .red, label: "Blocked")
                    LegendItem(color: .orange, label: "Rate Limited")
                    Spacer()
                }
                .padding(.top, 4)
            }
        }
    }
}

struct LegendItem: View {
    let color: Color
    let label: String

    var body: some View {
        HStack(spacing: 4) {
            Circle()
                .fill(color)
                .frame(width: 8, height: 8)
            Text(label)
                .font(.caption)
                .foregroundColor(.secondary)
        }
    }
}

// MARK: - Blocked Breakdown

struct BlockedBreakdown: View {
    let reasons: [String: Double]

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Blocked by Reason")
                .font(.headline)

            ForEach(reasons.sorted(by: { $0.value > $1.value }), id: \.key) { reason, count in
                HStack {
                    Text(reason)
                        .font(.caption)
                    Spacer()
                    Text(formatNumber(count))
                        .font(.caption)
                        .fontWeight(.medium)
                }
                .padding(.vertical, 2)
            }
        }
    }

    private func formatNumber(_ n: Double) -> String {
        if n >= 1_000 { return String(format: "%.1fK", n / 1_000) }
        return String(format: "%.0f", n)
    }
}
