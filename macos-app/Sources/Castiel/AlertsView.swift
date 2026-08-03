//
//  AlertsView.swift
//  Real-time alert feed from the DAD alert log.
//

import SwiftUI

struct AlertsView: View {
    @EnvironmentObject var alertFeed: AlertFeed
    @State private var filterSeverity: String?

    var filteredAlerts: [AlertEntry] {
        guard let filter = filterSeverity else { return alertFeed.alerts }
        return alertFeed.alerts.filter { $0.severity == filter }
    }

    var body: some View {
        VStack(spacing: 0) {
            // Filter bar
            HStack {
                Text("\(alertFeed.alerts.count) alerts")
                    .font(.caption)
                    .foregroundColor(.secondary)

                Spacer()

                Picker("Filter", selection: $filterSeverity) {
                    Text("All").tag(String?.none)
                    Text("Critical").tag(String?.some("critical"))
                    Text("Warning").tag(String?.some("warn"))
                    Text("Info").tag(String?.some("info"))
                }
                .pickerStyle(.segmented)
                .frame(width: 250)

                Button(action: { alertFeed.clear() }) {
                    Image(systemName: "trash")
                }
                .help("Clear alerts")
                .buttonStyle(.borderless)

                Button(action: {
                    if alertFeed.isWatching { alertFeed.stopWatching() } else { alertFeed.startWatching() }
                }) {
                    Image(systemName: alertFeed.isWatching ? "pause.fill" : "play.fill")
                        .foregroundColor(alertFeed.isWatching ? .green : .gray)
                }
                .help(alertFeed.isWatching ? "Pause watching" : "Start watching")
                .buttonStyle(.borderless)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 8)
            .background(Color(nsColor: .controlBackgroundColor))

            Divider()

            // Alert list
            if filteredAlerts.isEmpty {
                VStack(spacing: 12) {
                    Image(systemName: "checkmark.shield")
                        .font(.system(size: 48))
                        .foregroundColor(.green)
                    Text("No alerts")
                        .font(.headline)
                    Text(alertFeed.isWatching ? "Watching for new alerts..." : "Alert monitoring is paused")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(filteredAlerts) { alert in
                    AlertRow(alert: alert)
                }
                .listStyle(.plain)
            }
        }
        .navigationTitle("Alerts")
        .onAppear {
            if !alertFeed.isWatching {
                alertFeed.startWatching()
            }
        }
    }
}

struct AlertRow: View {
    let alert: AlertEntry

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: alert.severityIcon)
                .foregroundColor(alert.severityColor)
                .font(.title3)

            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text(alert.type)
                        .font(.caption)
                        .fontWeight(.semibold)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(alert.severityColor.opacity(0.15))
                        .cornerRadius(4)

                    if !alert.domain.isEmpty {
                        Text(alert.domain)
                            .font(.system(.caption, design: .monospaced))
                            .foregroundColor(.blue)
                    }

                    if !alert.source.isEmpty {
                        Text("from \(alert.source)")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }

                    Spacer()

                    Text(alert.timestamp.formatted(date: .omitted, time: .standard))
                        .font(.caption2)
                        .foregroundColor(.secondary)
                }
                Text(alert.message)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .lineLimit(2)
            }
        }
        .padding(.vertical, 4)
    }
}
