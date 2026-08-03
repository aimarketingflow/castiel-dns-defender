//
//  ContentView.swift
//  Main window with sidebar navigation and slide-out log panel.
//

import SwiftUI

enum SidebarItem: String, CaseIterable, Identifiable {
    case dashboard = "Dashboard"
    case dohControl = "DoH Control"
    case alerts = "Alerts"
    case logs = "Logs"
    case settings = "Settings"

    var id: String { rawValue }

    var icon: String {
        switch self {
        case .dashboard: return "shield.lefthalf.filled"
        case .dohControl: return "lock.fill"
        case .alerts: return "exclamationmark.bubble"
        case .logs: return "doc.text"
        case .settings: return "gear"
        }
    }
}

struct ContentView: View {
    @EnvironmentObject var daemon: DaemonManager
    @EnvironmentObject var metrics: MetricsPoller
    @EnvironmentObject var alertFeed: AlertFeed

    @State private var selection: SidebarItem? = .dashboard

    var body: some View {
        HStack(spacing: 0) {
            // Main content with sidebar
            NavigationSplitView {
                List(SidebarItem.allCases, selection: $selection) { item in
                    NavigationLink(value: item) {
                        Label(item.rawValue, systemImage: item.icon)
                            .foregroundColor(item == .dohControl && daemon.dohStatus == .disabled ? .red : nil)
                    }
                }
                .navigationTitle("Castiel")
                .frame(width: 200)

                VStack(spacing: 0) {
                    DaemonStatusBar()
                        .environmentObject(daemon)
                    Divider()

                    // Toggle log panel button
                    Button(action: {
                        withAnimation(.easeInOut(duration: 0.3)) {
                            daemon.showLogPanel.toggle()
                        }
                    }) {
                        HStack {
                            Image(systemName: daemon.showLogPanel ? "panel.left.collapse" : "panel.left")
                            Text(daemon.showLogPanel ? "Hide Logs" : "Show Logs")
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 6)
                    }
                    .buttonStyle(.borderless)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 6)
                }
            } detail: {
                switch selection {
                case .dashboard:
                    DashboardView()
                        .environmentObject(metrics)
                        .environmentObject(daemon)
                case .dohControl:
                    DoHControlView()
                        .environmentObject(daemon)
                case .alerts:
                    AlertsView()
                        .environmentObject(alertFeed)
                case .logs:
                    LogsView()
                        .environmentObject(daemon)
                case .settings:
                    SettingsView()
                        .environmentObject(daemon)
                case .none:
                    Text("Select an item from the sidebar")
                        .foregroundColor(.secondary)
                }
            }
            .onAppear {
                if daemon.status == .running {
                    metrics.startPolling()
                    alertFeed.startWatching()
                }
            }
            .onChange(of: daemon.status) { newStatus in
                if newStatus == .running {
                    metrics.startPolling()
                    alertFeed.startWatching()
                } else {
                    metrics.stopPolling()
                    alertFeed.stopWatching()
                }
            }

            // Slide-out log panel
            if daemon.showLogPanel {
                LogSidePanel()
                    .environmentObject(daemon)
                    .frame(width: 360)
                    .background(Color(nsColor: .windowBackgroundColor))
                    .transition(.move(edge: .trailing))
            }
        }
    }
}

// MARK: - Log Side Panel

struct LogSidePanel: View {
    @EnvironmentObject var daemon: DaemonManager

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Text("Live Logs")
                    .font(.headline)
                Spacer()
                Text("\(daemon.logEntries.count)")
                    .font(.caption)
                    .foregroundColor(.secondary)
                Button(action: { daemon.copyLogs() }) {
                    Image(systemName: "doc.on.doc")
                }
                .help("Copy Logs")
                .buttonStyle(.borderless)

                Button(action: { daemon.clearLogs() }) {
                    Image(systemName: "trash")
                }
                .help("Clear Logs")
                .buttonStyle(.borderless)

                Button(action: {
                    withAnimation(.easeInOut(duration: 0.3)) {
                        daemon.showLogPanel = false
                    }
                }) {
                    Image(systemName: "xmark")
                }
                .help("Close Panel")
                .buttonStyle(.borderless)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(Color(nsColor: .controlBackgroundColor))

            Divider()

            // Log entries
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 1) {
                        ForEach(daemon.logEntries) { entry in
                            LogLineView(entry: entry)
                                .id(entry.id)
                        }
                        if daemon.logEntries.isEmpty {
                            Text("No logs yet. App logs will appear here.")
                                .font(.caption)
                                .foregroundColor(.secondary)
                                .padding()
                        }
                        Color.clear.frame(height: 1).id("logBottom")
                    }
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                }
                .background(Color(nsColor: .textBackgroundColor))
                .onChange(of: daemon.logEntries.count) { _ in
                    withAnimation {
                        proxy.scrollTo("logBottom", anchor: .bottom)
                    }
                }
            }
        }
    }
}

struct LogLineView: View {
    let entry: LogEntry

    var levelColor: Color {
        switch entry.level {
        case .error: return .red
        case .warn: return .orange
        case .info: return .blue
        case .debug: return .secondary
        }
    }

    var body: some View {
        HStack(alignment: .top, spacing: 4) {
            Text(entry.timestamp, style: .time)
                .font(.system(size: 9, design: .monospaced))
                .foregroundColor(.secondary)
                .frame(width: 50, alignment: .leading)

            Text(entry.level.rawValue)
                .font(.system(size: 9, design: .monospaced))
                .fontWeight(.bold)
                .foregroundColor(levelColor)
                .frame(width: 36, alignment: .leading)

            Text(entry.message)
                .font(.system(size: 10, design: .monospaced))
                .foregroundColor(.primary)
                .textSelection(.enabled)
                .lineLimit(nil)
        }
        .padding(.vertical, 1)
    }
}

// MARK: - Daemon Status Bar

struct DaemonStatusBar: View {
    @EnvironmentObject var daemon: DaemonManager
    @ObservedObject private var netMonitor = NetworkMonitor.shared

    var statusColor: Color {
        switch daemon.status {
        case .running: return .green
        case .starting: return .yellow
        case .error: return .red
        case .stopped: return .gray
        }
    }

    var body: some View {
        HStack(spacing: 12) {
            Circle()
                .fill(statusColor)
                .frame(width: 10, height: 10)

            Text(daemon.status.rawValue)
                .font(.caption)
                .fontWeight(.medium)

            if netMonitor.state == .offline {
                Image(systemName: "wifi.slash")
                    .font(.caption)
                    .foregroundColor(.orange)
                    .help("Network offline — polling paused")
            }

            Spacer()

            if daemon.status == .running {
                Text("PID: \(daemon.pid)")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            Button(action: { daemon.start() }) {
                Image(systemName: "play.fill")
            }
            .help("Start Daemon")
            .disabled(daemon.status == .running || daemon.status == .starting)
            .buttonStyle(.borderless)

            Button(action: { daemon.stop() }) {
                Image(systemName: "stop.fill")
            }
            .help("Stop Daemon")
            .disabled(daemon.status != .running)
            .buttonStyle(.borderless)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(Color(nsColor: .controlBackgroundColor))
    }
}
