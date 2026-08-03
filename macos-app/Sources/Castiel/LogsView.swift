//
//  LogsView.swift
//  Live log output from the DAD daemon.
//

import SwiftUI

struct LogsView: View {
    @EnvironmentObject var daemon: DaemonManager

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("\(daemon.logEntries.count) entries")
                    .font(.caption)
                    .foregroundColor(.secondary)
                Spacer()
                Button(action: { daemon.copyLogs() }) {
                    Label("Copy", systemImage: "doc.on.doc")
                }
                .buttonStyle(.borderless)

                Button(action: { daemon.clearLogs() }) {
                    Label("Clear", systemImage: "trash")
                }
                .buttonStyle(.borderless)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 8)
            .background(Color(nsColor: .controlBackgroundColor))

            Divider()

            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 1) {
                        ForEach(daemon.logEntries) { entry in
                            HStack(alignment: .top, spacing: 4) {
                                Text(entry.timestamp, style: .time)
                                    .font(.system(.caption2, design: .monospaced))
                                    .foregroundColor(.secondary)
                                    .frame(width: 60, alignment: .leading)

                                Text(entry.level.rawValue)
                                    .font(.system(.caption2, design: .monospaced))
                                    .fontWeight(.bold)
                                    .foregroundColor(levelColor(entry.level))
                                    .frame(width: 40, alignment: .leading)

                                Text(entry.message)
                                    .font(.system(.caption2, design: .monospaced))
                                    .textSelection(.enabled)
                                    .lineLimit(nil)
                            }
                            .id(entry.id)
                        }
                        if daemon.logEntries.isEmpty {
                            Text("No log output yet. Start the daemon to see logs.")
                                .foregroundColor(.secondary)
                                .padding()
                        }
                        Color.clear.frame(height: 1).id("logEnd")
                    }
                    .padding(8)
                }
                .background(Color(nsColor: .textBackgroundColor))
                .onChange(of: daemon.logEntries.count) { _ in
                    withAnimation {
                        proxy.scrollTo("logEnd", anchor: .bottom)
                    }
                }
            }
        }
        .navigationTitle("Logs")
    }

    private func levelColor(_ level: LogLevel) -> Color {
        switch level {
        case .error: return .red
        case .warn: return .orange
        case .info: return .blue
        case .debug: return .secondary
        }
    }
}
