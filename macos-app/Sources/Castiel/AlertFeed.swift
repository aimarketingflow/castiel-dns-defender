//
//  AlertFeed.swift
//  Tails the DAD alert log file for real-time alert display.
//

import Foundation
import SwiftUI

struct AlertEntry: Identifiable, Codable {
    let id = UUID()
    let timestamp: Date
    let type: String
    let severity: String
    let source: String
    let domain: String
    let message: String

    var severityColor: Color {
        switch severity {
        case "critical": return .red
        case "warn": return .orange
        case "info": return .blue
        default: return .gray
        }
    }

    var severityIcon: String {
        switch severity {
        case "critical": return "exclamationmark.octagon.fill"
        case "warn": return "exclamationmark.triangle.fill"
        case "info": return "info.circle.fill"
        default: return "circle"
        }
    }
}

class AlertFeed: ObservableObject {
    @Published var alerts: [AlertEntry] = []
    @Published var isWatching = false

    private var timer: Timer?
    private var lastFileSize: Int64 = 0
    private let maxAlerts = 200

    var logPath: String {
        if let envPath = ProcessInfo.processInfo.environment["CASTIEL_ALERT_LOG"] {
            return envPath
        }
        return "/usr/local/var/log/castiel/castiel_alerts.jsonl"
    }

    func startWatching() {
        stopWatching()
        isWatching = true
        timer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { _ in
            self.checkForNewAlerts()
        }
        // Initial load
        checkForNewAlerts()
    }

    func stopWatching() {
        timer?.invalidate()
        timer = nil
        isWatching = false
    }

    func clear() {
        alerts.removeAll()
    }

    private func checkForNewAlerts() {
        let path = logPath
        guard FileManager.default.fileExists(atPath: path) else { return }

        let attrs = (try? FileManager.default.attributesOfItem(atPath: path)) ?? [:]
        let fileSize = (attrs[.size] as? Int64) ?? 0

        if fileSize < lastFileSize {
            // File was truncated/rotated
            lastFileSize = 0
        }

        guard fileSize > lastFileSize else { return }

        let fileHandle = FileHandle(forReadingAtPath: path)
        defer { fileHandle?.closeFile() }

        fileHandle?.seekToEndOfFile()
        let _ = fileHandle?.offsetInFile
        fileHandle?.seek(toFileOffset: UInt64(lastFileSize))

        let newData = fileHandle?.readDataToEndOfFile() ?? Data()
        lastFileSize = fileSize

        guard let text = String(data: newData, encoding: .utf8) else { return }

        for line in text.split(separator: "\n") {
            if let alert = parseAlertLine(String(line)) {
                DispatchQueue.main.async {
                    self.alerts.insert(alert, at: 0)
                    if self.alerts.count > self.maxAlerts {
                        self.alerts.removeLast()
                    }
                }
            }
        }
    }

    private func parseAlertLine(_ line: String) -> AlertEntry? {
        // Expected format: "2026-08-01T23:00:00Z [CRITICAL] type=blocklist_hit src=192.168.1.1 domain=evil.com msg=Blocked domain evil.com"
        // Or JSON: {"timestamp":"...","type":"...","severity":"...","source":"...","domain":"...","message":"..."}

        // Try JSON first
        if let data = line.data(using: .utf8) {
            if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                let ts = (json["time"] as? String) ?? (json["timestamp"] as? String) ?? ""
                let formatter = ISO8601DateFormatter()
                formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
                let date = formatter.date(from: ts) ?? ISO8601DateFormatter().date(from: ts) ?? Date()
                return AlertEntry(
                    timestamp: date,
                    type: (json["type"] as? String) ?? "unknown",
                    severity: (json["severity"] as? String) ?? "info",
                    source: (json["source"] as? String) ?? "",
                    domain: (json["domain"] as? String) ?? "",
                    message: (json["message"] as? String) ?? line
                )
            }
        }

        // Try structured text format
        let parts = line.components(separatedBy: " ")
        guard parts.count >= 3 else { return nil }

        var severity = "info"
        var type = "unknown"
        var source = ""
        var domain = ""
        var message = ""

        for part in parts {
            if part.hasPrefix("[") && part.hasSuffix("]") {
                severity = part.dropFirst().dropLast().lowercased()
            } else if part.hasPrefix("type=") {
                type = String(part.dropFirst("type=".count))
            } else if part.hasPrefix("src=") {
                source = String(part.dropFirst("src=".count))
            } else if part.hasPrefix("domain=") {
                domain = String(part.dropFirst("domain=".count))
            } else if part.hasPrefix("msg=") {
                message = String(part.dropFirst("msg=".count))
            }
        }

        if message.isEmpty {
            message = line
        }

        // Parse timestamp from first field
        let timestamp = ISO8601DateFormatter().date(from: parts[0]) ?? Date()

        return AlertEntry(
            timestamp: timestamp,
            type: type,
            severity: severity,
            source: source,
            domain: domain,
            message: message
        )
    }
}
