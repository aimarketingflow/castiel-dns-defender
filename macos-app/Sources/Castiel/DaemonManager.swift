//
//  DaemonManager.swift
//  Manages the Castiel Go binary process lifecycle and signal-based DoH control.
//

import Foundation
import SwiftUI

enum DaemonStatus: String, Codable {
    case stopped = "Stopped"
    case starting = "Starting..."
    case running = "Running"
    case error = "Error"
}

enum DoHStatus: String, Codable {
    case enabled = "Enabled"
    case disabled = "Disabled"
    case unknown = "Unknown"
}

struct LogEntry: Identifiable, Equatable {
    let id = UUID()
    let timestamp: Date
    let level: LogLevel
    let message: String
}

enum LogLevel: String, Codable {
    case info = "INFO"
    case warn = "WARN"
    case error = "ERR"
    case debug = "DEBUG"
}

class DaemonManager: ObservableObject {
    @Published var status: DaemonStatus = .stopped
    @Published var dohStatus: DoHStatus = .unknown
    @Published var pid: Int32 = 0
    @Published var lastError: String?
    @Published var logEntries: [LogEntry] = []
    @Published var showLogPanel: Bool = false

    private var process: Process?
    private var logPipe: Pipe?

    let binaryPath: String
    let configPath: String
    let projectRoot: String

    init() {
        let envRoot = ProcessInfo.processInfo.environment["CASTIEL_ROOT"]
        let cwd = FileManager.default.currentDirectoryPath
        let bundlePath = Bundle.main.bundlePath
        let bundleExec = Bundle.main.executablePath ?? bundlePath
        let bundleDir = (bundleExec as NSString).deletingLastPathComponent
        let bundleResources = Bundle.main.resourcePath ?? bundleDir

        // Collect all possible search roots
        let searchRoots = [
            envRoot,
            cwd,
            bundlePath,
            bundleDir,
            bundleResources,
            "/usr/local",
            "/opt/castiel",
            "/Applications/Castiel.app/Contents/Resources",
        ].compactMap { $0 }

        // Search for the binary
        // Exclude the app's own executable (Contents/MacOS/Castiel) — macOS is
        // case-insensitive so "castiel" matches "Castiel"
        let ownExecutable = Bundle.main.executablePath ?? ""
        let possiblePaths = searchRoots.flatMap { root in
            ["\(root)/castiel", "\(root)/bin/castiel", "\(root)/../castiel"]
        } + ["/usr/local/bin/castiel", "/opt/castiel/castiel"]

        if let found = possiblePaths.first(where: { path in
            // Skip the app's own executable
            if path.lowercased() == ownExecutable.lowercased() { return false }
            var isDir: ObjCBool = false
            return FileManager.default.fileExists(atPath: path, isDirectory: &isDir)
                && !isDir.boolValue
                && FileManager.default.isExecutableFile(atPath: path)
        }) {
            binaryPath = found
        } else {
            binaryPath = "/usr/local/bin/castiel"
        }

        // Search for config
        let possibleConfigs = searchRoots.flatMap { root in
            ["\(root)/config.yaml", "\(root)/etc/castiel/config.yaml"]
        } + ["/usr/local/etc/castiel/config.yaml", "/opt/castiel/config.yaml"]

        if let found = possibleConfigs.first(where: { FileManager.default.fileExists(atPath: $0) }) {
            configPath = found
        } else {
            configPath = "/usr/local/etc/castiel/config.yaml"
        }

        projectRoot = envRoot ?? cwd

        // Now log initialization steps
        addLog(.info, "=== Castiel App Starting ===")
        addLog(.info, "Bundle path: \(bundlePath)")
        addLog(.info, "CWD: \(cwd)")
        if let er = envRoot { addLog(.info, "CASTIEL_ROOT env: \(er)") }
        addLog(.debug, "Searched binary paths: \(possiblePaths.joined(separator: ", "))")

        if FileManager.default.isExecutableFile(atPath: binaryPath) {
            addLog(.info, "Found Castiel binary at: \(binaryPath)")
        } else {
            addLog(.warn, "Castiel binary not found. Defaulting to: \(binaryPath)")
            addLog(.warn, "Install with: sudo cp castiel /usr/local/bin/castiel")
            addLog(.warn, "Or copy into app bundle: cp castiel /Applications/Castiel.app/Contents/Resources/")
        }

        addLog(.debug, "Searched config paths: \(possibleConfigs.joined(separator: ", "))")
        if FileManager.default.fileExists(atPath: configPath) {
            addLog(.info, "Config file found: \(configPath)")
        } else {
            addLog(.warn, "Config file not found. Defaulting to: \(configPath)")
            addLog(.warn, "Install with: sudo mkdir -p /usr/local/etc/castiel && sudo cp config.yaml /usr/local/etc/castiel/")
        }

        addLog(.info, "App initialized. Ready to start daemon.")

        NetworkMonitor.shared.start()
        NetworkMonitor.shared.onStateChange { [weak self] state in
            DispatchQueue.main.async {
                switch state {
                case .offline:
                    self?.addLog(.warn, "Network offline detected — pausing metrics polling")
                    self?.addLog(.warn, "Interface: \(NetworkMonitor.shared.interfaceType)")
                case .online:
                    self?.addLog(.info, "Network online detected — resuming polling (interface: \(NetworkMonitor.shared.interfaceType))")
                case .unknown:
                    break
                }
            }
        }

        let currentState = NetworkMonitor.shared.state
        if currentState == .offline {
            addLog(.warn, "Starting with network offline — polling will resume when network returns")
        } else if currentState == .online {
            addLog(.info, "Network online: \(NetworkMonitor.shared.interfaceType)")
        }
    }

    // MARK: - Logging

    func addLog(_ level: LogLevel, _ message: String) {
        let entry = LogEntry(timestamp: Date(), level: level, message: message)
        DispatchQueue.main.async {
            self.logEntries.append(entry)
            if self.logEntries.count > 1000 {
                self.logEntries.removeFirst(self.logEntries.count - 500)
            }
        }
    }

    var logText: String {
        logEntries.map { entry in
            let timeStr = ISO8601DateFormatter().string(from: entry.timestamp)
            return "[\(timeStr)] [\(entry.level.rawValue)] \(entry.message)"
        }.joined(separator: "\n")
    }

    func clearLogs() {
        logEntries.removeAll()
    }

    func copyLogs() {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(logText, forType: .string)
    }

    // MARK: - Daemon Discovery

    /// Find the PID of an already-running castiel daemon (e.g. started by LaunchDaemon).
    private func findDaemonPID() -> Int32 {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
        proc.arguments = ["-x", "castiel"]
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = FileHandle.nullDevice
        do {
            try proc.run()
            proc.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            if let output = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
               let firstLine = output.components(separatedBy: "\n").first,
               let foundPid = Int32(firstLine), foundPid > 0 {
                return foundPid
            }
        } catch {}
        return 0
    }

    // MARK: - Daemon Lifecycle

    func start() {
        guard status != .running else {
            addLog(.warn, "Start requested but daemon is already running")
            return
        }
        guard status != .starting else {
            addLog(.warn, "Start requested but daemon is already starting")
            return
        }

        addLog(.info, "=== Starting Castiel Daemon ===")

        // Check if a daemon is already running (e.g. via LaunchDaemon)
        addLog(.info, "Checking for existing daemon on 127.0.0.1:9090...")
        if let url = URL(string: "http://127.0.0.1:9090/metrics") {
            let semaphore = DispatchSemaphore(value: 0)
            var alreadyRunning = false
            let config = URLSessionConfiguration.ephemeral
            config.timeoutIntervalForRequest = 2
            let session = URLSession(configuration: config)
            session.dataTask(with: url) { data, response, _ in
                if let http = response as? HTTPURLResponse, http.statusCode == 200 {
                    alreadyRunning = true
                }
                semaphore.signal()
            }.resume()
            _ = semaphore.wait(timeout: .now() + 3)
            if alreadyRunning {
                addLog(.info, "Daemon already running on 127.0.0.1:9090 (e.g. via LaunchDaemon)")
                // Find the PID of the running daemon so we can send signals (DoH toggle)
                let foundPid = self.findDaemonPID()
                if foundPid > 0 {
                    addLog(.info, "Attached to existing daemon (PID: \(foundPid))")
                } else {
                    addLog(.warn, "Could not find daemon PID — DoH toggle may not work")
                }
                DispatchQueue.main.async {
                    self.status = .running
                    self.pid = foundPid
                    self.dohStatus = .enabled
                    self.lastError = nil
                }
                return
            }
        }

        // Pre-flight checks
        addLog(.info, "Running pre-flight checks...")

        if !FileManager.default.isExecutableFile(atPath: binaryPath) {
            let msg = "Castiel binary not found or not executable at: \(binaryPath)"
            addLog(.error, msg)
            addLog(.error, "Please build the daemon first: make build")
            addLog(.error, "Or install it: sudo make install")
            DispatchQueue.main.async {
                self.status = .error
                self.lastError = msg
            }
            return
        }
        addLog(.info, "Pre-flight: binary OK (\(binaryPath))")

        if !FileManager.default.fileExists(atPath: configPath) {
            let msg = "Config file not found: \(configPath)"
            addLog(.error, msg)
            addLog(.error, "Please ensure config.yaml exists")
            DispatchQueue.main.async {
                self.status = .error
                self.lastError = msg
            }
            return
        }
        addLog(.info, "Pre-flight: config OK (\(configPath))")

        DispatchQueue.main.async {
            self.status = .starting
            self.lastError = nil
        }

        addLog(.info, "Launching daemon process...")

        DispatchQueue.global(qos: .userInitiated).async {
            let proc = Process()
            proc.executableURL = URL(fileURLWithPath: self.binaryPath)
            proc.arguments = ["-config", self.configPath]

            // Set working directory to the config file's directory so relative paths
            // (data/, logs/, etc.) resolve correctly
            let configDir = (self.configPath as NSString).deletingLastPathComponent
            proc.currentDirectoryURL = URL(fileURLWithPath: configDir)
            self.addLog(.info, "Working directory: \(configDir)")

            let pipe = Pipe()
            proc.standardOutput = pipe
            proc.standardError = pipe

            self.logPipe = pipe

            do {
                try proc.run()
                let launchedPid = proc.processIdentifier
                self.addLog(.info, "Daemon process launched successfully (PID: \(launchedPid))")

                DispatchQueue.main.async {
                    self.process = proc
                    self.pid = launchedPid
                    self.status = .running
                    self.dohStatus = .enabled
                }

                self.addLog(.info, "DoH status: Enabled (assumed from config)")
                self.addLog(.info, "Starting log reader pipe...")
                self.startLogReader(pipe)

                self.addLog(.info, "Waiting for daemon process to exit...")
                proc.waitUntilExit()

                let exitCode = proc.terminationStatus
                if exitCode == 0 {
                    self.addLog(.info, "Daemon exited normally (exit code 0)")
                } else {
                    self.addLog(.error, "Daemon exited with code: \(exitCode)")
                }

                DispatchQueue.main.async {
                    self.status = .stopped
                    self.pid = 0
                    self.dohStatus = .unknown
                }
                self.addLog(.info, "Daemon process stopped")

            } catch {
                let errMsg = "Failed to launch daemon: \(error.localizedDescription)"
                self.addLog(.error, errMsg)
                self.addLog(.error, "Error type: \(type(of: error))")

                if let nsError = error as NSError? {
                    self.addLog(.error, "Domain: \(nsError.domain), Code: \(nsError.code)")
                    if let underlying = nsError.userInfo[NSUnderlyingErrorKey] as? Error {
                        self.addLog(.error, "Underlying: \(underlying.localizedDescription)")
                    }
                }

                self.addLog(.error, "Binary path: \(self.binaryPath)")
                self.addLog(.error, "Config path: \(self.configPath)")
                self.addLog(.error, "Check: binary exists=\(FileManager.default.isExecutableFile(atPath: self.binaryPath))")
                self.addLog(.error, "Check: config exists=\(FileManager.default.fileExists(atPath: self.configPath))")

                DispatchQueue.main.async {
                    self.status = .error
                    self.lastError = errMsg
                }
            }
        }
    }

    func stop() {
        guard let proc = process, proc.isRunning else {
            addLog(.warn, "Stop requested but no running process found")
            return
        }

        addLog(.info, "Stopping daemon (PID: \(proc.processIdentifier))...")
        proc.terminate()

        DispatchQueue.main.async {
            self.status = .stopped
            self.pid = 0
            self.dohStatus = .unknown
        }

        addLog(.info, "SIGTERM sent to daemon")
    }

    // MARK: - DoH Control

    func toggleDoH() {
        guard pid > 0 else {
            addLog(.warn, "Toggle DoH requested but daemon not running (PID: 0)")
            return
        }

        addLog(.info, "Sending SIGHUP to PID \(pid) — toggling DoH...")
        let result = kill(pid, SIGHUP)
        if result == 0 {
            addLog(.info, "SIGHUP sent successfully")
            DispatchQueue.main.async {
                self.dohStatus = (self.dohStatus == .enabled) ? .disabled : .enabled
            }
        } else {
            let err = String(cString: strerror(errno))
            addLog(.error, "SIGHUP failed: \(err) (errno: \(errno))")
        }
    }

    func emergencyDisableDoH() {
        guard pid > 0 else {
            addLog(.warn, "Emergency disable DoH requested but daemon not running (PID: 0)")
            return
        }

        addLog(.warn, "Sending SIGUSR1 to PID \(pid) — emergency DoH disable...")
        let result = kill(pid, SIGUSR1)
        if result == 0 {
            addLog(.warn, "SIGUSR1 sent — DoH emergency disabled")
            DispatchQueue.main.async {
                self.dohStatus = .disabled
            }
        } else {
            let err = String(cString: strerror(errno))
            addLog(.error, "SIGUSR1 failed: \(err) (errno: \(errno))")
        }
    }

    func reEnableDoH() {
        guard pid > 0 else {
            addLog(.warn, "Re-enable DoH requested but daemon not running (PID: 0)")
            return
        }

        addLog(.info, "Sending SIGUSR2 to PID \(pid) — re-enabling DoH...")
        let result = kill(pid, SIGUSR2)
        if result == 0 {
            addLog(.info, "SIGUSR2 sent — DoH re-enabled")
            DispatchQueue.main.async {
                self.dohStatus = .enabled
            }
        } else {
            let err = String(cString: strerror(errno))
            addLog(.error, "SIGUSR2 failed: \(err) (errno: \(errno))")
        }
    }

    // MARK: - Log Reader

    private func startLogReader(_ pipe: Pipe) {
        let handle = pipe.fileHandleForReading
        handle.readabilityHandler = { [weak self] fh in
            let data = fh.availableData
            if data.isEmpty {
                fh.readabilityHandler = nil
                self?.addLog(.info, "Daemon log pipe closed (EOF)")
                return
            }
            if let output = String(data: data, encoding: .utf8) {
                let lines = output.split(separator: "\n", omittingEmptySubsequences: false)
                for line in lines {
                    let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
                    if trimmed.isEmpty { continue }

                    let level: LogLevel
                    if trimmed.contains("[ERR]") || trimmed.contains("error") || trimmed.contains("ERROR") || trimmed.contains("fail") {
                        level = .error
                    } else if trimmed.contains("[WARN]") || trimmed.contains("warn") {
                        level = .warn
                    } else if trimmed.contains("[DEBUG]") || trimmed.contains("debug") {
                        level = .debug
                    } else {
                        level = .info
                    }

                    self?.addLog(level, "[daemon] \(trimmed)")
                }
            }
        }
        addLog(.info, "Log reader pipe attached to daemon stdout/stderr")
    }

    // MARK: - Kill Switch Script

    func runKillSwitchScript(_ action: String) {
        addLog(.info, "Running kill switch script: \(action)")

        DispatchQueue.global(qos: .userInitiated).async {
            let scriptPath = self.binaryPath.replacingOccurrences(of: "/castiel", with: "/doh-killswitch.sh")

            if !FileManager.default.isExecutableFile(atPath: scriptPath) {
                self.addLog(.error, "Kill switch script not found: \(scriptPath)")
                return
            }

            let proc = Process()
            proc.executableURL = URL(fileURLWithPath: "/bin/bash")
            proc.arguments = [scriptPath, action]

            let pipe = Pipe()
            proc.standardOutput = pipe
            proc.standardError = pipe

            do {
                try proc.run()
                self.addLog(.info, "Kill switch script started (PID: \(proc.processIdentifier))")
                proc.waitUntilExit()

                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                if let output = String(data: data, encoding: .utf8) {
                    for line in output.split(separator: "\n") {
                        self.addLog(.info, "[killswitch] \(line)")
                    }
                }

                if proc.terminationStatus == 0 {
                    self.addLog(.info, "Kill switch '\(action)' completed successfully")
                } else {
                    self.addLog(.error, "Kill switch '\(action)' exited with code: \(proc.terminationStatus)")
                }
            } catch {
                self.addLog(.error, "Kill switch failed: \(error.localizedDescription)")
            }
        }
    }
}
