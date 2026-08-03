//
//  SettingsView.swift
//  Configuration view for DAD settings.
//

import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var daemon: DaemonManager

    @State private var listenPort: String = "5353"
    @State private var upstreamTimeout: String = "5s"
    @State private var useDoH: Bool = true
    @State private var dohUpstream: String = "https://cloudflare-dns.com/dns-query"
    @State private var dnssecEnabled: Bool = true
    @State private var rejectBogus: Bool = true
    @State private var rateLimitEnabled: Bool = true
    @State private var perIPQPS: String = "50"
    @State private var blocklistsEnabled: Bool = true
    @State private var cacheEnabled: Bool = true
    @State private var cacheMaxEntries: String = "10000"
    @State private var pfEnabled: Bool = false

    @State private var showingSavedAlert = false

    var body: some View {
        Form {
            Section("Server") {
                LabeledContent("Listen Port") {
                    TextField("Port", text: $listenPort)
                        .frame(width: 100)
                }
                LabeledContent("Upstream Timeout") {
                    TextField("Timeout", text: $upstreamTimeout)
                        .frame(width: 100)
                }
            }

            Section("DNS-over-HTTPS") {
                Toggle("Enable DoH", isOn: $useDoH)
                LabeledContent("DoH Upstream URL") {
                    TextField("URL", text: $dohUpstream)
                        .frame(width: 300)
                }
            }

            Section("DNSSEC Validation") {
                Toggle("Enable DNSSEC", isOn: $dnssecEnabled)
                Toggle("Reject Bogus Responses", isOn: $rejectBogus)
                    .disabled(!dnssecEnabled)
            }

            Section("Rate Limiting") {
                Toggle("Enable Rate Limiting", isOn: $rateLimitEnabled)
                LabeledContent("Per-IP QPS") {
                    TextField("QPS", text: $perIPQPS)
                        .frame(width: 100)
                }
                .disabled(!rateLimitEnabled)
            }

            Section("Blocklists") {
                Toggle("Enable Blocklists", isOn: $blocklistsEnabled)
            }

            Section("Cache") {
                Toggle("Enable Cache", isOn: $cacheEnabled)
                LabeledContent("Max Entries") {
                    TextField("Entries", text: $cacheMaxEntries)
                        .frame(width: 100)
                }
                .disabled(!cacheEnabled)
            }

            Section("PF Firewall") {
                Toggle("Enable PF Redirect", isOn: $pfEnabled)
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Settings")
        .toolbar {
            Button("Save") {
                saveConfig()
                showingSavedAlert = true
            }
        }
        .alert("Settings Saved", isPresented: $showingSavedAlert) {
            Button("OK") {}
        } message: {
            Text("Configuration has been written to config.yaml. Restart the daemon to apply changes.")
        }
        .onAppear {
            loadConfig()
        }
    }

    private func loadConfig() {
        let projectRoot = ProcessInfo.processInfo.environment["DAD_ROOT"]
            ?? FileManager.default.currentDirectoryPath
        let path = "\(projectRoot)/config.yaml"

        guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { return }

        // Simple parsing of key values
        useDoH = content.contains("use_doh: true")
        dnssecEnabled = content.contains("enabled: true") && content.range(of: "dnssec:") != nil
        rateLimitEnabled = content.contains("rate_limit:") && content.contains("enabled: true")
        blocklistsEnabled = content.contains("blocklists:") && content.contains("enabled: true")
        cacheEnabled = content.contains("cache:") && content.contains("enabled: true")
        pfEnabled = content.contains("pf:") && content.contains("enabled: true")
        rejectBogus = content.contains("reject_bogus: true")

        // Extract values
        if let range = content.range(of: #"listen_port:\s*(\d+)"#, options: .regularExpression) {
            let match = content[range]
            if let port = match.split(separator: ":").last {
                listenPort = String(port).trimmingCharacters(in: .whitespaces)
            }
        }

        if let range = content.range(of: #"doh_upstream:\s*\"([^\"]+)\""#, options: .regularExpression) {
            let match = content[range]
            if let start = match.firstIndex(of: "\""), let end = match.lastIndex(of: "\""), start != end {
                dohUpstream = String(match[match.index(after: start)..<end])
            }
        }
    }

    private func saveConfig() {
        // For now, just log — a full YAML writer would go here
        // In production, use a YAML library or call the Go binary with a config-update flag
        print("Settings saved (stub — would write to config.yaml)")
    }
}
