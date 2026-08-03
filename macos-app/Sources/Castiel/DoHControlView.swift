//
//  DoHControlView.swift
//  DoH kill switch control panel.
//

import SwiftUI

struct DoHControlView: View {
    @EnvironmentObject var daemon: DaemonManager
    @State private var showingEmergencyConfirm = false

    var body: some View {
        ScrollView {
            VStack(spacing: 24) {
                // DoH Status Hero
                DoHStatusHero()
                    .environmentObject(daemon)

                // Quick Actions
                VStack(spacing: 12) {
                    Text("Quick Actions")
                        .font(.headline)
                        .frame(maxWidth: .infinity, alignment: .leading)

                    HStack(spacing: 12) {
                        DoHActionButton(
                            title: "Toggle DoH",
                            description: "Switch DoH on or off",
                            icon: "arrow.triangle.2.circlepath",
                            color: .blue,
                            action: { daemon.toggleDoH() }
                        )
                        .disabled(daemon.status != .running)

                        DoHActionButton(
                            title: "Re-enable DoH",
                            description: "Turn DoH back on",
                            icon: "lock.open.fill",
                            color: .green,
                            action: { daemon.reEnableDoH() }
                        )
                        .disabled(daemon.status != .running || daemon.dohStatus == .enabled)

                        DoHActionButton(
                            title: "Emergency Disable",
                            description: "Instantly disable DoH",
                            icon: "exclamationmark.octagon",
                            color: .red,
                            action: { showingEmergencyConfirm = true }
                        )
                        .disabled(daemon.status != .running || daemon.dohStatus == .disabled)
                    }
                }

                // Kill Switch Script
                VStack(spacing: 12) {
                    Text("Kill Switch Script")
                        .font(.headline)
                        .frame(maxWidth: .infinity, alignment: .leading)

                    VStack(spacing: 8) {
                        KillSwitchRow(
                            command: "./doh-killswitch.sh toggle",
                            description: "Toggle DoH on/off",
                            action: { daemon.runKillSwitchScript("toggle") }
                        )
                        KillSwitchRow(
                            command: "./doh-killswitch.sh off",
                            description: "Emergency disable DoH",
                            action: { daemon.runKillSwitchScript("off") }
                        )
                        KillSwitchRow(
                            command: "./doh-killswitch.sh on",
                            description: "Re-enable DoH",
                            action: { daemon.runKillSwitchScript("on") }
                        )
                        KillSwitchRow(
                            command: "./doh-killswitch.sh stop",
                            description: "Stop Castiel + remove PF + restore DNS",
                            action: { daemon.runKillSwitchScript("stop") }
                        )
                        KillSwitchRow(
                            command: "./doh-killswitch.sh restore",
                            description: "Restore DNS to DHCP defaults (last resort)",
                            action: { daemon.runKillSwitchScript("restore") }
                        )
                    }
                    .padding()
                    .background(Color(nsColor: .controlBackgroundColor))
                    .cornerRadius(8)
                }

                // Signal Reference
                VStack(spacing: 12) {
                    Text("Signal Reference")
                        .font(.headline)
                        .frame(maxWidth: .infinity, alignment: .leading)

                    VStack(spacing: 6) {
                        SignalRow(signal: "SIGHUP", description: "Toggle DoH on/off", command: "kill -HUP $(pgrep castiel)")
                        SignalRow(signal: "SIGUSR1", description: "Emergency disable DoH", command: "kill -USR1 $(pgrep castiel)")
                        SignalRow(signal: "SIGUSR2", description: "Re-enable DoH", command: "kill -USR2 $(pgrep castiel)")
                        SignalRow(signal: "SIGTERM", description: "Stop Castiel daemon", command: "kill -TERM $(pgrep castiel)")
                    }
                    .padding()
                    .background(Color(nsColor: .controlBackgroundColor))
                    .cornerRadius(8)
                }

                // Safety info
                VStack(alignment: .leading, spacing: 8) {
                    Label("Safety Layers", systemImage: "shield.lefthalf.filled")
                        .font(.headline)
                    Text("1. Auto-failover — DoH errors fall back to plain DNS per-query")
                    Text("2. Auto-disable — 5 consecutive failures → DoH off")
                    Text("3. Signal kill switch — kill -USR1 $(pgrep castiel)")
                    Text("4. Shell script — ./doh-killswitch.sh off")
                    Text("5. Config — set use_doh: false in config.yaml and restart")
                }
                .padding()
                .background(Color.yellow.opacity(0.05))
                .cornerRadius(8)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .padding()
        }
        .navigationTitle("DoH Control")
        .alert("Emergency Disable DoH?", isPresented: $showingEmergencyConfirm) {
            Button("Cancel", role: .cancel) {}
            Button("Disable Now", role: .destructive) {
                daemon.emergencyDisableDoH()
            }
        } message: {
            Text("This will instantly disable DoH and fall back to plain DNS. Use if DoH is causing connectivity issues.")
        }
    }
}

// MARK: - DoH Status Hero

struct DoHStatusHero: View {
    @EnvironmentObject var daemon: DaemonManager

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: daemon.dohStatus == .enabled ? "lock.fill" : "lock.slash.fill")
                .font(.system(size: 64))
                .foregroundColor(daemon.dohStatus == .enabled ? .green : .red)

            Text("DoH is \(daemon.dohStatus.rawValue)")
                .font(.title)
                .fontWeight(.bold)

            Text(daemon.dohStatus == .enabled
                 ? "DNS queries are encrypted over HTTPS"
                 : "DNS queries use plain DNS (unencrypted)")
                .font(.caption)
                .foregroundColor(.secondary)

            if daemon.status != .running {
                Text("Daemon is not running — start it to control DoH")
                    .font(.caption)
                    .foregroundColor(.orange)
            }
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 32)
        .background(
            LinearGradient(colors: [
                daemon.dohStatus == .enabled ? Color.green.opacity(0.1) : Color.red.opacity(0.1),
                Color.clear
            ], startPoint: .top, endPoint: .bottom)
        )
        .cornerRadius(12)
    }
}

// MARK: - DoH Action Button

struct DoHActionButton: View {
    let title: String
    let description: String
    let icon: String
    let color: Color
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            VStack(spacing: 8) {
                Image(systemName: icon)
                    .font(.title2)
                    .foregroundColor(color)
                Text(title)
                    .font(.caption)
                    .fontWeight(.medium)
                Text(description)
                    .font(.system(size: 10))
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
            }
            .frame(maxWidth: .infinity)
            .padding()
            .background(Color(nsColor: .controlBackgroundColor))
            .cornerRadius(8)
        }
        .buttonStyle(.plain)
    }
}

// MARK: - Kill Switch Row

struct KillSwitchRow: View {
    let command: String
    let description: String
    let action: () -> Void

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(command)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundColor(.blue)
                Text(description)
                    .font(.system(size: 10))
                    .foregroundColor(.secondary)
            }
            Spacer()
            Button("Run", action: action)
                .buttonStyle(.bordered)
                .controlSize(.small)
        }
        .padding(.vertical, 4)
    }
}

// MARK: - Signal Row

struct SignalRow: View {
    let signal: String
    let description: String
    let command: String

    var body: some View {
        HStack {
            Text(signal)
                .font(.system(.caption, design: .monospaced))
                .fontWeight(.bold)
                .foregroundColor(.purple)
                .frame(width: 70, alignment: .leading)
            Text(description)
                .font(.caption)
                .frame(width: 180, alignment: .leading)
            Spacer()
            Text(command)
                .font(.system(size: 10, design: .monospaced))
                .foregroundColor(.secondary)
        }
        .padding(.vertical, 2)
    }
}
