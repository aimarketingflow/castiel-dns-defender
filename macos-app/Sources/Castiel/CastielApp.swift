//
//  CastielApp.swift
//  Castiel — macOS DNS Defense
//
//  Native SwiftUI app for managing the Castiel DNS daemon:
//  - Start/stop the daemon
//  - Toggle DoH kill switch
//  - View real-time metrics
//  - Configure settings
//  - View alerts
//

import SwiftUI

@main
struct CastielApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var daemon = DaemonManager()
    @StateObject private var metrics = MetricsPoller()
    @StateObject private var alertFeed = AlertFeed()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(daemon)
                .environmentObject(metrics)
                .environmentObject(alertFeed)
                .frame(minWidth: 900, minHeight: 600)
                .onAppear {
                    appDelegate.setup(daemon: daemon)
                }
        }
        .windowStyle(.titleBar)
        .commands {
            CommandGroup(after: .appSettings) {
                Button("Start Daemon") {
                    daemon.start()
                }
                .keyboardShortcut("s", modifiers: [.command, .shift])
                .disabled(daemon.status == .running)

                Button("Stop Daemon") {
                    daemon.stop()
                }
                .keyboardShortcut("x", modifiers: [.command, .shift])
                .disabled(daemon.status != .running)

                Divider()

                Button("Toggle DoH") {
                    daemon.toggleDoH()
                }
                .keyboardShortcut("d", modifiers: [.command, .shift])
                .disabled(daemon.status != .running)

                Button("Emergency Disable DoH") {
                    daemon.emergencyDisableDoH()
                }
                .keyboardShortcut("e", modifiers: [.command, .shift])
                .disabled(daemon.status != .running)
            }
        }

        Settings {
            SettingsView()
                .environmentObject(daemon)
                .frame(width: 600, height: 500)
        }
    }
}
