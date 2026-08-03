//
//  StatusBarController.swift
//  Castiel — Menu Bar Status Item
//
//  Provides a persistent menu bar icon with quick controls.
//  The app stays alive in the background when the main window is closed.
//

import AppKit
import SwiftUI

class StatusBarController: NSObject, ObservableObject {
    private var statusItem: NSStatusItem?
    private var menu: NSMenu?
    private weak var daemon: DaemonManager?
    private var statusMenuItem: NSMenuItem?
    private var startStopMenuItem: NSMenuItem?
    private var dohMenuItem: NSMenuItem?
    private var observer: NSObjectProtocol?

    func setup(daemon: DaemonManager) {
        self.daemon = daemon

        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)

        if let button = statusItem?.button {
            if let img = NSImage(systemSymbolName: "shield.checkered", accessibilityDescription: "Castiel") {
                img.isTemplate = true
                button.image = img
            } else if let img = NSImage(systemSymbolName: "shield.fill", accessibilityDescription: "Castiel") {
                img.isTemplate = true
                button.image = img
            } else {
                button.title = "C"
            }
            button.toolTip = "Castiel DNS Defense"
        }

        buildMenu()
        statusItem?.menu = menu

        // Observe daemon status changes on the main thread
        observer = NotificationCenter.default.addObserver(
            forName: NSApplication.didBecomeActiveNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            self?.refreshMenu()
        }

        // Poll for status updates periodically
        Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in
            DispatchQueue.main.async {
                self?.refreshMenu()
            }
        }
    }

    private func buildMenu() {
        menu = NSMenu()

        // Status line
        statusMenuItem = NSMenuItem(title: "Castiel: Checking...", action: nil, keyEquivalent: "")
        statusMenuItem?.isEnabled = false
        menu?.addItem(statusMenuItem!)

        menu?.addItem(NSMenuItem.separator())

        // Start / Stop
        startStopMenuItem = NSMenuItem(title: "Start Daemon", action: #selector(toggleDaemon), keyEquivalent: "s")
        startStopMenuItem?.target = self
        menu?.addItem(startStopMenuItem!)

        // DoH Toggle
        dohMenuItem = NSMenuItem(title: "DoH: Unknown", action: #selector(toggleDoH), keyEquivalent: "d")
        dohMenuItem?.target = self
        menu?.addItem(dohMenuItem!)

        menu?.addItem(NSMenuItem.separator())

        // Show Window
        let showItem = NSMenuItem(title: "Show Dashboard", action: #selector(showMainWindow), keyEquivalent: "o")
        showItem.target = self
        menu?.addItem(showItem)

        menu?.addItem(NSMenuItem.separator())

        // Quit
        let quitItem = NSMenuItem(title: "Quit Castiel", action: #selector(quitApp), keyEquivalent: "q")
        quitItem.target = self
        menu?.addItem(quitItem)

        refreshMenu()
    }

    func refreshMenu() {
        guard let daemon = daemon else { return }

        let statusEmoji: String
        switch daemon.status {
        case .running:
            statusEmoji = "●"
            statusMenuItem?.title = "\(statusEmoji) Castiel: Protected"
            startStopMenuItem?.title = "Stop Daemon"
            startStopMenuItem?.action = #selector(toggleDaemon)
        case .starting:
            statusEmoji = "◐"
            statusMenuItem?.title = "\(statusEmoji) Castiel: Starting..."
            startStopMenuItem?.title = "Starting..."
            startStopMenuItem?.action = nil
        case .stopped:
            statusEmoji = "○"
            statusMenuItem?.title = "\(statusEmoji) Castiel: Stopped"
            startStopMenuItem?.title = "Start Daemon"
            startStopMenuItem?.action = #selector(toggleDaemon)
        case .error:
            statusEmoji = "✕"
            statusMenuItem?.title = "\(statusEmoji) Castiel: Error"
            startStopMenuItem?.title = "Restart Daemon"
            startStopMenuItem?.action = #selector(toggleDaemon)
        }

        // Update menu bar icon tint based on status
        if let button = statusItem?.button {
            if daemon.status == .running {
                if let img = NSImage(systemSymbolName: "shield.checkered", accessibilityDescription: "Castiel — Protected") {
                    img.isTemplate = true
                    button.image = img
                }
            } else {
                if let img = NSImage(systemSymbolName: "shield.slash", accessibilityDescription: "Castiel — Not Protected") {
                    img.isTemplate = true
                    button.image = img
                }
            }
        }

        switch daemon.dohStatus {
        case .enabled:
            dohMenuItem?.title = "DoH Block: Enabled"
        case .disabled:
            dohMenuItem?.title = "DoH Block: Disabled"
        case .unknown:
            dohMenuItem?.title = "DoH Block: Unknown"
        }
    }

    @objc private func toggleDaemon() {
        guard let daemon = daemon else { return }
        if daemon.status == .running {
            daemon.stop()
        } else {
            daemon.start()
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
            self.refreshMenu()
        }
    }

    @objc private func toggleDoH() {
        daemon?.toggleDoH()
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
            self.refreshMenu()
        }
    }

    @objc private func showMainWindow() {
        NSApplication.shared.activate(ignoringOtherApps: true)
        if let window = NSApplication.shared.windows.first(where: { $0.canBecomeMain }) {
            window.makeKeyAndOrderFront(nil)
        } else {
            // If window was closed, re-open it
            NSApplication.shared.activate(ignoringOtherApps: true)
            for window in NSApplication.shared.windows {
                window.makeKeyAndOrderFront(nil)
            }
        }
    }

    @objc private func quitApp() {
        NSApplication.shared.terminate(nil)
    }
}
