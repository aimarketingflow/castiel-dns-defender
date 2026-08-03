//
//  AppDelegate.swift
//  Castiel — App Delegate
//
//  Keeps the app running in the background when the main window is closed.
//

import AppKit
import SwiftUI

class AppDelegate: NSObject, NSApplicationDelegate {
    let statusBar = StatusBarController()

    func setup(daemon: DaemonManager) {
        statusBar.setup(daemon: daemon)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        // Keep running in the menu bar when the window is closed
        return false
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        // Re-open the main window when the dock icon is clicked
        if !flag {
            for window in sender.windows {
                window.makeKeyAndOrderFront(nil)
            }
        }
        return true
    }
}
