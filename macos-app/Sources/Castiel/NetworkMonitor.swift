import Foundation
import Network
import SwiftUI

enum NetworkState: String {
    case online = "Online"
    case offline = "Offline"
    case unknown = "Unknown"
}

class NetworkMonitor: ObservableObject {
    @Published var state: NetworkState = .unknown
    @Published var interfaceType: String = "Unknown"

    static let shared = NetworkMonitor()

    private let monitor = NWPathMonitor()
    private let queue = DispatchQueue(label: "com.castiel.networkmonitor")
    private var observers: [(NetworkState) -> Void] = []
    private var started = false

    private init() {}

    func start() {
        guard !started else { return }
        started = true

        monitor.pathUpdateHandler = { [weak self] path in
            let newState: NetworkState = path.status == .satisfied ? .online : .offline
            let iface: String
            if path.usesInterfaceType(.wifi) {
                iface = "Wi-Fi"
            } else if path.usesInterfaceType(.cellular) {
                iface = "Cellular"
            } else if path.usesInterfaceType(.wiredEthernet) {
                iface = "Ethernet"
            } else if path.usesInterfaceType(.loopback) {
                iface = "Loopback"
            } else if path.usesInterfaceType(.other) {
                iface = "VPN/Other"
            } else {
                iface = "Unknown"
            }

            DispatchQueue.main.async {
                let prevState = self?.state ?? .unknown
                self?.state = newState
                self?.interfaceType = iface

                if prevState != newState {
                    for obs in self?.observers ?? [] {
                        obs(newState)
                    }
                }
            }
        }

        monitor.start(queue: queue)
    }

    func onStateChange(_ handler: @escaping (NetworkState) -> Void) {
        observers.append(handler)
    }
}
