// YogaFP — menu bar app for yoga-fp (fingerprint on the Lenovo Yoga 920 under macOS).
// Talks to the root daemon yogafpd over /var/run/yogafpd.sock. It never sees image data:
// the daemon only sends prompts, progress and results.
import SwiftUI
import AppKit
import Darwin

let socketPath = "/var/run/yogafpd.sock"
let cliPath = "/usr/local/bin/yogafp"

// MARK: - Daemon client

final class DaemonCall {
    private var fd: Int32 = -1
    private var cancelled = false

    /// Sends one request and streams events on the main queue; `done` gets the final message.
    func start(_ req: [String: Any], onEvent: @escaping ([String: Any]) -> Void,
               done: @escaping ([String: Any]) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async {
            let result = self.run(req) { ev in DispatchQueue.main.async { onEvent(ev) } }
            DispatchQueue.main.async { done(result) }
        }
    }

    func cancel() {
        cancelled = true
        if fd >= 0 { shutdown(fd, SHUT_RDWR) }
    }

    private func run(_ req: [String: Any], onEvent: ([String: Any]) -> Void) -> [String: Any] {
        fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return ["ok": false, "error": "socket failed"] }
        defer { close(fd); fd = -1 }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &addr.sun_path) { buf in
            _ = socketPath.withCString { strlcpy(buf.baseAddress!.assumingMemoryBound(to: CChar.self), $0, buf.count) }
        }
        let ok = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) == 0
            }
        }
        guard ok else { return ["ok": false, "error": "daemon not running", "offline": true] }
        // Only trust a daemon running as root.
        var euid: uid_t = 1, egid: gid_t = 0
        guard getpeereid(fd, &euid, &egid) == 0, euid == 0 else {
            return ["ok": false, "error": "daemon socket is not owned by root"]
        }
        guard var data = try? JSONSerialization.data(withJSONObject: req) else { return ["ok": false] }
        data.append(0x0a)
        _ = data.withUnsafeBytes { write(fd, $0.baseAddress, data.count) }

        var pending = Data()
        var chunk = [UInt8](repeating: 0, count: 4096)
        while !cancelled {
            let n = read(fd, &chunk, chunk.count)
            if n <= 0 { break }
            pending.append(contentsOf: chunk[0..<n])
            while let nl = pending.firstIndex(of: 0x0a) {
                let line = pending.subdata(in: pending.startIndex..<nl)
                pending.removeSubrange(pending.startIndex...nl)
                guard let obj = try? JSONSerialization.jsonObject(with: line) as? [String: Any] else { continue }
                if obj["done"] as? Bool == true { return obj }
                onEvent(obj)
            }
        }
        return ["ok": false, "error": cancelled ? "cancelled" : "connection closed"]
    }
}

// MARK: - Model

enum Phase: Equatable { case idle, working, success, failure }

let regionOrder = ["center", "tip", "upper_right", "upper_left", "right", "left", "lower", "rot_cw", "rot_ccw"]
let regionTargets: [String: Int] = ["center": 4, "tip": 4, "upper_right": 5, "upper_left": 3,
                                    "right": 3, "left": 3, "lower": 3, "rot_cw": 3, "rot_ccw": 3]

@MainActor
final class Model: ObservableObject {
    @Published var online = false
    @Published var sensorReady = false
    @Published var enrolled = false
    @Published var fingers: [String] = []
    @Published var passwordNeeded: String? = nil
    @Published var sudoEnabled = false

    @Published var title = ""
    @Published var message = ""
    @Published var progress: Double = 0
    @Published var regionDone: [String: Int] = [:]
    @Published var currentRegion: String? = nil
    @Published var phase: Phase = .idle
    @Published var lastScore: Int? = nil
    @Published var pieces: Int? = nil

    // Live PAM authentication (e.g. sudo) mirrored from the daemon.
    @Published var authService: String? = nil
    @Published var authMessage = ""
    @Published var authPhase: Phase = .idle

    private var call: DaemonCall?
    private var timer: Timer?
    private var watcher: DaemonCall?

    init() {
        refresh()
        startWatching()
        timer = Timer.scheduledTimer(withTimeInterval: 10, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refresh() }
        }
    }

    var statusLine: String {
        if !online { return "Service not running" }
        if !sensorReady { return "Sensor not ready" }
        if !enrolled { return "No fingerprint enrolled" }
        return passwordNeeded == nil ? "Ready" : "Ready - type your password once"
    }

    var symbol: String {
        switch phase {
        case .working: return "touchid"
        case .success: return "checkmark.circle"
        case .failure: return "xmark.circle"
        case .idle: return online && sensorReady ? "touchid" : "exclamationmark.triangle"
        }
    }

    func refresh() {
        sudoEnabled = (try? String(contentsOfFile: "/etc/pam.d/sudo_local", encoding: .utf8))?
            .contains("pam_yogafp.so") ?? false
        DaemonCall().start(["op": "status"], onEvent: { _ in }) { [weak self] r in
            guard let self else { return }
            self.online = r["offline"] as? Bool != true && r["ok"] as? Bool == true
            self.sensorReady = r["sensor_ready"] as? Bool ?? false
            self.enrolled = r["enrolled"] as? Bool ?? false
            self.fingers = r["fingers"] as? [String] ?? []
            self.passwordNeeded = r["password_needed"] as? String
        }
    }

    /// Long-lived connection: the daemon pushes events when sudo (or another PAM service) asks for a fingerprint.
    func startWatching() {
        let w = DaemonCall(); watcher = w
        w.start(["op": "watch"], onEvent: { [weak self] ev in self?.handleAuth(ev) }) { [weak self] _ in
            // Daemon restarted or not running: retry quietly.
            DispatchQueue.main.asyncAfter(deadline: .now() + 3) { self?.startWatching() }
        }
    }

    private func handleAuth(_ ev: [String: Any]) {
        guard let svc = ev["auth"] as? String else { return }
        switch ev["event"] as? String {
        case "auth_start":
            authService = svc; authPhase = .working; authMessage = "Touch the fingerprint sensor"
            AuthPanel.show(self)
        case "lift": authMessage = (ev["msg"] as? String) ?? "Lift your finger"
        case "place": authMessage = "Touch the fingerprint sensor"
        case "nomatch", "partial": authMessage = (ev["msg"] as? String) ?? "Try again"
        case "matched": authPhase = .success; authMessage = "Recognized"
        case "auth_end":
            let r = ev["result"] as? String ?? ""
            if r == "match" { authPhase = .success; authMessage = "Recognized" }
            else if r == "cancelled" { authPhase = .idle; authMessage = "Using password" }
            else { authPhase = .failure; authMessage = r == "timeout" ? "Timed out — use your password" : "Not recognized — use your password" }
            DispatchQueue.main.asyncAfter(deadline: .now() + (r == "match" ? 0.8 : 1.6)) { [weak self] in
                AuthPanel.hide(); self?.authService = nil
            }
        default: break
        }
    }

    func usePassword() {
        authMessage = "Using password"
        DaemonCall().start(["op": "cancel_auth"], onEvent: { _ in }) { _ in }
    }

    private func begin(_ title: String) {
        self.title = title; message = "Keep your finger off the sensor"; progress = 0
        regionDone = [:]; currentRegion = nil; phase = .working; lastScore = nil; pieces = nil
    }

    private func handle(_ ev: [String: Any]) {
        if let m = ev["msg"] as? String { message = m }
        if let p = ev["progress"] as? Double { progress = p }
        switch ev["event"] as? String {
        case "place": currentRegion = ev["region"] as? String
        case "accepted":
            if let r = ev["region"] as? String { regionDone[r, default: 0] += 1 }
            pieces = ev["pieces"] as? Int
            message = "Good — lift your finger"
        case "matched": message = "Recognized"
        case "score": lastScore = ev["score"] as? Int
        default: break
        }
    }

    private func finish(_ r: [String: Any], success: String) {
        call = nil
        if r["ok"] as? Bool == true, r["match"] as? Bool ?? true {
            phase = .success; message = success; progress = 1
        } else {
            phase = .failure
            message = (r["error"] as? String) ?? (r["reason"] as? String).map { "Not recognized (\($0))" } ?? "Failed"
        }
        refresh()
        DispatchQueue.main.asyncAfter(deadline: .now() + 4) { [weak self] in
            if self?.phase != .working { self?.phase = .idle }
        }
    }

    func verify() {
        begin("Test fingerprint")
        let c = DaemonCall(); call = c
        c.start(["op": "verify", "tries": 3], onEvent: handle) { [weak self] r in
            self?.finish(r, success: "Fingerprint recognized")
        }
    }

    /// First enrollment needs an administrator: ask for the admin password (system dialog),
    /// grant a 5-minute single-use window for this user, then stream the guided enrollment.
    func enroll() {
        begin("Enroll fingerprint")
        if !enrolled {
            let uid = getuid()
            let script = "do shell script \"\(cliPath) grant-enroll --uid \(uid)\" with administrator privileges " +
                         "with prompt \"YogaFP needs an administrator to enroll a fingerprint.\""
            var err: NSDictionary?
            NSAppleScript(source: script)?.executeAndReturnError(&err)
            if err != nil { phase = .failure; message = "Administrator approval was cancelled"; return }
        } else {
            message = "Confirm with your enrolled finger first"
        }
        let c = DaemonCall(); call = c
        c.start(["op": "enroll"], onEvent: handle) { [weak self] r in
            self?.finish(r, success: "Enrolled — your fingerprint is ready")
        }
    }

    func addTouches() {
        begin("Add touches")
        message = "Confirm with your enrolled finger, then touch the area that is often missed"
        let c = DaemonCall(); call = c
        c.start(["op": "add", "count": 5], onEvent: handle) { [weak self] r in
            self?.finish(r, success: "Added")
        }
    }

    /// Enroll another named finger (max 3). The daemon first asks for an already-enrolled finger.
    func addFinger() {
        let a = NSAlert()
        a.messageText = "Add a finger"
        a.informativeText = "Give it a name, e.g. \"Left index\". You will confirm with an enrolled finger first, then touch the new finger about 30 times across its surface."
        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 240, height: 24))
        field.placeholderString = "Finger name"
        a.accessoryView = field
        a.addButton(withTitle: "Continue"); a.addButton(withTitle: "Cancel")
        a.window.initialFirstResponder = field
        guard a.runModal() == .alertFirstButtonReturn else { return }
        let name = field.stringValue.trimmingCharacters(in: .whitespaces)
        guard !name.isEmpty else { return }
        TaskWindow.show(self)
        begin("Add a finger: \(name)")
        message = "Confirm with an enrolled finger first"
        let c = DaemonCall(); call = c
        c.start(["op": "add_finger", "finger": name], onEvent: handle) { [weak self] r in
            self?.finish(r, success: "\(name) added")
        }
    }

    func removeFinger(_ name: String) {
        let a = NSAlert()
        a.messageText = "Remove \"\(name)\"?"
        a.informativeText = "You will confirm with an enrolled finger. The other fingers stay enrolled."
        a.addButton(withTitle: "Remove"); a.addButton(withTitle: "Cancel")
        a.alertStyle = .warning
        guard a.runModal() == .alertFirstButtonReturn else { return }
        TaskWindow.show(self)
        begin("Remove a finger")
        message = "Confirm with an enrolled finger"
        let c = DaemonCall(); call = c
        c.start(["op": "remove_finger", "finger": name], onEvent: handle) { [weak self] r in
            self?.finish(r, success: "\(name) removed")
        }
    }

    func deleteData() {
        let a = NSAlert()
        a.messageText = "Delete your enrolled fingerprints?"
        a.informativeText = "You will confirm with your finger. This cannot be undone."
        a.addButton(withTitle: "Delete"); a.addButton(withTitle: "Cancel")
        a.alertStyle = .warning
        guard a.runModal() == .alertFirstButtonReturn else { return }
        begin("Delete fingerprint data")
        let c = DaemonCall(); call = c
        c.start(["op": "delete"], onEvent: handle) { [weak self] r in
            self?.finish(r, success: "Fingerprint data deleted")
        }
    }

    func cancel() {
        call?.cancel(); call = nil
        phase = .idle; message = "Cancelled"
    }
}

// MARK: - Views

struct FingertipMap: View {
    let done: [String: Int]
    let current: String?

    // Approximate positions of the regions on a fingertip outline (unit square).
    private let spots: [String: CGPoint] = [
        "tip": CGPoint(x: 0.5, y: 0.15), "upper_left": CGPoint(x: 0.28, y: 0.3),
        "upper_right": CGPoint(x: 0.72, y: 0.3), "center": CGPoint(x: 0.5, y: 0.5),
        "left": CGPoint(x: 0.25, y: 0.6), "right": CGPoint(x: 0.75, y: 0.6), "lower": CGPoint(x: 0.5, y: 0.82),
        "rot_ccw": CGPoint(x: 0.12, y: 0.92), "rot_cw": CGPoint(x: 0.88, y: 0.92),
    ]

    var body: some View {
        GeometryReader { g in
            let w = g.size.width, h = g.size.height
            ZStack {
                Capsule().stroke(.secondary.opacity(0.5), lineWidth: 2)
                    .frame(width: w * 0.8, height: h * 0.98)
                    .position(x: w / 2, y: h / 2)
                ForEach(regionOrder, id: \.self) { r in
                    let p = spots[r]!
                    let frac = Double(done[r] ?? 0) / Double(regionTargets[r] ?? 1)
                    if r.hasPrefix("rot") {
                        Image(systemName: r == "rot_cw" ? "arrow.clockwise.circle.fill" : "arrow.counterclockwise.circle.fill")
                            .font(.system(size: w * 0.13))
                            .foregroundStyle(Color.accentColor.opacity(0.25 + 0.75 * min(1, frac)))
                            .overlay(Circle().stroke(current == r ? Color.accentColor : .clear, lineWidth: 3))
                            .position(x: p.x * w, y: p.y * h)
                    } else {
                        Circle()
                            .fill(Color.accentColor.opacity(0.15 + 0.75 * min(1, frac)))
                            .overlay(Circle().stroke(current == r ? Color.accentColor : .clear, lineWidth: 3))
                            .frame(width: w * 0.26, height: w * 0.26)
                            .position(x: p.x * w, y: p.y * h)
                    }
                }
            }
        }
        .aspectRatio(0.7, contentMode: .fit)
        .accessibilityLabel("Enrollment coverage")
    }
}

struct TaskView: View {
    @ObservedObject var m: Model
    var body: some View {
        VStack(spacing: 14) {
            Text(m.title).font(.headline)
            if m.title.hasPrefix("Enroll") || m.title.hasPrefix("Add") {
                FingertipMap(done: m.regionDone, current: m.currentRegion).frame(height: 180)
                ProgressView(value: m.progress).frame(width: 220)
                if let p = m.pieces {
                    Text(p == 1 ? "Assembled into one map" : "Assembled into \(p) pieces — overlap your touches a bit more")
                        .font(.caption).foregroundStyle(.secondary)
                }
            } else {
                Image(systemName: m.phase == .success ? "checkmark.circle.fill"
                      : m.phase == .failure ? "xmark.circle.fill" : "touchid")
                    .font(.system(size: 54))
                    .foregroundStyle(m.phase == .success ? .green : m.phase == .failure ? .red : .accentColor)
            }
            Text(m.message).multilineTextAlignment(.center).frame(minHeight: 40)
            HStack {
                if m.phase == .working {
                    Button("Cancel") { m.cancel() }.keyboardShortcut(.cancelAction)
                } else {
                    Button("Close") { TaskWindow.window?.close() }.keyboardShortcut(.cancelAction)
                    if m.title.hasPrefix("Test") {
                        Button("Test again") { m.verify() }.keyboardShortcut(.defaultAction)
                    } else if m.phase == .success && (m.title.hasPrefix("Enroll") || m.title.hasPrefix("Add")) {
                        Button("Test now") { m.verify() }.keyboardShortcut(.defaultAction)
                    }
                }
            }
        }
        .padding(24).frame(width: 320)
    }
}

final class TaskWindow {
    static var window: NSWindow?
    @MainActor static func show(_ m: Model) {
        if window == nil {
            let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 320, height: 380),
                             styleMask: [.titled, .closable], backing: .buffered, defer: false)
            w.title = "YogaFP"
            w.isReleasedWhenClosed = false
            w.contentView = NSHostingView(rootView: TaskView(m: m))
            window = w
        }
        window!.level = .floating
        window!.collectionBehavior = [.moveToActiveSpace, .fullScreenAuxiliary]
        window!.center()
        NSApp.activate(ignoringOtherApps: true)
        window!.makeKeyAndOrderFront(nil)
        window!.orderFrontRegardless()
    }
}

struct AuthPanelView: View {
    @ObservedObject var m: Model
    var body: some View {
        HStack(spacing: 14) {
            Image(systemName: m.authPhase == .success ? "checkmark.circle.fill"
                  : m.authPhase == .failure ? "xmark.circle.fill" : "touchid")
                .font(.system(size: 34))
                .foregroundStyle(m.authPhase == .success ? .green : m.authPhase == .failure ? .red : .accentColor)
                .symbolEffect(.pulse, isActive: m.authPhase == .working)
            VStack(alignment: .leading, spacing: 4) {
                Text(m.authService == "admin" ? "An app wants administrator rights" : "\(m.authService ?? "sudo") is requesting authentication").font(.headline)
                Text(m.authMessage).font(.subheadline).foregroundStyle(.secondary)
            }
            Spacer(minLength: 8)
            if m.authPhase == .working {
                Button("Use Password") { m.usePassword() }.keyboardShortcut(.cancelAction)
            }
        }
        .padding(16)
        .frame(width: 420)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 14))
    }
}

final class AuthPanel {
    static var panel: NSPanel?
    @MainActor static func show(_ m: Model) {
        if panel == nil {
            let p = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 420, height: 80),
                            styleMask: [.nonactivatingPanel, .borderless], backing: .buffered, defer: false)
            p.isFloatingPanel = true
            p.level = .statusBar
            p.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .stationary]
            p.isOpaque = false
            p.backgroundColor = .clear
            p.hasShadow = true
            p.hidesOnDeactivate = false
            p.contentView = NSHostingView(rootView: AuthPanelView(m: m))
            panel = p
        }
        if let screen = NSScreen.main, let p = panel {
            let f = screen.visibleFrame
            p.setFrameOrigin(NSPoint(x: f.midX - 210, y: f.maxY - 110))
        }
        panel?.orderFrontRegardless()
    }
    @MainActor static func hide() { panel?.orderOut(nil) }
}

struct MenuContent: View {
    @ObservedObject var m: Model
    var body: some View {
        Text("Fingerprint: \(m.statusLine)")
        Text("Use for sudo: \(m.sudoEnabled ? "on" : "off")")
        Divider()
        Button("Test fingerprint…") { TaskWindow.show(m); m.verify() }.disabled(!m.enrolled || !m.online)
        Button(m.enrolled ? "Re-enroll…" : "Enroll fingerprint…") { TaskWindow.show(m); m.enroll() }.disabled(!m.online)
        Button("Add touches for a missed area…") { TaskWindow.show(m); m.addTouches() }.disabled(!m.enrolled || !m.online)
        Divider()
        Text("Fingers: \(m.fingers.isEmpty ? "none" : m.fingers.joined(separator: ", ")) (\(m.fingers.count)/3)")
        Button("Add a finger…") { m.addFinger() }.disabled(!m.enrolled || !m.online || m.fingers.count >= 3)
        Menu("Remove a finger") {
            ForEach(m.fingers, id: \.self) { name in
                Button(name) { m.removeFinger(name) }
            }
        }.disabled(m.fingers.count < 2 || !m.online)
        Divider()
        Button("Delete fingerprint data…") { TaskWindow.show(m); m.deleteData() }.disabled(!m.enrolled || !m.online)
        Divider()
        Button("How to turn sudo on or off…") {
            let a = NSAlert()
            a.messageText = m.sudoEnabled ? "Turn off fingerprint for sudo" : "Use fingerprint for sudo"
            a.informativeText = "Run in Terminal, from the yoga-fp folder:\n\nsudo ./install.sh \(m.sudoEnabled ? "disable-sudo" : "enable-sudo")\n\nEnabling tests the module with a real touch first and rolls back automatically if anything fails."
            a.runModal()
        }
        Button("Refresh") { m.refresh() }
        Divider()
        Button("Quit YogaFP") { NSApp.terminate(nil) }.keyboardShortcut("q")
    }
}

@main
struct YogaFPApp: App {
    @StateObject private var model = Model()
    var body: some Scene {
        MenuBarExtra {
            MenuContent(m: model)
        } label: {
            Image(systemName: model.symbol)
        }
    }
}
