/*
 SPDX-License-Identifier: LicenseRef-EPSL-1.1

 Copyright (C) 2025 - 2026 emexlab

 This file is part of Nyxian.

 Licensed under the emexLabs Public Source License, version 1.1
 (EPSL 1.1).

 Private use and modification are permitted under the license.
 Redistribution of source or binaries, modified or unmodified,
 requires prior written permission from emexLabs.

 External deployment is subject to the source-availability
 requirements and other conditions of the license.

 Provided "AS IS", without warranty, to the extent permitted by law.

 See LICENSE for the full license terms.
*/

import UIKit
import CommonCrypto
import UniformTypeIdentifiers

final class ROMImporter: NSObject, UIDocumentPickerDelegate {
    private var completion: ((URL?) -> Void)?
    
    func present(from viewController: UIViewController, completion: @escaping (URL?) -> Void) {
        self.completion = completion
        
        let picker = UIDocumentPickerViewController(
            forOpeningContentTypes: [.item],
            asCopy: true
        )
        
        picker.delegate = self
        picker.allowsMultipleSelection = false
        
        viewController.present(picker, animated: true)
    }
    
    func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
        let url = urls.first
        
        completion?(url)
        completion = nil
    }
    
    func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) {
        completion?(nil)
        completion = nil
    }
}

final class ROMPath {
    let path: String
    let permission: Int
    
    struct ROMPathCodeSigningInfo {
        let needed: Bool
        let neededNXT2: Bool
        let nxt2: [String:Any]
    }
    let codesigning: ROMPath.ROMPathCodeSigningInfo
    
    init(path: String,
         permission: Int,
         codesigning: ROMPath.ROMPathCodeSigningInfo) {
        self.path = path
        self.permission = permission
        self.codesigning = codesigning
    }
}

func adaptiveImage(light: UIImage, dark: UIImage) -> UIImage {
    let asset = UIImageAsset()
    let lightTraits = UITraitCollection(traitsFrom: [
        .current,
        UITraitCollection(userInterfaceStyle: .light)
    ])
    asset.register(light, with: lightTraits)
    let darkTraits = UITraitCollection(traitsFrom: [
        .current,
        UITraitCollection(userInterfaceStyle: .dark)
    ])
    asset.register(dark, with: darkTraits)
    return asset.image(with: .current)
}

final class ROMManifest {
    // ABI
    let manifestVersion: Int
    
    // identity
    let identifier: String
    let name: String
    let version: String
    let dataPartitionPath: String?
    let securityVersion: UInt64
    let minimumNyxianVersion: String
    let minimumLiveProcessABI: UInt32
    let maximumNyxianVersion: String?
    
    // file permissions
    let defaultFilePermission: Int
    let defaultDirectoryPermission: Int
    let paths: [ROMPath]
    
    // runtime
    let installer: String?
    let uninstaller: String?
    let executable: String
    
    // bootlogo
    let bootlogo: UIImage?
    
    // helpers
    var isNyxianMinimumVersionMet: Bool {
        compareVersions(currentNyxianVersion(), minimumNyxianVersion) != .orderedAscending
    }
    
    var isNyxianVersionSupported: Bool {
        guard isNyxianMinimumVersionMet else { return false }
        if let maximumNyxianVersion {
            return compareVersions(currentNyxianVersion(), maximumNyxianVersion) == .orderedAscending
        }
        return true
    }
    
    var isHostCompatible: Bool {
        isNyxianVersionSupported && minimumLiveProcessABI <= NXLiveProcessGetHostABIVersion()
    }
    
    var hostRequirement: String {
        if minimumLiveProcessABI > NXLiveProcessGetHostABIVersion() {
            return "\(nyxianRequirement) and LiveProcess ABI \(minimumLiveProcessABI)"
        }
        return nyxianRequirement
    }
    
    var nyxianRequirement: String {
        if let maximumNyxianVersion {
            return "Nyxian \(minimumNyxianVersion) up to (not including) \(maximumNyxianVersion)"
        }
        return "Nyxian \(minimumNyxianVersion) or newer"
    }
    
    init(manifestPlistURL: URL) throws {
        // first we'll read the plist
        guard let manifestContent = NSDictionary(contentsOf: manifestPlistURL) as? [String: Any] else {
            throw NSError(domain: "org.emexlabs.nyxian.bootloader.rom-flash", code: 1, userInfo: [NSLocalizedDescriptionKey:"failed to read menifest plist"])
        }
        
        // next we need to parse version
        guard let manifestVersion = manifestContent["NXRomManifestVersion"] as? Int,
              let identifier = manifestContent["NXRomIdentifier"] as? String,
              let name = manifestContent["NXRomName"] as? String,
              let version = manifestContent["NXRomVersion"] as? String,
              let minimumNyxianVersion = manifestContent["NXRomMinimumNyxianVersion"] as? String,
              let executable = manifestContent["NXRomExecutable"] as? String else {
            throw NSError(domain: "org.emexlabs.nyxian.bootloader.rom-flash", code: 1, userInfo: [NSLocalizedDescriptionKey:"malformed manifest plist"])
        }
        
        guard let securityVersion = NXROMParseSecurityVersion(manifestContent["NXRomSecurityVersion"]) else {
            throw romError("ROM has no valid NXRomSecurityVersion; legacy ROMs cannot bypass rollback protection")
        }
        guard NXROMIdentifierIsValid(identifier) else { throw romError("Invalid NXRomIdentifier") }
        if let raw = manifestContent["NXRomDataPartitionPath"] {
            guard let path = raw as? String else { throw romError("NXRomDataPartitionPath must be a string") }
            _ = try romDataPartitionURL(path)
            self.dataPartitionPath = path
        } else { self.dataPartitionPath = nil }
        // ABI
        self.manifestVersion = manifestVersion
        
        // identity
        self.identifier = identifier
        self.name = name
        self.version = version
        self.securityVersion = securityVersion.uint64Value
        self.minimumNyxianVersion = minimumNyxianVersion
        if let raw = manifestContent["NXRomMinimumLiveProcessABI"] {
            guard let number = raw as? NSNumber,
                  CFGetTypeID(number) != CFBooleanGetTypeID(),
                  ["c", "s", "i", "l", "q", "C", "S", "I", "L", "Q"].contains(String(cString: number.objCType)),
                  number.int64Value >= 0, number.uint64Value <= UInt32.max else {
                throw romError("NXRomMinimumLiveProcessABI must be a nonnegative integer")
            }
            self.minimumLiveProcessABI = UInt32(number.uint64Value)
        } else {
            self.minimumLiveProcessABI = 0
        }
        self.maximumNyxianVersion = manifestContent["NXRomMaximumNyxianVersion"] as? String
        
        // file permissions
        self.defaultFilePermission = manifestContent["NXRomDefaultFilePermission"] as? Int ?? 420
        self.defaultDirectoryPermission = manifestContent["NXRomDefaultDirectoryPermission"] as? Int ?? 493
        
        // parsing explicit paths
        var actualPathObjects: [ROMPath] = []
        let paths: [[String:Any]] = manifestContent["NXRomPaths"] as? [[String:Any]] ?? []
        for pathDict in paths {
            let permission: Int = pathDict["NXPermission"] as? Int ?? self.defaultFilePermission
            let requiresCodeSigning: Bool = pathDict["NXRequiresCodeSigning"] as? Bool ?? false
            var requiresNXT2Signing: Bool = requiresCodeSigning
            let nxt2Entitlements: [String:Any]
            if requiresNXT2Signing {
                if let nxt2: [String:Any] = pathDict["NXT2Entitlements"] as? [String:Any] {
                    nxt2Entitlements = nxt2
                } else {
                    nxt2Entitlements = [:]
                    requiresNXT2Signing = false
                }
            } else {
                nxt2Entitlements = [:]
            }
            
            if let path: [String] = pathDict["NXPath"] as? [String] {
                for additionalPath in path {
                    actualPathObjects.append(ROMPath(path: additionalPath, permission: permission, codesigning: ROMPath.ROMPathCodeSigningInfo(needed: requiresCodeSigning, neededNXT2: requiresNXT2Signing, nxt2: nxt2Entitlements)))
                }
            } else if let path: String = pathDict["NXPath"] as? String {
                actualPathObjects.append(ROMPath(path: path, permission: permission, codesigning: ROMPath.ROMPathCodeSigningInfo(needed: requiresCodeSigning, neededNXT2: requiresNXT2Signing, nxt2: nxt2Entitlements)))
            } else {
                throw NSError(domain: "org.emexlabs.nyxian.bootloader.rom-flash", code: 1, userInfo: [NSLocalizedDescriptionKey:"malformed manifest path's in manifest plist"])
            }
        }
        self.paths = actualPathObjects
        
        self.installer = manifestContent["NXRomInstaller"] as? String
        self.uninstaller = manifestContent["NXRomUninstaller"] as? String
        self.executable = executable
        
        // bootlogo
        if let bootLogoConfig = manifestContent["NXRomBootLogo"] as? [String:String],
           let lightPath = bootLogoConfig["Light"],
           let darkPath = bootLogoConfig["Dark"],
           let light = UIImage(contentsOfFile: manifestPlistURL.deletingLastPathComponent().appendingPathComponent(lightPath).path) {
            let dark = UIImage(contentsOfFile: manifestPlistURL.deletingLastPathComponent().appendingPathComponent(darkPath).path) ?? light
            self.bootlogo = adaptiveImage(light: light, dark: dark)
        } else {
            self.bootlogo = nil
        }
    }
}

enum BootFlag: String, CaseIterable {
    case kextLoading = "nyxian.boot.kextLoading"
    case logObfucation = "nyxian.boot.log.obfuscated"
    case sandboxFilesystem = "nyxian.boot.sandbox.filesystems"
    case verboseBoot = "nyxian.boot.verbose"
    
    var title: String {
        switch self {
            case .kextLoading: return "Load kexts at boot"
            case .logObfucation: return "Obfuscate Log"
            case .sandboxFilesystem: return "Filesystem Sandbox"
            case .verboseBoot: return "Verbose Boot"
        }
    }
    
    var defaultValue: Bool {
        switch self {
            case .kextLoading: return true
            case .logObfucation: return true
            case .sandboxFilesystem: return true
            case .verboseBoot: return false
        }
    }
}

enum BootConfig {
    fileprivate static let entitlementModeKey = "nyxian.boot.entitlements.mode"
    
    static func registerDefaults() {
        var defaults: [String: Any] = Dictionary(uniqueKeysWithValues: BootFlag.allCases.map { ($0.rawValue, $0.defaultValue) })
        defaults[entitlementModeKey] = EnforcementMode.enforcing.rawValue
        defaults["nyxian.recovery.tw_military_time"] = true
        
        UserDefaults.standard.register(defaults: defaults)
    }
    
    static var entitlementMode: EnforcementMode {
        get {
            guard let raw = UserDefaults.standard.string(forKey: entitlementModeKey),
                  let mode = EnforcementMode(rawValue: raw) else {
                return .enforcing
            }
            return mode
        }
        set {
            UserDefaults.standard.set(newValue.rawValue, forKey: entitlementModeKey)
        }
    }
    
    static func isEnabled(_ flag: BootFlag) -> Bool {
        UserDefaults.standard.bool(forKey: flag.rawValue)
    }
    
    static func toggle(_ flag: BootFlag) {
        UserDefaults.standard.set(!isEnabled(flag), forKey: flag.rawValue)
    }
}

enum BootArguments {
    static let key = "nyxian.boot-args"
    
    static let help = """
        Separated by spaces. The standard ones:
        -v  verbose boot, the ROM shows its log
        -x  don't load kernel extensions
        klog_obfuscate=0  kernel log in clear text
        fs_sandbox=0  no filesystem sandbox
        Anything else is passed to the ROM. Applies the next time the ROM boots.
        """
    
    static var string: String {
        get { normalized(UserDefaults.standard.string(forKey: key) ?? "") }
        set {
            UserDefaults.standard.set(normalized(newValue), forKey: key)
            writeLegacyKeys()
        }
    }
    
    static var verbose: Bool { hasFlag("-v") }
    static var kextLoading: Bool { !hasFlag("-x") }
    static var logObfuscated: Bool { bool("klog_obfuscate", default: true) }
    static var filesystemSandbox: Bool { bool("fs_sandbox", default: true) }
    
    private static func tokens(_ args: String) -> [Substring] {
        args.split(whereSeparator: { $0 == " " || $0 == "\t" || $0 == "\n" || $0 == "\r" })
    }
    
    private static func normalized(_ args: String) -> String {
        tokens(args).joined(separator: " ")
    }
    
    static func hasFlag(_ flag: String, in args: String? = nil) -> Bool {
        tokens(args ?? string).contains { $0 == flag }
    }
    
    /// the last key=value, as NXBootArgsGetBool reads it: fallback when not given or not a boolean
    static func bool(_ name: String, default fallback: Bool, in args: String? = nil) -> Bool {
        guard let token = tokens(args ?? string).last(where: { $0.hasPrefix(name + "=") }) else { return fallback }
        switch token.dropFirst(name.count + 1).lowercased() {
        case "1", "yes", "true", "on": return true
        case "0", "no", "false", "off": return false
        default: return fallback
        }
    }
    
    /// the first 0.11.6.2 boot: whatever toggles a user had set become boot arguments
    static func migrateIfNeeded() {
        guard UserDefaults.standard.object(forKey: key) == nil else { return }
        var args: [String] = []
        if BootConfig.isEnabled(.verboseBoot) { args.append("-v") }
        if !BootConfig.isEnabled(.kextLoading) { args.append("-x") }
        if !BootConfig.isEnabled(.logObfucation) { args.append("klog_obfuscate=0") }
        if !BootConfig.isEnabled(.sandboxFilesystem) { args.append("fs_sandbox=0") }
        string = args.joined(separator: " ")
    }
    
    /// what 0.11.6.1 ROMs (and SuperSlot, and the kernel surface's sandbox check) read
    static func writeLegacyKeys() {
        let args = string
        let defaults = UserDefaults.standard
        defaults.set(hasFlag("-v", in: args), forKey: BootFlag.verboseBoot.rawValue)
        defaults.set(!hasFlag("-x", in: args), forKey: BootFlag.kextLoading.rawValue)
        defaults.set(bool("klog_obfuscate", default: true, in: args), forKey: BootFlag.logObfucation.rawValue)
        defaults.set(bool("fs_sandbox", default: true, in: args), forKey: BootFlag.sandboxFilesystem.rawValue)
    }
    
    /// this boot's arguments: the old keys and the NXBootGetArguments() export
    static func publish() {
        writeLegacyKeys()
        NXBootArgumentsHostSet(string)
    }
}

enum EnforcementMode: String, CaseIterable {
    case enforcing
    case permissive
    case disabled
    
    var badge: String {
        switch self {
            case .enforcing: return "E"
            case .permissive: return "P"
            case .disabled: return "-"
        }
    }
    
    var title: String {
        switch self {
            case .enforcing: return "Enforcing"
            case .permissive: return "Permissive"
            case .disabled: return "Disabled"
        }
    }
    
    var summary: String {
        switch self {
            case .enforcing: return "Every entitlement check runs. A process without the entitlement for an action is denied. Recommended."
            case .permissive: return "Every entitlement check runs and denials are logged, but nothing is blocked. For finding the entitlements a program is missing."
            case .disabled: return "No entitlement checks run. Every process is allowed everything the kernel surface offers."
        }
    }
    
    var warning: String? {
        switch self {
            case .enforcing: return nil
            case .permissive: return "Processes will no longer be stopped from doing what they have no entitlement for. Denials are only logged."
            case .disabled: return "Entitlement checks will not run at all. Every process, untrusted ones included, gets every privilege."
        }
    }
    
    var confirmTitle: String {
        switch self {
            case .enforcing: return "Enforce"
            case .permissive: return "Allow Permissive"
            case .disabled: return "Disable Checks"
        }
    }
}

private let otaFeedURL = URL(string: "https://emexlabs.org/switzach/ota/ota.json")!

private struct OTARelease {
    let version: String
    let name: String
    let downloadURL: URL
    let sha256: String
    let minimumNyxianVersion: String
    let maximumNyxianVersion: String?
}

private func currentNyxianVersion() -> String {
    Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.0.0"
}

private var bootloaderUserAgent: String {
    "Nyxian/\(currentNyxianVersion()) (bootloader)"
}

private func compareVersions(_ a: String, _ b: String) -> ComparisonResult {
    let left = a.split(separator: ".").map { Int($0) ?? 0 }
    let right = b.split(separator: ".").map { Int($0) ?? 0 }
    for i in 0..<max(left.count, right.count) {
        let x = i < left.count ? left[i] : 0
        let y = i < right.count ? right[i] : 0
        if x < y { return .orderedAscending }
        if x > y { return .orderedDescending }
    }
    return .orderedSame
}

private func isCompatible(_ release: OTARelease, with nyxian: String) -> Bool {
    if compareVersions(nyxian, release.minimumNyxianVersion) == .orderedAscending {
        return false
    }
    if let max = release.maximumNyxianVersion, compareVersions(nyxian, max) != .orderedAscending {
        return false
    }
    return true
}

private func sha256(of url: URL) -> String? {
    guard let data = try? Data(contentsOf: url) else {
        return nil
    }
    var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
    data.withUnsafeBytes {
        CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash)
    }
    return hash.map { String(format: "%02x", $0) }.joined()
}

private func fetchAndStageInitialROM(progress: @escaping (Double, String) -> Void, completion: @escaping (URL?) -> Void) {
    guard initialROMSlotsAreEmpty() else { DispatchQueue.main.async { completion(nil) }; return }
    let nyxian = currentNyxianVersion()
    var request = URLRequest(url: otaFeedURL, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 30)
    request.setValue(bootloaderUserAgent, forHTTPHeaderField: "User-Agent")
    request.setValue("application/json", forHTTPHeaderField: "Accept")
    
    DispatchQueue.main.async { progress(0.0, "Checking for updates…") }
    
    URLSession.shared.dataTask(with: request) { data, response, error in
        guard let data = data, error == nil,
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let entries = json["releases"] as? [[String: Any]] else {
            DispatchQueue.main.async { completion(nil) }
            return
        }
        
        var candidates: [OTARelease] = []
        for entry in entries {
            guard let version = entry["version"] as? String,
                  let urlStr = entry["url"] as? String,
                  let url = URL(string: urlStr),
                  let sha = entry["sha256"] as? String,
                  let min = entry["minimumNyxianVersion"] as? String else { continue }
            if let signed = entry["signed"] as? Bool, !signed {
                continue
            }
            let max = entry["maximumNyxianVersion"] as? String
            let name = (entry["name"] as? String) ?? "ROM \(version)"
            let rel = OTARelease(version: version, name: name, downloadURL: url, sha256: sha.lowercased(), minimumNyxianVersion: min, maximumNyxianVersion: max)
            if isCompatible(rel, with: nyxian) {
                candidates.append(rel)
            }
        }
        
        guard let best = candidates.max(by: { compareVersions($0.version, $1.version) == .orderedAscending }) else {
            DispatchQueue.main.async { completion(nil) }
            return
        }
        
        guard initialROMSlotsAreEmpty() else { DispatchQueue.main.async { completion(nil) }; return }
        DispatchQueue.main.async { progress(0.05, "Downloading \(best.name)…") }
        
        let dest = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("initial-rom-\(UUID().uuidString).zip")
        
        let task = URLSession.shared.downloadTask(with: best.downloadURL) { location, _, err in
            guard let location = location, err == nil else {
                DispatchQueue.main.async { completion(nil) }
                return
            }
            do {
                try FileManager.default.moveItem(at: location, to: dest)
                DispatchQueue.main.async { progress(0.95, "Verifying…") }
                if initialROMSlotsAreEmpty(), let hash = sha256(of: dest), hash == best.sha256 {
                    DispatchQueue.main.async { progress(1.0, "Ready"); completion(dest) }
                } else {
                    try? FileManager.default.removeItem(at: dest)
                    DispatchQueue.main.async { completion(nil) }
                }
            } catch {
                DispatchQueue.main.async { completion(nil) }
            }
        }
        
        let progressObserver = task.progress.observe(\.fractionCompleted, options: [.new]) { prog, _ in
            let frac = 0.05 + max(0, min(1, prog.fractionCompleted)) * 0.85
            DispatchQueue.main.async {
                progress(frac, "Downloading…")
            }
        }
        task.resume()
        objc_setAssociatedObject(task, "progressObserver", progressObserver, .OBJC_ASSOCIATION_RETAIN_NONATOMIC)
    }.resume()
}

private typealias NXSlotMainFn = @convention(c) () -> UnsafeMutableRawPointer?
private typealias NXSlotDidAppearFn = @convention(c) () -> Void
private typealias NXSlotCreateWindowFn = @convention(c) (UnsafeMutableRawPointer) -> UnsafeMutableRawPointer?
private typealias NXRomGenericFn = @convention(c) (UnsafePointer<CChar>) -> Int32

private func romError(_ message: String) -> NSError {
    NSError(domain: "org.emexlabs.nyxian.bootloader.rom-flash", code: 3, userInfo: [NSLocalizedDescriptionKey: message])
}

func importNyxLoaderCertificate() {
    let folder = URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/NyxLoader")
    let p12URL = folder.appendingPathComponent("Certificate.p12")
    let passwordURL = folder.appendingPathComponent("CertificatePassword")
    guard let data = try? Data(contentsOf: p12URL) else { return }
    let password = (try? String(contentsOf: passwordURL, encoding: .utf8)) ?? ""
    defer {
        try? FileManager.default.removeItem(at: p12URL)
        try? FileManager.default.removeItem(at: passwordURL)
    }
    var error: NSError?
    guard let profile = NXBootSigningProfileData(),
          NXBootValidateSigningIdentity(data, password, profile, Bundle.main.bundleIdentifier ?? "", Date(), &error) != nil else {
        bootLog("bootloader: NyxLoader's certificate not taken: \(error?.localizedDescription ?? "Nyxian has no provisioning profile")")
        return
    }
    NXBootSigningSetCredential(data, password)
    guard CFPreferencesAppSynchronize(kCFPreferencesCurrentApplication) else {
        bootLog("bootloader: NyxLoader's certificate couldn't be saved")
        return
    }
    bootLog("bootloader: signing certificate from NyxLoader taken")
}

private func requestROMTicket(rom: String, digest: Data, log: RomLog) throws -> Data {
    dispatchPrecondition(condition: .notOnQueue(.main))
    guard let nonce = NXROMTicketNewNonce() else { throw romError("Could not make a nonce for the install ticket") }
    var error: NSError?
    guard let body = NXROMTicketRequestBody(rom, digest, nonce, &error) else {
        throw error ?? romError("Could not ask for an install ticket")
    }
    log.info("asking \(NXROMTicketServerURL().host ?? "the TSS") to sign this install")
    var request = URLRequest(url: NXROMTicketServerURL(), cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 30)
    request.httpMethod = "POST"
    request.httpBody = body
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.setValue(bootloaderUserAgent, forHTTPHeaderField: "User-Agent")
    let done = DispatchSemaphore(value: 0)
    var answer: (data: Data?, status: Int, failure: String?) = (nil, 0, "no answer")
    let task = URLSession.shared.dataTask(with: request) { data, response, failure in
        answer = (data, (response as? HTTPURLResponse)?.statusCode ?? 0, failure?.localizedDescription)
        done.signal()
    }
    task.resume()
    if done.wait(timeout: .now() + 35) == .timedOut {
        task.cancel()
        done.wait()
        answer.failure = "timed out"
    }
    guard answer.status == 200, let ticket = answer.data, !ticket.isEmpty else {
        if answer.status != 0, let data = answer.data,
           let reply = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let message = (reply["error"] ?? reply["detail"]) as? String {
            throw romError("Not signed: \(message)")
        }
        if answer.status != 0 {
            throw romError("The TSS answered HTTP \(answer.status); the ROM can't be installed right now")
        }
        throw romError("Couldn't reach the TSS (\(answer.failure ?? "no answer")): installing a ROM needs the internet")
    }
    guard NXROMTicketVerify(ticket, rom, digest, nonce, &error) != nil else {
        throw error ?? romError("The install ticket doesn't verify")
    }
    log.info("install ticket signed for this device")
    return ticket
}

private func slotFile(_ relative: String,
                      in slot: URL) throws -> URL {
    let root = slot.resolvingSymlinksInPath().standardizedFileURL.path
    let url = slot.appendingPathComponent(relative).resolvingSymlinksInPath().standardizedFileURL
    guard url.path.hasPrefix(root + "/") else {
        throw romError("path escapes ROM slot: \(relative)")
    }
    return url
}

private let legacyLogFD: Int32 = 27
private let romQueue = DispatchQueue(label: "org.emexlabs.nyxian.bootloader.rom", qos: .userInitiated)
private var romOperationInProgress = false

private func drainLines(from readFD: Int32, onLine: @escaping (String) -> Void) -> DispatchGroup {
    let drained = DispatchGroup()
    drained.enter()
    DispatchQueue.global(qos: .userInitiated).async {
        var buf = [UInt8](repeating: 0, count: 4096)
        var pending: [UInt8] = []
        while true {
            let n = read(readFD, &buf, buf.count)
            if n > 0 {
                pending.append(contentsOf: buf[0..<n])
                var start = pending.startIndex
                while let nl = pending[start...].firstIndex(of: 0x0A) {
                    emitRomLine(pending[start..<nl], onLine)
                    start = nl + 1
                }
                pending.removeFirst(start)
                continue
            }
            if n < 0 && errno == EINTR {
                continue
            }
            break
        }
        emitRomLine(pending[...], onLine)
        close(readFD)
        drained.leave()
    }
    return drained
}

private func parkLegacyLogFD() {
    guard fcntl(legacyLogFD, F_GETFD) == -1, errno == EBADF else { return }
    let null = open("/dev/null", O_WRONLY)
    guard null >= 0 else { return }
    if null != legacyLogFD {
        dup2(null, legacyLogFD)
        close(null)
    }
}

private func bootLog(_ message: String) {
    NSLog("%@", message)
}

// MARK: - TrustStore

private func downloadTrustStore(timeout: TimeInterval) -> (data: Data?, failure: String?) {
    dispatchPrecondition(condition: .notOnQueue(.main))
    var url = NXTrustStoreUpdateURL()
    let installed = (NXTrustStoreStatus()["version"] as? NSNumber)?.uint64Value ?? 0
    if var components = URLComponents(url: url, resolvingAgainstBaseURL: false) {
        components.queryItems = (components.queryItems ?? []) + [URLQueryItem(name: "installed", value: String(installed))]
        url = components.url ?? url
    }
    var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: timeout)
    request.setValue(bootloaderUserAgent, forHTTPHeaderField: "User-Agent")
    let done = DispatchSemaphore(value: 0)
    var result: (data: Data?, failure: String?) = (nil, "no answer")
    let task = URLSession.shared.dataTask(with: request) { data, response, error in
        if let error {
            result = (nil, error.localizedDescription)
        } else if let http = response as? HTTPURLResponse, http.statusCode != 200 {
            result = (nil, "HTTP \(http.statusCode)")
        } else if let data, !data.isEmpty {
            result = (data, nil)
        } else {
            result = (nil, "empty response")
        }
        done.signal()
    }
    task.resume()
    if done.wait(timeout: .now() + timeout) == .timedOut {
        task.cancel()
        done.wait()
        return (nil, "timed out after \(Int(timeout)) s")
    }
    return result
}

private func trustStoreSummary() -> String {
    let status = NXTrustStoreStatus()
    let version = (status["version"] as? NSNumber)?.uint64Value ?? 0
    let keys = (status["keys"] as? NSNumber)?.intValue ?? 0
    switch status["source"] as? String {
        case "none": return "no trusted keys: no TrustStore it accepts yet (missing, too old or tampered with), it needs the online one"
        case let source?:
            let tss = (status["tss"] as? NSNumber)?.intValue ?? 0
            return "version \(version) (\(source)), \(keys) key\(keys == 1 ? "" : "s"), \(tss == 0 ? "no TSS key" : "\(tss) TSS key\(tss == 1 ? "" : "s")")"
        case nil: return "unknown"
    }
}

@discardableResult private func updateTrustStore(timeout: TimeInterval, log: (String, Bool) -> Void) -> Bool {
    let download = downloadTrustStore(timeout: timeout)
    guard let data = download.data else {
        log("could not download the TrustStore: \(download.failure ?? "unknown error")", true)
        return false
    }
    var error: NSError?
    guard let store = NXTrustStoreParse(data, &error) else {
        log("downloaded TrustStore rejected: \(error?.localizedDescription ?? "invalid")", true)
        return false
    }
    let version = (store["version"] as? NSNumber)?.uint64Value ?? 0
    let trusted = (NXTrustStoreStatus()["version"] as? NSNumber)?.uint64Value ?? 0
    if version <= trusted {
        log("TrustStore is up to date (version \(trusted))", false)
        return true
    }
    guard NXTrustStoreInstall(data, &error) else {
        log("TrustStore version \(version) not installed: \(error?.localizedDescription ?? "unknown error")", true)
        return false
    }
    let names = (store["keys"] as? [[String: Any]])?.compactMap { $0["name"] as? String } ?? []
    log("TrustStore updated to version \(version): \(names.joined(separator: ", "))", false)
    return true
}

private struct RomLog {
    let controller: NXRecoveryViewController
    
    func info(_ message: String) {
        DispatchQueue.main.async { controller.recoveryLog(message) }
    }
    
    func error(_ message: String) {
        DispatchQueue.main.async { controller.recoveryLogError(message) }
    }
    
    func rom(_ line: String) {
        if line.hasPrefix("ERROR:") {
            error(line)
        } else {
            info(line)
        }
    }
}

private func romIsBusy(_ c: NXRecoveryViewController) -> Bool {
    if romOperationInProgress {
        c.recoveryLogError("ERROR: a ROM operation is still running")
    }
    return romOperationInProgress
}

private func runRomOperation(_ c: NXRecoveryViewController, returnToMenu: Bool = false, _ work: @escaping (RomLog) -> Void) {
    dispatchPrecondition(condition: .onQueue(.main))
    guard !romIsBusy(c) else { return }
    romOperationInProgress = true
    c.enterConsole()
    let log = RomLog(controller: c)
    romQueue.async {
        work(log)
        DispatchQueue.main.async {
            romOperationInProgress = false
            if returnToMenu {
                c.finishConsole(selectAction: { controller in
                    guard let controller else { return }
                    controller.exitConsole()
                    recoveryShowMenu(recoveryController: controller)
                })
            }
        }
    }
}

private func runRomGeneric(_ relative: String, symbol: String, slot: URL, verifiedFlash: Bool = false, onLine: @escaping (String) -> Void) throws {
    dispatchPrecondition(condition: .notOnQueue(.main))
    let signing = try currentBootSigningIdentity()
    if !verifiedFlash {
        try refreshROMSigningIfNeeded(slot, identity: signing)
        var trustError: NSError?
        guard NXROMDeviceVerifyRelease(slot.path, &trustError),
              NXROMDeviceCheckRollback(slot.path, false, &trustError) else {
            throw trustError ?? romError("ROM integrity or rollback verification failed")
        }
    }
    let url = try slotFile(relative, in: slot)
    
    var fds: [Int32] = [0, 0]
    guard pipe(&fds) == 0 else {
        throw romError("pipe failed: \(String(cString: strerror(errno)))")
    }
    
    let readFD = fds[0]
    let writeFD = fds[1]
    
    let oldFD = dup(STDERR_FILENO)
    guard dup2(writeFD, STDERR_FILENO) >= 0 else {
        close(readFD)
        close(writeFD)
        if oldFD >= 0 { close(oldFD) }
        throw romError("dup2 failed: \(String(cString: strerror(errno)))")
    }
    close(writeFD)
    
    let drained = drainLines(from: readFD, onLine: onLine)
    
    func restoreLogFD() {
        if oldFD >= 0 {
            dup2(oldFD, STDERR_FILENO)
            close(oldFD)
        } else {
            close(STDERR_FILENO)
        }
        drained.wait()
    }
    
    parkLegacyLogFD()
    guard let handle = dlopen(url.path, RTLD_NOW | RTLD_LOCAL) else {
        let reason = lastDlError()
        restoreLogFD()
        throw romError("couldnt load \(relative): \(reason)")
    }
    defer { dlclose(handle) }
    
    guard let sym = dlsym(handle, symbol) else {
        restoreLogFD()
        throw romError("\(relative) has no \(symbol) entry point")
    }
    
    let generic = unsafeBitCast(sym, to: NXRomGenericFn.self)
    let rc = slot.path.withCString {
        generic($0)
    }
    
    restoreLogFD()
    
    guard rc == 0 else {
        throw romError("\(symbol) returned \(rc)")
    }
}

private func emitRomLine(_ bytes: ArraySlice<UInt8>, _ onLine: (String) -> Void) {
    var bytes = bytes
    if bytes.last == 0x0D {
        bytes = bytes.dropLast()
    }
    guard !bytes.isEmpty else { return }
    onLine(String(decoding: bytes, as: UTF8.self))
}

private enum SlotLoadResult {
    case loaded(name: String, main: NXSlotMainFn, didAppear: NXSlotDidAppearFn?, createWindow: NXSlotCreateWindowFn?)
    case failed(String)
}

private var bootLockdownAttempted = false

private typealias RestartSelfFn = @convention(c) () -> Void

private func restartSelf() {
    let RTLD_DEFAULT = UnsafeMutableRawPointer(bitPattern: -2)
    guard let sym = dlsym(RTLD_DEFAULT, "PERestartSelf") else {
        exit(0)
    }
    unsafeBitCast(sym, to: RestartSelfFn.self)()
}

private func refreshVnode(atPath path: String) -> Bool {
    let fd = open(path, O_RDWR)
    guard fd >= 0 else { return false }
    defer { close(fd) }
    guard unlink(path) == 0 else { return false }
    if fclonefileat(fd, AT_FDCWD, path, 0) == 0 {
        return true
    }
    let copyfd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0o777)
    guard copyfd >= 0 else { return false }
    defer { close(copyfd) }
    lseek(fd, 0, SEEK_SET)
    return fcopyfile(fd, copyfd, nil, copyfile_flags_t(COPYFILE_DATA)) == 0
}

// MARK: - Slots

private let activeSlotKey = "org.emexlabs.nyxian.bootloader.active-slot"
private let slotNames = ["A", "B"]

private func slotURL(_ name: String) -> URL {
    URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Boot/Slot/\(name)")
}

private func slotManifest(_ name: String) -> ROMManifest? {
    try? ROMManifest(manifestPlistURL: slotURL(name).appendingPathComponent("manifest.plist"))
}

private func slotIsFlashed(_ name: String) -> Bool {
    FileManager.default.fileExists(atPath: slotURL(name).appendingPathComponent("manifest.plist").path)
}

private func otherSlotName(_ name: String) -> String {
    name == "A" ? "B" : "A"
}

private func activeSlotName() -> String {
    let stored = UserDefaults.standard.string(forKey: activeSlotKey) ?? "A"
    let name = slotNames.contains(stored) ? stored : "A"
    if UserDefaults.standard.string(forKey: activeSlotKey) == nil,
       !slotIsFlashed(name) && slotIsFlashed(otherSlotName(name)) {
        return otherSlotName(name)
    }
    return name
}

private func setActiveSlot(_ name: String) {
    UserDefaults.standard.set(name, forKey: activeSlotKey)
    CFPreferencesAppSynchronize(kCFPreferencesCurrentApplication)
}

private func flashTargetSlotName() -> String {
    let active = activeSlotName()
    return slotIsFlashed(active) ? otherSlotName(active) : active
}

private func slotSummary(_ name: String) -> String {
    if let manifest = slotManifest(name) {
        return "Slot \(name): \(manifest.name) \(manifest.version)"
    }
    return slotIsFlashed(name) ? "Slot \(name): unreadable manifest" : "Slot \(name): empty"
}

private func flashedSlotURL() -> URL {
    slotURL(activeSlotName())
}

private func lastDlError() -> String {
    if let err = dlerror() { return String(cString: err) }
    return "unknown dyld error"
}

private func loadSlot(loadSuperslotForcefully: Bool) -> SlotLoadResult {
    let signing: BootSigningIdentity
    do {
        signing = try currentBootSigningIdentity()
    }
    catch { return .failed(error.localizedDescription) }
    let fm = FileManager.default
    let slot = flashedSlotURL()
    let manifestURL = slot.appendingPathComponent("manifest.plist")
    
    let image: URL
    let name: String
    
    let romsAllowed = NXDeviceHasUniqueID()
    if fm.fileExists(atPath: manifestURL.path), !loadSuperslotForcefully, !romsAllowed {
        bootLog("bootloader: slot \(activeSlotName()) not booted: no UniqueID")
    }
    if fm.fileExists(atPath: manifestURL.path),
       !loadSuperslotForcefully,
       romsAllowed {
        do {
            var trustError: NSError?
            try refreshROMSigningIfNeeded(slot, identity: signing)
            let manifest = try ROMManifest(manifestPlistURL: manifestURL)
            guard manifest.isHostCompatible else { throw romError("ROM requires \(manifest.hostRequirement)") }
            image = try slotFile(manifest.executable, in: slot)
            guard fm.fileExists(atPath: image.path) else { throw romError("ROM executable missing") }
            guard NXROMDeviceCommitRollback(slot.path, &trustError) else {
                throw trustError ?? romError("ROM rollback protection failed")
            }
            guard NXROMDeviceCheckRevocation(slot.path, &trustError) else {
                throw trustError ?? romError("ROM release was revoked")
            }
            guard NXROMDeviceCheckTicket(slot.path, &trustError) else {
                throw trustError ?? romError("ROM has no valid install ticket for this device")
            }
            name = manifest.name
        } catch {
            return .failed("flashed ROM is invalid: \(error.localizedDescription)")
        }
        guard fm.fileExists(atPath: image.path) else {
            return .failed("\(name): executable missing")
        }
    } else if let bundled = Bundle.main.privateFrameworksURL?.appendingPathComponent("SuperSlot.dylib"),
              fm.fileExists(atPath: bundled.path) {
        image = bundled
        name = "SuperSlot.dylib"
    } else {
        return .failed("No slot found (no flashed ROM and no bundled SuperSlot.dylib)")
    }
    
    var floorError: NSError?
    if !NXTrustStoreCommitFloor(&floorError) {
        bootLog("bootloader: TrustStore floor not recorded: \(floorError?.localizedDescription ?? "unknown error")")
    }
    
    bootLockdownAttempted = true
    guard NXBootLockdown() else {
        return .failed("boot lockdown failed")
    }
    
    // the boot arguments this slot boots with, for old ROMs as the old keys too
    BootArguments.publish()
    
    parkLegacyLogFD()
    guard let handle = dlopen(image.path, RTLD_NOW | RTLD_NODELETE | RTLD_GLOBAL) else {
        return .failed("Couldnt load \(name): \(lastDlError())")
    }
    
    guard let mainSym = dlsym(handle, "NXSlotMain") else {
        return .failed("\(name) has no NXSlotMain entry point")
    }
    
    let main = unsafeBitCast(mainSym, to: NXSlotMainFn.self)
    let didAppear = dlsym(handle, "NXSlotDidAppear").map { unsafeBitCast($0, to: NXSlotDidAppearFn.self) }
    let createWindow = dlsym(handle, "NXSlotCreateWindow").map { unsafeBitCast($0, to: NXSlotCreateWindowFn.self) }
    return .loaded(name: name, main: main, didAppear: didAppear, createWindow: createWindow)
}

private func bootConfigItems() -> [NXRecoveryItem] {
    func reload(_ c: NXRecoveryViewController) {
        c.recoveryItems = bootConfigItems()
    }
    
    var items: [NXRecoveryItem] = []
    
    let clock: NXRecoveryItem = NXRecoveryItem(title: "Use 24-hour clock") { c in
        guard let c else { return }
        let key = "nyxian.recovery.tw_military_time"
        UserDefaults.standard.set(!UserDefaults.standard.bool(forKey: key), forKey: key)
        reload(c)
    }
    clock.toggle = true
    clock.checked = UserDefaults.standard.bool(forKey: "nyxian.recovery.tw_military_time")
    items.append(clock)
    // the boot toggles are boot arguments now (BootHandoff/NXBootArgs.h)
    items.append(NXRecoveryItem(title: bootArgumentsSettingTitle()) { c in
        guard let c else { return }
        c.enterBootArgumentsInput(BootArguments.string, help: BootArguments.help) { c, value in
            guard let c, let value else { return }
            BootArguments.string = value
            reload(c)
            c.recoveryLog("Boot arguments: \(BootArguments.string.isEmpty ? "none" : BootArguments.string)")
        }
    })
    let entitlements: NXRecoveryItem = NXRecoveryItem(title: entitlementSettingTitle()) { _ in }
    entitlements.action = { [weak entitlements] c in
        if let c, let entitlements { recoveryShowEntitlements(c, settingsItem: entitlements) }
    }
    items.append(entitlements)
    items.append(NXRecoveryItem(title: "Import Recovery Theme…") { c in c?.importRecoveryTheme() })
    items.append(NXRecoveryItem(title: "Use Stock Recovery Theme") { c in c?.useStockRecoveryTheme() })
    items.append(NXRecoveryItem(title: "Restore Defaults") { c in
        guard let c else { return }
        BootArguments.string = ""
        BootConfig.entitlementMode = .enforcing
        c.restoreRecoverySettings()
        reload(c)
    })
    return items
}

private func bootArgumentsSettingTitle() -> String {
    let args = BootArguments.string
    return "Boot Arguments: \(args.isEmpty ? "none" : args)"
}

private func entitlementSettingTitle() -> String {
    "Entitlement Enforcement: \(BootConfig.entitlementMode.title)"
}

private func recoveryShowEntitlements(_ c: NXRecoveryViewController, settingsItem: NXRecoveryItem) {
    let header = "Entitlement Enforcement"
    
    func instructions() -> String {
        "\(BootConfig.entitlementMode.summary)\nApplies the next time the ROM boots."
    }
    
    func choices() -> [NXRecoveryItem] {
        EnforcementMode.allCases.map { mode in
            let item: NXRecoveryItem = NXRecoveryItem(title: mode.title) { c in
                guard let c else { return }
                if mode == BootConfig.entitlementMode || mode.warning == nil {
                    apply(c, mode)
                } else {
                    confirm(c, mode)
                }
            }
            item.toggle = true
            item.radio = true
            item.checked = mode == BootConfig.entitlementMode
            return item
        }
    }
    
    func show(_ c: NXRecoveryViewController) {
        c.setRecoveryHeader(header)
        c.setRecoveryInstructions(instructions())
        c.recoveryItems = choices()
        c.recoveryIndex = EnforcementMode.allCases.firstIndex(of: BootConfig.entitlementMode) ?? 0
    }
    
    func apply(_ c: NXRecoveryViewController, _ mode: EnforcementMode) {
        let changed = mode != BootConfig.entitlementMode
        BootConfig.entitlementMode = mode
        settingsItem.title = entitlementSettingTitle()
        show(c)
        if changed {
            if mode == .enforcing { c.recoveryLog("Entitlements: enforcing") }
            else { c.recoveryLogError("Entitlements: \(mode.rawValue)") }
        }
    }
    
    func confirm(_ c: NXRecoveryViewController, _ mode: EnforcementMode) {
        c.setRecoveryHeader("\(header)\n\(mode.title)")
        c.setRecoveryInstructions(mode.warning ?? "")
        c.recoveryItems = [
            NXRecoveryItem(title: "Cancel") { c in if let c { show(c) } },
            NXRecoveryItem(title: mode.confirmTitle) { c in if let c { apply(c, mode) } },
        ]
    }
    
    c.enterRecovery(withHeader: header, instructions: instructions(), footer: nil, items: choices(), onSelect: nil, onMove: nil)
    c.recoveryIndex = EnforcementMode.allCases.firstIndex(of: BootConfig.entitlementMode) ?? 0
}

func recoveryShowBootConfig(recoveryController c: NXRecoveryViewController) {
    c.enterRecovery(
        withHeader: "Settings",
        instructions: nil,
        footer: nil,
        items: bootConfigItems(),
        onSelect: nil,
        onMove: nil
    )
}

private struct WipeFailure {
    let path: String
    let reason: String
}

private struct WipeStats {
    var removedFiles = 0
    var removedDirectories = 0
    var bytes: Int64 = 0
    var failures: [WipeFailure] = []
}

private let maxFailuresShown = 3

private let wipeResourceKeys: [URLResourceKey] = [
    .isDirectoryKey,
    .isSymbolicLinkKey,
    .totalFileAllocatedSizeKey,
]

private func errnoDescription(_ error: Error) -> String {
    let ns = error as NSError
    if let u = ns.userInfo[NSUnderlyingErrorKey] as? NSError, u.domain == NSPOSIXErrorDomain {
        return String(cString: strerror(Int32(u.code)))
    }
    return ns.localizedDescription
}

private func formatBytes(_ bytes: Int64) -> String {
    ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)
}

private func relativePath(_ url: URL, home: String) -> String {
    let path = url.standardizedFileURL.path
    return path.hasPrefix(home) ? String(path.dropFirst(home.count)) : path
}

private func recordFailure(_ url: URL, _ error: Error, home: String, stats: inout WipeStats) {
    stats.failures.append(WipeFailure(path: relativePath(url, home: home), reason: errnoDescription(error)))
}

private func removeTree(_ url: URL,
                        keeping keep: Set<String>,
                        isRoot: Bool,
                        preservingSubtrees: Set<String> = [],
                        home: String,
                        stats: inout WipeStats) -> Bool {
    if preservingSubtrees.contains(url.standardizedFileURL.path) { return true }
    let fm = FileManager.default
    if !fm.fileExists(atPath: url.path) { return true }
    let values = try? url.resourceValues(forKeys: Set(wipeResourceKeys))
    let isSymlink = values?.isSymbolicLink ?? false
    let isRealDirectory = (values?.isDirectory ?? false) && !isSymlink
    
    var ok = true
    if isRealDirectory {
        let children: [URL]
        do {
            children = try fm.contentsOfDirectory(at: url, includingPropertiesForKeys: wipeResourceKeys, options: [])
        } catch {
            recordFailure(url, error, home: home, stats: &stats)
            return false
        }
        
        for child in children {
            let childOK = removeTree(child, keeping: keep, isRoot: false, preservingSubtrees: preservingSubtrees, home: home, stats: &stats)
            ok = ok && childOK
        }
    }
    
    let containsPreservedSubtree = preservingSubtrees.contains { $0.hasPrefix(url.standardizedFileURL.path + "/") }
    if isRoot || keep.contains(url.standardizedFileURL.path) || containsPreservedSubtree || !ok {
        return ok
    }
    
    let size = Int64(values?.totalFileAllocatedSize ?? 0)
    do {
        try fm.removeItem(at: url)
    } catch {
        recordFailure(url, error, home: home, stats: &stats)
        return false
    }
    
    if isRealDirectory {
        stats.removedDirectories += 1
    } else {
        stats.removedFiles += 1
        stats.bytes += size
    }
    
    return true
}

private enum RecoveryWipePartition: Int, CaseIterable {
    case data, cache, internalStorage
    var title: String { switch self { case .data: return "Data"; case .cache: return "Cache"; case .internalStorage: return "Internal Storage" } }
}

func recoveryWipeData(_ c: NXRecoveryViewController) {
    recoveryWipePartitions(c, partitions: [.data])
}

private func recoveryWipePartitions(_ c: NXRecoveryViewController, partitions: Set<RecoveryWipePartition>) {
    dispatchPrecondition(condition: .onQueue(.main))
    guard !romIsBusy(c), !partitions.isEmpty else { return }
    c.enterConsole()
    let home = URL(fileURLWithPath: NSHomeDirectory(), isDirectory: true).standardizedFileURL
    let homePath = home.path
    
    var targets: [URL]
    let dataOnly: Bool
    do {
        if !partitions.contains(.data) {
            targets = []; dataOnly = true
        } else if slotIsFlashed(activeSlotName()) {
            let slot = flashedSlotURL()
            var error: NSError?
            guard NXROMDeviceVerify(slot.path, true, &error) else { throw error ?? romError("Cannot authenticate the ROM reset policy") }
            let manifest = try ROMManifest(manifestPlistURL: slot.appendingPathComponent("manifest.plist"))
            if let path = manifest.dataPartitionPath {
                targets = [try romDataPartitionURL(path, home: home)]
                dataOnly = true
            } else {
                targets = ["Documents", "Library", "tmp"].map { home.appendingPathComponent($0) }
                dataOnly = false
            }
        } else {
            targets = ["Documents", "Library", "tmp"].map { home.appendingPathComponent($0) }
            dataOnly = false
        }
        if partitions.contains(.cache) {
            targets += [home.appendingPathComponent("Library/Caches"), home.appendingPathComponent("tmp")]
        }
        if partitions.contains(.internalStorage) { targets.append(home.appendingPathComponent("Documents")) }
        let unique = Array(Set(targets))
        targets = unique.filter { target in !unique.contains { $0 != target && target.path.hasPrefix($0.path + "/") } }
        if !dataOnly {
            guard let domain = Bundle.main.bundleIdentifier else { throw romError("Missing bundle identifier") }
            try resetPreferencesPreservingSigning(.standard, domain: domain)
        }
    } catch {
        c.recoveryLogError("Reset cancelled: \(error.localizedDescription)")
        c.finishConsole(selectAction: { controller in if let controller { controller.exitConsole(); recoveryShowMenu(recoveryController: controller) } })
        return
    }
    let keep: Set<String> = [home.appendingPathComponent("Library/Caches").path]
    var preservedSubtrees = Set(["Library/Preferences", "Library/Boot/Slot", "Library/Boot/TrustStore", "Documents/Inbox", "Inbox"].map { home.appendingPathComponent($0).path })
    if !partitions.contains(.internalStorage) { preservedSubtrees.insert(home.appendingPathComponent("Documents/TWRP").path) }
    c.recoveryLogMax = max(c.recoveryLogMax, 16)
    let started = CFAbsoluteTimeGetCurrent()
    c.recoveryLog("\n-- Wiping: " + RecoveryWipePartition.allCases.filter { partitions.contains($0) }.map { $0.title }.joined(separator: ", "))
    c.recoveryLog("Signing credentials, ROM system slots, the TrustStore and Inbox are preserved.")
    
    runRomOperation(c, returnToMenu: true) { _ in
        var success = true
        var totalBytes: Int64 = 0
        
        for dir in targets {
            let name = dir.lastPathComponent
            DispatchQueue.main.async { c.recoveryLog("Formatting /\(name)...") }
            
            var stats = WipeStats()
            let ok = removeTree(dir, keeping: keep, isRoot: true, preservingSubtrees: preservedSubtrees, home: homePath, stats: &stats)
            success = success && ok
            totalBytes += stats.bytes
            
            let summary = "  \(stats.removedFiles) files, \(stats.removedDirectories) dirs, \(formatBytes(stats.bytes))"
            let shown = Array(stats.failures.prefix(maxFailuresShown))
            let hidden = stats.failures.count - shown.count
            
            DispatchQueue.main.async {
                c.recoveryLog(summary)
                for f in shown {
                    c.recoveryLogError("  failed: \(f.path): \(f.reason)")
                }
                if hidden > 0 {
                    c.recoveryLogError("  ... and \(hidden) more (see system log)")
                }
            }
        }
        
        let elapsed = String(format: "%.1f", CFAbsoluteTimeGetCurrent() - started)
        let tail = "(\(formatBytes(totalBytes)) in \(elapsed)s)"
        
        DispatchQueue.main.async {
            if success {
                c.recoveryLog("Data wipe complete. \(tail)")
            } else {
                c.recoveryLogError("Data wipe failed. \(tail)")
            }
        }
    }
}

func recoveryWipeCache(_ c: NXRecoveryViewController) {
    dispatchPrecondition(condition: .onQueue(.main))
    guard !romIsBusy(c) else { return }
    c.enterConsole()
    let home = URL(fileURLWithPath: NSHomeDirectory(), isDirectory: true).standardizedFileURL
    let homePath = home.path
    
    let targets = ["Library/Caches", "tmp"].map {
        home.appendingPathComponent($0, isDirectory: true)
    }
    
    let keep: Set<String> = [
        home.appendingPathComponent("Library/Caches").standardizedFileURL.path,
        home.appendingPathComponent("Library/Preferences").standardizedFileURL.path,
    ]
    
    c.recoveryLogMax = max(c.recoveryLogMax, 16)
    
    let started = CFAbsoluteTimeGetCurrent()
    c.recoveryLog("\n-- Wiping cache...")
    
    runRomOperation(c, returnToMenu: true) { _ in
        var success = true
        var totalBytes: Int64 = 0
        
        for dir in targets {
            let name = dir.lastPathComponent
            DispatchQueue.main.async { c.recoveryLog("Formatting /\(name)...") }
            
            var stats = WipeStats()
            let ok = removeTree(dir, keeping: keep, isRoot: true, home: homePath, stats: &stats)
            success = success && ok
            totalBytes += stats.bytes
            
            let summary = "  \(stats.removedFiles) files, \(stats.removedDirectories) dirs, \(formatBytes(stats.bytes))"
            let shown = Array(stats.failures.prefix(maxFailuresShown))
            let hidden = stats.failures.count - shown.count
            
            DispatchQueue.main.async {
                c.recoveryLog(summary)
                for f in shown {
                    c.recoveryLogError("  failed: \(f.path): \(f.reason)")
                }
                if hidden > 0 {
                    c.recoveryLogError("  ... and \(hidden) more (see system log)")
                }
            }
        }
        
        let elapsed = String(format: "%.1f", CFAbsoluteTimeGetCurrent() - started)
        let tail = "(\(formatBytes(totalBytes)) in \(elapsed)s)"
        
        DispatchQueue.main.async {
            if success {
                c.recoveryLog("Cache wipe complete. \(tail)")
            } else {
                c.recoveryLogError("Cache wipe failed. \(tail)")
            }
        }
    }
}

func recoveryConfirmWipe(recoveryController c: NXRecoveryViewController) {
    recoveryShowWipe(c)
}

private func recoveryShowWipe(_ c: NXRecoveryViewController) {
    guard !romIsBusy(c) else { return }
    let declared = slotManifest(activeSlotName())?.dataPartitionPath != nil
    c.enterRecovery(withHeader: "Wipe", instructions: declared ? "Only the ROM data partition is cleared" : "Legacy ROM: container data reset", footer: nil, items: [
        NXRecoveryItem(title: "Advanced Wipe") { controller in if let controller { recoveryShowAdvancedWipe(controller) } },
        NXRecoveryItem(title: "Format Data") { controller in if let controller { recoveryShowFormatData(controller) } },
        NXRecoveryItem(title: "Factory Reset") { controller in if let controller { recoveryWipeData(controller) } }
    ], onSelect: nil, onMove: nil)
}

private func recoveryShowAdvancedWipe(_ c: NXRecoveryViewController) {
    guard !romIsBusy(c) else { return }
    let choices: [NXRecoveryItem] = RecoveryWipePartition.allCases.map { partition in
        let item: NXRecoveryItem = NXRecoveryItem(title: partition.title) { controller in
            guard let controller else { return }
            let item = controller.recoveryItems[partition.rawValue]
            item.checked.toggle()
            let wipe = controller.recoveryItems[3]
            wipe.enabled = controller.recoveryItems.prefix(3).contains { $0.checked }
            controller.recoveryItems = controller.recoveryItems
        }
        item.toggle = true; item.checked = false
        return item
    }
    let wipe: NXRecoveryItem = NXRecoveryItem(title: "Wipe") { controller in
        guard let controller else { return }
        let selected = Set(RecoveryWipePartition.allCases.filter { controller.recoveryItems[$0.rawValue].checked })
        recoveryWipePartitions(controller, partitions: selected)
    }
    wipe.enabled = false
    let repair: NXRecoveryItem = NXRecoveryItem(title: "Repair or Change File System") { _ in }
    repair.enabled = false
    c.enterRecovery(withHeader: "Wipe\nAdvanced Wipe", instructions: "System slots, signing credentials and Inbox are preserved.", footer: nil, items: choices + [wipe, repair], onSelect: nil, onMove: nil)
}

private func recoveryShowFormatData(_ c: NXRecoveryViewController) {
    guard !romIsBusy(c) else { return }
    c.enterRecovery(withHeader: "Wipe\nFormat Data", instructions: "", footer: nil, items: [
        NXRecoveryItem(title: "Cancel") { controller in if let controller { recoveryShowWipe(controller) } },
        NXRecoveryItem(title: "Format Data") { controller in
            if let controller { recoveryWipePartitions(controller, partitions: [.data, .cache, .internalStorage]) }
        },
        NXRecoveryItem(title: "Type yes to continue") { controller in controller?.focusWipeConfirmation() }
    ], onSelect: nil, onMove: nil)
}

@discardableResult private func runUninstaller(_ log: RomLog, slot: URL = flashedSlotURL()) -> Bool {
    let manifestURL = slot.appendingPathComponent("manifest.plist")
    guard FileManager.default.fileExists(atPath: manifestURL.path) else { return true }
    
    do {
        let manifest = try ROMManifest(manifestPlistURL: manifestURL)
        guard let uninstaller = manifest.uninstaller else { return true }
        log.info("running uninstaller of \(manifest.name)")
        try runRomGeneric(uninstaller, symbol: "NXRomUninstall", slot: slot, onLine: log.rom)
        log.info("uninstaller finished")
        return true
    } catch {
        log.error("uninstaller failed: \(error.localizedDescription)")
        return false
    }
}

private func confirmManualRollback(_ c: NXRecoveryViewController, reason: String) -> Bool {
    dispatchPrecondition(condition: .notOnQueue(.main))
    let answer = DispatchSemaphore(value: 0)
    var approved = false
    DispatchQueue.main.async {
        c.exitConsole()
        c.enterRecovery(withHeader: "Allow ROM rollback?\n\(reason)\nThis may install known vulnerabilities and changes rollback protection to this release.", instructions: nil, footer: nil, items: [ NXRecoveryItem(title: "Cancel") { _ in c.enterConsole(); answer.signal() }, NXRecoveryItem(title: "Allow rollback") { _ in approved = true; c.enterConsole(); answer.signal() } ], onSelect: nil, onMove: nil)
    }
    answer.wait()
    return approved
}

private func isRollbackPolicyError(_ error: NSError?) -> Bool {
    error?.domain == "org.emexlabs.rom.rollback" && error?.code == 2
}

private func approveManualSlot(_ slot: URL, controller: NXRecoveryViewController) throws -> Data? {
    var error: NSError?
    guard NXROMDeviceVerifyRelease(slot.path, &error) else { throw error ?? romError("ROM integrity verification failed") }
    if NXROMDeviceCheckRollback(slot.path, true, &error) { return nil }
    guard isRollbackPolicyError(error) else { throw error ?? romError("Could not read rollback protection") }
    let reason = "Slot \(slot.lastPathComponent): \(error!.localizedDescription)"
    error = nil
    guard let digest = NXROMDeviceReleaseProof(slot.path, &error)?["digest"] as? Data else { throw error ?? romError("ROM release identity missing") }
    guard confirmManualRollback(controller, reason: reason) else { throw romError("Rollback cancelled; ROM kept") }
    return digest
}

private func commitManualSlot(_ slot: URL, approved: Data?) throws {
    var error: NSError?
    guard NXROMDeviceVerifyRelease(slot.path, &error) else { throw error ?? romError("ROM integrity verification failed") }
    if let approved {
        guard let digest = NXROMDeviceReleaseProof(slot.path, &error)?["digest"] as? Data, digest == approved else {
            throw error ?? romError("ROM changed after rollback approval; please select it again")
        }
    }
    let ok = approved != nil ? NXROMDeviceManualCommitRollback(slot.path, &error) : NXROMDeviceCommitRollback(slot.path, &error)
    guard ok else { throw error ?? romError("Could not commit ROM rollback protection") }
}

private func slotIsTrusted(_ slot: URL) -> Bool {
    var error: NSError?
    return NXROMDeviceVerifyRelease(slot.path, &error)
}

private func removeFlashedSlot(_ log: RomLog, fallbackApproved: Data?) {
    let name = activeSlotName()
    let other = otherSlotName(name)
    do {
        let fallback = slotIsFlashed(other) && slotIsTrusted(slotURL(other))
        if fallback { try commitManualSlot(slotURL(other), approved: fallbackApproved) }
        try FileManager.default.removeItem(at: slotURL(name))
        if fallback {
            setActiveSlot(other)
            log.info("slot \(name) removed, next boot uses slot \(other)")
        } else {
            if slotIsFlashed(other) {
                try FileManager.default.removeItem(at: slotURL(other))
                log.info("slot \(other) couldn't boot anymore either (no valid signed file list), removed it too")
            }
            log.info("slot \(name) removed, next boot uses SuperSlot.dylib")
        }
    } catch {
        log.error("ERROR: \(errnoDescription(error))")
    }
}

func recoveryShowUnflash(recoveryController c: NXRecoveryViewController) {
    guard !romIsBusy(c) else { return }
    
    let slot = flashedSlotURL()
    guard FileManager.default.fileExists(atPath: slot.path) else {
        c.recoveryLogError("no ROM flashed")
        return
    }
    
    let manifest = try? ROMManifest(manifestPlistURL: slot.appendingPathComponent("manifest.plist"))
    
    let name = activeSlotName()
    let header: String
    if let manifest {
        header = "Unflash \(manifest.name) \(manifest.version) (slot \(name))?\n\(manifest.identifier)"
    } else {
        header = "Unflash ROM (slot \(name))?\nmanifest unreadable, only force removal possible"
    }
    
    var items: [NXRecoveryItem] = []
    
    if let manifest {
        let title = manifest.uninstaller != nil ? "Uninstall ROM" : "Remove ROM (no uninstaller)"
        items.append(NXRecoveryItem(title: title) { c in
            guard let c = c else { return }
            runRomOperation(c, returnToMenu: true) { log in
                log.info("\n-- Unflashing \(manifest.name)...")
                
                do {
                    let runsUninstaller = manifest.uninstaller != nil && slotIsTrusted(slot)
                    let currentApproved = runsUninstaller ? try approveManualSlot(slot, controller: c) : nil
                    let other = slotURL(otherSlotName(name))
                    let fallbackApproved = slotIsFlashed(otherSlotName(name)) && slotIsTrusted(other) ? try approveManualSlot(other, controller: c) : nil
                    if runsUninstaller {
                        try commitManualSlot(slot, approved: currentApproved)
                        guard runUninstaller(log) else {
                            log.error("ROM kept, use force removal to delete it anyway")
                            return
                        }
                    } else if manifest.uninstaller != nil {
                        log.error("this ROM has no valid signed file list, its uninstaller is skipped; leftovers outside the slot may remain")
                    }
                    removeFlashedSlot(log, fallbackApproved: fallbackApproved)
                } catch { log.error(error.localizedDescription) }
            }
        })
    }
    
    items.append(NXRecoveryItem(title: "Force remove (skip uninstaller)") { c in
        guard let c = c else { return }
        runRomOperation(c, returnToMenu: true) { log in
            log.info("\n-- Force removing ROM...")
            log.error("uninstaller skipped, leftovers outside the slot may remain")
            do {
                let other = otherSlotName(name)
                let approved = slotIsFlashed(other) && slotIsTrusted(slotURL(other)) ? try approveManualSlot(slotURL(other), controller: c) : nil
                removeFlashedSlot(log, fallbackApproved: approved)
            } catch { log.error(error.localizedDescription) }
        }
    })
    
    c.enterRecovery(
        withHeader: header,
        instructions: nil,
        footer: nil,
        items: items,
        onSelect: nil,
        onMove: nil
    )
}

private func signROMFiles(_ files: [ROMPath], slot: URL, identity: BootSigningIdentity, log: RomLog?) throws {
    try validateBootSigningSnapshot(identity)
    let fm = FileManager.default
    if !files.isEmpty {
        log?.info("signing files")
        for file in files {
            let path = try slotFile(file.path, in: slot)
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: path.path)
            guard trust_remove_blob(path.path) == KERN_SUCCESS else { throw romError("Could not remove old signing metadata from \(file.path)") }
            guard NXSignMachOWithIdentity(slot.appendingPathComponent(file.path), identity.profile, identity.certificate, identity.password) else {
                throw romError("failed to sign \(file.path)")
            }
            log?.info("signed \(file.path)")
        }
        
        log?.info("refreshing signed files")
        for file in files {
            guard refreshVnode(atPath: slot.appendingPathComponent(file.path).path) else {
                throw romError("failed to refresh \(file.path)")
            }
            log?.info("refreshed \(file.path)")
        }
        
        log?.info("adding NXT2 entitlements if needed")
        for file in files {
            if file.codesigning.neededNXT2 {
                let kr: kern_return_t = NXROMBootNXT2Sign(slot.appendingPathComponent(file.path).path, file.codesigning.nxt2 as CFDictionary, true, nil)
                if kr != 0 {
                    throw romError("failed to add NXT2 entitlements to \(file.path): \(String(cString: mach_error_string(kr)))")
                }
                log?.info("added NXT2 entitlements to \(file.path)")
            }
        }
        
        log?.info("refixing sign files permissions")
        for file in files {
            try fm.setAttributes([.posixPermissions: file.permission], ofItemAtPath: slot.appendingPathComponent(file.path).path)
        }
    }
    try validateBootSigningSnapshot(identity)
}

private func refreshROMSigningIfNeeded(_ slot: URL, identity: BootSigningIdentity) throws {
    var error: NSError?
    guard NXROMDeviceVerifyRelease(slot.path, &error), NXROMDeviceCheckRollback(slot.path, true, &error) else {
        throw error ?? romError("ROM integrity or rollback verification failed")
    }
    let previous = NXROMDeviceSigningContext(slot.path, &error)
    if let error { throw error }
    if previous == identity.context { return }
    guard let proof = NXROMDeviceReleaseProof(slot.path, &error) else { throw error ?? romError("ROM release proof is missing") }
    let manifest = try ROMManifest(manifestPlistURL: slot.appendingPathComponent("manifest.plist"))
    let candidate = slot.deletingLastPathComponent().appendingPathComponent(".signing-\(UUID().uuidString)")
    try FileManager.default.copyItem(at: slot, to: candidate)
    defer { try? FileManager.default.removeItem(at: candidate) }
    bootLog("bootloader: refreshing ROM signatures for the current certificate and provisioning profile")
    try signROMFiles(manifest.paths.filter { $0.codesigning.needed }, slot: candidate, identity: identity, log: nil)
    guard NXROMDeviceSeal(candidate.path, proof, identity.context, &error),
          NXROMDeviceVerifyRelease(candidate.path, &error), NXROMDeviceCheckRollback(candidate.path, true, &error) else {
        throw error ?? romError("Could not authenticate the re-signed ROM")
    }
    guard renameatx_np(AT_FDCWD, candidate.path, AT_FDCWD, slot.path, UInt32(RENAME_SWAP)) == 0 else {
        throw romError("Could not activate the re-signed ROM: \(String(cString: strerror(errno)))")
    }
}

private func uninstallDifferentROMs(for identifier: String, log: RomLog) throws {
    let names = [activeSlotName(), otherSlotName(activeSlotName())]
    var previous: [(String, ROMManifest)] = []
    var untrusted = Set<String>()
    for name in names where slotIsFlashed(name) {
        let slot = slotURL(name)
        var error: NSError?
        guard NXROMDeviceVerify(slot.path, true, &error) else {
            log.info("slot \(name) can't be authenticated (\(error?.localizedDescription ?? "no seal")), removing it")
            try FileManager.default.removeItem(at: slot)
            continue
        }
        if !slotIsTrusted(slot) { untrusted.insert(name) }
        let manifest = try ROMManifest(manifestPlistURL: slot.appendingPathComponent("manifest.plist"))
        if manifest.identifier != identifier { previous.append((name, manifest)) }
    }
    var uninstalled = Set<String>()
    for (name, manifest) in previous.sorted(by: { $0.1.securityVersion > $1.1.securityVersion }) {
        if uninstalled.insert(manifest.identifier).inserted {
            log.info("switching NXRomIdentifier from \(manifest.identifier) to \(identifier); uninstalling previous system first")
            if untrusted.contains(name) {
                log.error("slot \(name) has no valid signed file list, its uninstaller is skipped; leftovers outside the slot may remain")
            } else {
                guard runUninstaller(log, slot: slotURL(name)) else { throw romError("Previous ROM uninstaller failed; replacement cancelled") }
            }
            if let path = manifest.dataPartitionPath {
                let data = try romDataPartitionURL(path)
                if FileManager.default.fileExists(atPath: data.path) { try FileManager.default.removeItem(at: data) }
            }
        }
    }
    for (name, _) in previous {
        if FileManager.default.fileExists(atPath: slotURL(name).path) { try FileManager.default.removeItem(at: slotURL(name)) }
        log.info("removed previous system from slot \(name)")
    }
}

private func requireOTAIdentity(_ identifier: String) throws {
    let current = flashedSlotURL()
    var error: NSError?
    guard NXROMDeviceVerify(current.path, true, &error) else { throw error ?? romError("OTA requires an authenticated installed ROM") }
    let manifest = try ROMManifest(manifestPlistURL: current.appendingPathComponent("manifest.plist"))
    guard manifest.identifier == identifier else {
        throw romError("OTA NXRomIdentifier mismatch: installed \(manifest.identifier), update \(identifier). Use a manual flash to switch systems.")
    }
}

private func flashROM(archive: URL, slotName: String, log: RomLog, approveRollback: ((String) -> Bool)? = nil, isOTA: Bool = false) throws -> ROMManifest {
    guard NXDeviceHasUniqueID() else {
        throw romError("This Nyxian has no UniqueID, so it can't flash or boot ROMs. Install Nyxian with NyxLoader from emexlabs.org.")
    }
    let signing = try currentBootSigningIdentity()
    let fm = FileManager.default
    let destination = slotURL(slotName)
    var slot = destination
    var touchedSlot = false
    var completed = false
    defer { if touchedSlot && !completed { try? fm.removeItem(at: destination) } }
    // Use a private copy, then verify exactly the archive we will extract.
    let verifiedArchive = try stageOTA(archive.path)
    defer { try? fm.removeItem(at: verifiedArchive) }
    var trustError: NSError?
    guard let releaseProof = NXROMArchiveProof(verifiedArchive.path, &trustError) else {
        throw trustError ?? romError("ROM release signature verification failed")
    }

    log.info("\n-- Flashing rom into slot \(slotName)...")
    log.info("selected rom: \(archive.lastPathComponent)")
    
    let candidate = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("rom-\(UUID().uuidString)")
    try fm.createDirectory(at: candidate, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer { try? fm.removeItem(at: candidate) }
    var extractionError: NSError?
    guard unzipArchiveAtPathWithoutParentDirectoryWithError(verifiedArchive.path, candidate.path, &extractionError) else {
        throw extractionError ?? romError("failed to extract ROM")
    }
    guard NXROMVerifyFileList(candidate.path, releaseProof, false, &trustError) else {
        throw trustError ?? romError("The ROM's files don't match its signed file list")
    }
    let manifest = try ROMManifest(manifestPlistURL: candidate.appendingPathComponent("manifest.plist"))
    guard manifest.isHostCompatible else { throw romError("ROM requires \(manifest.hostRequirement)") }
    if isOTA { try requireOTAIdentity(manifest.identifier) }
    guard let releaseDigest = releaseProof["digest"] as? Data else { throw romError("ROM release identity missing") }
    if slotIsFlashed(activeSlotName()) {
        guard NXROMDeviceCommitRollback(flashedSlotURL().path, &trustError) else {
            throw trustError ?? romError("Could not preserve the installed ROM security floor")
        }
    }
    var manualApproval = false
    if !NXROMRollbackCheckForIdentifier(manifest.identifier, manifest.securityVersion, releaseDigest, true, &trustError) {
        guard isRollbackPolicyError(trustError), let approveRollback else { throw trustError ?? romError("ROM downgrade blocked") }
        guard approveRollback("\(manifest.name) \(manifest.version): \(trustError!.localizedDescription)") else { throw romError("Rollback cancelled; installed slots untouched") }
        manualApproval = true
        trustError = nil
    }
    slot = candidate
    log.info("verified ROM security version \(manifest.securityVersion)")
    var sealedProof = releaseProof
    if !NXROMProofIsTrusted(releaseProof) {
        log.error("this ROM isn't signed by a key in the TrustStore; flashing it because TrustStore validation is off for this install")
    }
    if !NXROMProofRequiresTicket(releaseProof) {
        if !NXBootPolicyTSSValidation() {
            log.info("TSS validation is off for this install: no install ticket")
        } else if !NXROMProofIsTrusted(releaseProof) {
            log.info("an unsigned ROM can't get an install ticket: installing without one")
        } else {
            log.info("the release key doesn't use the TSS: no install ticket needed")
        }
    } else {
        #if DEBUG
        do {
            sealedProof["ticket"] = try requestROMTicket(rom: manifest.identifier, digest: releaseDigest, log: log)
        } catch {
            log.info("debug build: installing without an install ticket (\(error.localizedDescription))")
        }
        #else
        sealedProof["ticket"] = try requestROMTicket(rom: manifest.identifier, digest: releaseDigest, log: log)
        #endif // DEBUG
    }
    log.info("setting up default file and directory permissions")
    guard let enumerator = fm.enumerator(at: slot, includingPropertiesForKeys: [.isDirectoryKey, .isSymbolicLinkKey]) else {
        throw NSError(domain: "org.emexlabs.nyxian.bootloader.rom-flash", code: 2, userInfo: [NSLocalizedDescriptionKey: "could not enumerate \(slot)"])
    }
    var dirs: [URL] = [slot]
    for case let url as URL in enumerator {
        let values = try url.resourceValues(forKeys: Set([.isDirectoryKey, .isSymbolicLinkKey]))
        if values.isSymbolicLink == true { continue }
        if values.isDirectory == true {
            dirs.append(url)
        } else {
            try fm.setAttributes([.posixPermissions: manifest.defaultFilePermission], ofItemAtPath: url.path)
        }
    }
    for dir in dirs.reversed() {
        try fm.setAttributes([.posixPermissions: manifest.defaultDirectoryPermission], ofItemAtPath: dir.path)
    }
    
    log.info("setting up explicit path permissions and configurations")
    var signFiles: [ROMPath] = []
    for path in manifest.paths {
        log.info("setting up \(path.path)")
        if path.codesigning.needed {
            signFiles.append(path)
        } else {
            try fm.setAttributes([.posixPermissions: path.permission], ofItemAtPath: slot.appendingPathComponent(path.path).path)
        }
    }
    
    try signROMFiles(signFiles, slot: slot, identity: signing, log: log)
    if !isOTA { try uninstallDifferentROMs(for: manifest.identifier, log: log) }
    try fm.createDirectory(at: destination.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    touchedSlot = true
    if fm.fileExists(atPath: destination.path) { try fm.removeItem(at: destination) }
    try fm.moveItem(at: candidate, to: destination)
    slot = destination
    
    if let installer = manifest.installer {
        log.info("running installer")
        do {
            try runRomGeneric(installer, symbol: "NXRomInstall", slot: slot, verifiedFlash: true, onLine: log.rom)
        } catch {
            throw romError("installer failed: \(error.localizedDescription)")
        }
        log.info("installer finished")
    }
    
    let installedManifest = try ROMManifest(manifestPlistURL: slot.appendingPathComponent("manifest.plist"))
    guard installedManifest.identifier == manifest.identifier,
          installedManifest.securityVersion == manifest.securityVersion,
          installedManifest.dataPartitionPath == manifest.dataPartitionPath else {
        throw romError("Installer changed NXRomIdentifier, NXRomSecurityVersion or NXRomDataPartitionPath; flash refused")
    }
    let entry = try slotFile(manifest.executable, in: slot)
    var entryIsDirectory: ObjCBool = false
    guard fm.fileExists(atPath: entry.path, isDirectory: &entryIsDirectory), !entryIsDirectory.boolValue else {
        throw romError("ROM executable missing after installation")
    }
    guard NXROMDeviceSeal(slot.path, sealedProof, signing.context, &trustError) else {
        throw trustError ?? romError("Could not seal the flashed ROM")
    }
    guard NXROMDeviceCheckTicket(slot.path, &trustError) else {
        throw trustError ?? romError("The flashed ROM's install ticket doesn't verify")
    }
    guard NXROMDeviceVerifyRelease(slot.path, &trustError) else {
        throw trustError ?? romError("The installed ROM doesn't match its signed file list")
    }
    let committed = manualApproval ? NXROMDeviceManualCommitRollback(slot.path, &trustError) : NXROMDeviceCommitRollback(slot.path, &trustError)
    guard committed else { throw trustError ?? romError("Could not commit ROM rollback protection") }
    completed = true
    clearPendingOTAAfterFlash(log)
    log.info("authenticated ROM trust cache and security floor committed")
    return manifest
}

private func recoveryFlashROM(_ c: NXRecoveryViewController, archive: URL) {
    guard !romIsBusy(c) else { return }
    c.enterConsole()
    
    runRomOperation(c) { log in
        let previous = activeSlotName()
        let target = flashTargetSlotName()
        do {
            let manifest = try flashROM(archive: archive, slotName: target, log: log, approveRollback: { confirmManualRollback(c, reason: $0) })
            setActiveSlot(target)
            log.info("flashed \(manifest.name) \(manifest.version) into slot \(target), slot \(target) is active")
            if slotIsFlashed(previous) {
                log.info("the previous ROM stays in slot \(previous)")
            }
            if !manifest.isHostCompatible {
                log.error("this ROM needs \(manifest.hostRequirement), this is Nyxian \(currentNyxianVersion())")
            }
            DispatchQueue.main.async {
                c.recoveryLog("\nFlash complete.\nTap Reboot when ready.")
                c.finishConsole(selectAction: { _ in
                    restartSelf()
                }, title: "Reboot", status: "Complete")
            }
        } catch {
            log.error("ERROR: \(error.localizedDescription)")
            DispatchQueue.main.async {
                c.recoveryLogError(slotIsFlashed(previous)
                    ? "\nFlash failed, slot \(previous) untouched."
                    : "\nFlash failed.")
                c.recoveryLogError("Tap Continue to return to the menu.")
                c.finishConsole(selectAction: { c in
                    guard let c = c else { return }
                    c.exitConsole()
                    recoveryShowMenu(recoveryController: c)
                })
            }
        }
    }
}

// MARK: - OTA

private let otaPathKey = "org.emexlabs.nyxian.bootloader.ota-path"

private func clearPendingOTAAfterFlash(_ log: RomLog, defaults: UserDefaults = .standard, documents: URL = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]) {
    defaults.removeObject(forKey: otaPathKey)
    var cleanupSucceeded = true
    if !CFPreferencesAppSynchronize(kCFPreferencesCurrentApplication) {
        cleanupSucceeded = false
        log.error("ROM flashed, but the pending OTA cancellation could not be saved")
    }
    let fm = FileManager.default
    let snapshots = documents.appendingPathComponent(".verified-rom-ota", isDirectory: true)
    let rootfs = documents.appendingPathComponent("rootfs", isDirectory: true)
    let staging = rootfs.appendingPathComponent("var/root/stage/rom", isDirectory: true)
    for directory in [snapshots, staging] {
        guard fm.fileExists(atPath: directory.path) else { continue }
        if directory == staging {
            let root = rootfs.resolvingSymlinksInPath().standardizedFileURL.path
            let target = directory.resolvingSymlinksInPath().standardizedFileURL.path
            guard target.hasPrefix(root + "/") else {
                cleanupSucceeded = false
                log.error("Pending OTA cancelled; refusing to remove a staging directory outside vroot")
                continue
            }
        }
        do { try fm.removeItem(at: directory) }
        catch {
            cleanupSucceeded = false
            log.error("Pending OTA cancelled, but could not remove \(directory.lastPathComponent): \(error.localizedDescription)")
        }
    }
    if cleanupSucceeded { log.info("cleared pending OTA request and staged update files") }
}

private func takePendingOTA() -> String? {
    let defaults = UserDefaults.standard
    guard let path = defaults.string(forKey: otaPathKey) else { return nil }
    defaults.removeObject(forKey: otaPathKey)
    CFPreferencesAppSynchronize(kCFPreferencesCurrentApplication)
    return path
}

private func stageOTA(_ path: String) throws -> URL {
    let fm = FileManager.default
    var isDir: ObjCBool = false
    guard fm.fileExists(atPath: path, isDirectory: &isDir), !isDir.boolValue else {
        throw romError("OTA archive missing: \(path)")
    }
    let staged = URL(fileURLWithPath: NSTemporaryDirectory())
        .appendingPathComponent("ota-\(UUID().uuidString).zip")
    try fm.copyItem(at: URL(fileURLWithPath: path), to: staged)
    return staged
}

private func otaFailed(_ c: NXRecoveryViewController, slotIntact: Bool) {
    c.recoveryLogError(slotIntact
        ? "\nOTA failed, current ROM untouched."
        : "\nOTA failed, no ROM flashed, next boot uses SuperSlot.dylib.")
    c.recoveryLogError("Tap Continue to return to the menu.")
    c.finishConsole(selectAction: { c in
        guard let c = c else { return }
        c.exitConsole()
        recoveryShowMenu(recoveryController: c)
    })
}

private func initialROMSlotsAreEmpty() -> Bool {
    !slotIsFlashed("A") && !slotIsFlashed("B")
}

private func shouldDownloadInitialROM(mode: Int) -> Bool {
    mode == 0 && NXDeviceHasUniqueID() && initialROMSlotsAreEmpty()
}

private func initialROMRollbackApproval(_ c: NXRecoveryViewController, initialInstall: Bool) -> ((String) -> Bool)? {
    guard initialInstall, initialROMSlotsAreEmpty() else { return nil }
    return { reason in
        confirmManualRollback(c, reason: "No ROM is installed, but a previously approved ROM is still recorded.\n\(reason)")
    }
}

private func applyOTA(_ c: NXRecoveryViewController, path: String, initialInstall: Bool = false) {
    c.clearOperationProgress()
    c.enterConsole()
    
    runRomOperation(c) { log in
        guard !initialInstall || initialROMSlotsAreEmpty() else {
            log.info("Initial installation skipped: a ROM is already installed.")
            DispatchQueue.main.async {
                c.finishConsole(selectAction: { controller in
                    guard let controller else { return }
                    controller.exitConsole();recoveryShowMenu(recoveryController: controller)
                })
            }
            return
        }
        log.info("\n-- Applying OTA update...")
        log.info("source: \(path)")
        
        let staged: URL
        do {
            staged = try stageOTA(path)
        } catch {
            log.error("ERROR: \(error.localizedDescription)")
            DispatchQueue.main.async { otaFailed(c, slotIntact: true) }
            return
        }
        defer { try? FileManager.default.removeItem(at: staged) }
        
        let previous = activeSlotName()
        let target = flashTargetSlotName()
        do {
            let manifest = try flashROM(archive: staged, slotName: target, log: log,
                                        approveRollback: initialROMRollbackApproval(c, initialInstall: initialInstall), isOTA: !initialInstall)
            setActiveSlot(target)
            log.info("flashed \(manifest.name) \(manifest.version) into slot \(target), slot \(target) is active")
            if slotIsFlashed(previous) {
                log.info("the previous ROM stays in slot \(previous)")
            }
            DispatchQueue.main.async {
                c.recoveryLog("\nUpdate complete. Rebooting...")
                DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                    restartSelf()
                }
            }
        } catch {
            log.error("ERROR: \(error.localizedDescription)")
            DispatchQueue.main.async { otaFailed(c, slotIntact: slotIsFlashed(previous)) }
        }
    }
}

let romImporter: ROMImporter = ROMImporter()

private func slotSwitchItems() -> [NXRecoveryItem] {
    return ["A", "B"].map { slot in
        let item: NXRecoveryItem = NXRecoveryItem(title: "Slot \(slot)") { c in
            guard let c, !romIsBusy(c) else { return }
            runRomOperation(c) { log in
                do {
                    if slotIsFlashed(slot) {
                        let approved = try approveManualSlot(slotURL(slot), controller: c)
                        try commitManualSlot(slotURL(slot), approved: approved)
                    } else {
                        log.info("Slot \(slot) is empty. No ROM was modified.")
                    }
                    setActiveSlot(slot)
                    log.info("Change Boot Slot Complete: slot \(slot) is active.")
                } catch { log.error(error.localizedDescription) }
                DispatchQueue.main.async {
                    c.finishConsole(selectAction: { controller in
                        guard let controller else { return }
                        controller.exitConsole()
                        // Drop any completed rollback prompt before returning to Reboot.
                        recoveryShowMenu(recoveryController: controller)
                        recoveryShowReboot(recoveryController: controller)
                    })
                }
            }
        }
        return item
    }
}

private func recoveryShowReboot(recoveryController c: NXRecoveryViewController) {
    let items: [NXRecoveryItem] = [
        NXRecoveryItem(title: "System") { _ in restartSelf() },
        NXRecoveryItem(title: "Power Off") { _ in
            UIApplication.shared.perform(Selector("suspend"))
            exit(0)
        }
    ] + slotSwitchItems()
    c.enterRecovery(withHeader: "Reboot", instructions: "Current Slot: \(activeSlotName())", footer: nil, items: items, onSelect: nil, onMove: nil)
}

func recoveryShowMenu(recoveryController: NXRecoveryViewController) {
    let header = "Nyxian Recovery"
    func page(_ title: String, items: [NXRecoveryItem]) -> NXRecoveryItem {
        NXRecoveryItem(title: title) { c in
            guard let c, !romIsBusy(c) else { return }
            c.enterRecovery(withHeader: title, instructions: nil, footer: nil,
                            items: items, onSelect: nil, onMove: nil)
        }
    }
    func unavailable(_ title: String) -> NXRecoveryItem {
        let item: NXRecoveryItem = NXRecoveryItem(title: title) { _ in }
        item.enabled = false
        return item
    }
    let install: NXRecoveryItem = NXRecoveryItem(title: "Install") { c in
        guard let c, !romIsBusy(c) else { return }
        c.enterFileBrowser(atPath: NSHomeDirectory(), root: NSHomeDirectory(), header: "Install Zip",
                          onBack: { c in
            if let c { recoveryShowMenu(recoveryController: c) }
        }, onFile: { path, name, c in
            guard let c, let path, let name else { return }
            guard URL(fileURLWithPath: path).pathExtension.lowercased() == "zip" else {
                c.recoveryLogError("Select a signed ROM ZIP archive.")
                return
            }
            c.enterRecovery(withHeader: "Install Zip\n\(name)", instructions: nil, footer: nil, items: [
                NXRecoveryItem(title: "Cancel") { c in
                    if let c { recoveryShowMenu(recoveryController: c) }
                },
                NXRecoveryItem(title: "Install") { c in
                    if let c { recoveryFlashROM(c, archive: URL(fileURLWithPath: path)) }
                }
            ], onSelect: nil, onMove: nil)
        })
    }
    let wipe: NXRecoveryItem = NXRecoveryItem(title: "Wipe") { controller in if let controller { recoveryShowWipe(controller) } }
    let advanced: [NXRecoveryItem] = [
        NXRecoveryItem(title: "Flash ROM") { c in
            guard let c, !romIsBusy(c) else { return }
            romImporter.present(from: c) { url in
                if let url { recoveryFlashROM(c, archive: url) }
            }
        },
        NXRecoveryItem(title: "Unflash ROM") { c in
            if let c { recoveryShowUnflash(recoveryController: c) }
        },
        NXRecoveryItem(title: "Nyxian Files") { c in
            c?.enterFileManager(atPath: NSHomeDirectory(), root: NSHomeDirectory(), onBack: { c in
                if let c { recoveryShowMenu(recoveryController: c) }
            })
        },
        NXRecoveryItem(title: "Terminal") { c in
            guard let c, !romIsBusy(c) else { return }
            NXRecoveryTerminal.shared.present(inRecovery: c)
        },
        NXRecoveryItem(title: "System Files") { c in
            c?.enterFileManager(atPath: "/", root: "/", onBack: { c in
                if let c { recoveryShowMenu(recoveryController: c) }
            })
        },
        NXRecoveryItem(title: "Reload Theme") { c in
            c?.reloadRecoveryTheme()
        },
        NXRecoveryItem(title: "Update TrustStore") { c in
            guard let c else { return }
            runRomOperation(c, returnToMenu: true) { log in
                log.info("\n-- TrustStore: \(trustStoreSummary())")
                log.info("checking \(NXTrustStoreUpdateURL().absoluteString)")
                updateTrustStore(timeout: 30) { line, isError in isError ? log.error(line) : log.info(line) }
                log.info("trusted: \(trustStoreSummary())")
            }
        },
    ]
    let settings: NXRecoveryItem = NXRecoveryItem(title: "Settings") { c in
        if let c { recoveryShowBootConfig(recoveryController: c) }
    }
    let reboot: NXRecoveryItem = NXRecoveryItem(title: "Reboot") { c in
        guard let c, !romIsBusy(c) else { return }
        recoveryShowReboot(recoveryController: c)
    }
    let items: [NXRecoveryItem] = [install, wipe, unavailable("Backup"), unavailable("Restore"), unavailable("Mount"), settings, page("Advanced", items: advanced), reboot]
    recoveryController.enterRecovery(withHeader: header, instructions: nil, footer: nil, items: items, onSelect: nil, onMove: nil)
}

class BootViewController: UIViewController {
    private let splashView = UIView()
    private let logoView = UIImageView()
    private var splashImageSize: CGSize = .zero
    private var signingGateStarted = false
    private var bootRecoveryController: NXRecoveryViewController?
    private var signingSetup: BootSigningImportController?
    
    private enum BootTransition {
        case zoomThrough
        case crossfade
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        parkLegacyLogFD()
        
        BootConfig.registerDefaults()
        BootArguments.migrateIfNeeded()
        BootArguments.publish()
        
        self.view.backgroundColor = .systemBackground
        
        splashView.backgroundColor = UIColor(white: 34.0 / 255.0, alpha: 1)
        splashView.frame = self.view.bounds
        splashView.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        self.view.addSubview(splashView)
        
        logoView.contentMode = .scaleAspectFit
        logoView.translatesAutoresizingMaskIntoConstraints = false
        
        splashView.addSubview(logoView)
        
        NSLayoutConstraint.activate([
            logoView.topAnchor.constraint(equalTo: splashView.topAnchor),
            logoView.bottomAnchor.constraint(equalTo: splashView.bottomAnchor),
            logoView.leadingAnchor.constraint(equalTo: splashView.leadingAnchor),
            logoView.trailingAnchor.constraint(equalTo: splashView.trailingAnchor),
        ])
        
    }
    
    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        guard !signingGateStarted else { return }
        signingGateStarted = true
        requireBootSigning(showSetup: { [weak self] importer in
            guard let self else { return }
            self.signingSetup = importer
            let recovery = self.makeRecoveryController(importer.recoveryController)
            self.transition(to: recovery, style: .crossfade)
        }) { [weak self] in
            self?.signingSetup = nil
            self?.beginBoot()
        }
    }
    
    private func beginBoot() {
        let verbose = BootArguments.verbose
        DispatchQueue.global(qos: .utility).async {
            var uniqueIDError: NSError?
            if !NXDeviceMirrorUniqueID(&uniqueIDError) {
                bootLog("bootloader: " + (uniqueIDError?.localizedDescription ?? "no UniqueID"))
            } else if verbose {
                bootLog("bootloader: UniqueID from the \(NXDeviceUniqueIDSource())")
            }
            if verbose { bootLog("bootloader: scanning volume buttons") }
            let mode = NXVolumeButtonMonitor.scan(for: 1.0)
            NXVolumeButtonMonitor.disarm()
            
            if mode == 2 {
                if verbose { bootLog("bootloader: recovery requested") }
                DispatchQueue.main.async {
                    self.enterRecovery(error: nil)
                }
                return
            }
            
            if !NXBootPolicyTrustStoreValidation() {
                bootLog("bootloader: TrustStore validation is off for this install: ROMs don't need a TrustStore key, unsigned ones flash too")
            }
            if !NXBootPolicyTSSValidation() {
                bootLog("bootloader: TSS validation is off for this install: ROMs flash and boot without an install ticket")
            }
            let haveStore = FileManager.default.fileExists(atPath: NXTrustStoreDownloadedPath())
            if verbose {
                bootLog("bootloader: checking for a newer TrustStore")
            }
            updateTrustStore(timeout: haveStore ? 4 : 8) { line, _ in bootLog("bootloader: " + line) }
            
            if mode == 0, let otaPath = takePendingOTA() {
                if verbose { bootLog("bootloader: OTA pending: \(otaPath)") }
                DispatchQueue.main.async { self.enterOTA(path: otaPath) }
                return
            }
            if shouldDownloadInitialROM(mode: mode) {
                DispatchQueue.main.async { self.beginInitialROMDownload(verbose: verbose) }
                return
            }
            
            let forceSuperSlot = mode == 1
            if !forceSuperSlot,
               NXDeviceHasUniqueID(),
               let manifest = slotManifest(activeSlotName()),
               !manifest.isHostCompatible {
                if verbose { bootLog("bootloader: slot \(activeSlotName()) needs \(manifest.hostRequirement)") }
                DispatchQueue.main.async {
                    self.presentUnsupportedROM(manifest, verbose: verbose)
                }
                return
            }
            
            self.bootSlot(forceSuperSlot: forceSuperSlot, verbose: verbose)
        }
    }
    
    private func continueNormalBoot(forceSuperSlot: Bool, verbose: Bool) {
        if !forceSuperSlot,
           NXDeviceHasUniqueID(),
           let manifest = slotManifest(activeSlotName()),
           !manifest.isHostCompatible {
            if verbose { bootLog("bootloader: slot \(activeSlotName()) needs \(manifest.hostRequirement)") }
            DispatchQueue.main.async {
                self.presentUnsupportedROM(manifest, verbose: verbose)
            }
            return
        }
        self.bootSlot(forceSuperSlot: forceSuperSlot, verbose: verbose)
    }
    
    private func bootSlot(forceSuperSlot: Bool, verbose: Bool) {
        if verbose { bootLog(forceSuperSlot ? "bootloader: forcing SuperSlot.dylib" : "bootloader: loading slot \(activeSlotName())") }
        let slot = loadSlot(loadSuperslotForcefully: forceSuperSlot)
        
        DispatchQueue.main.async {
            guard case let .loaded(name, slotMain, slotDidAppear, slotCreateWindow) = slot else {
                if case let .failed(message) = slot {
                    self.enterRecoveryAfterBootFailure("ERROR: \(message)")
                }
                return
            }
            
            let raw = slotMain()
            
            guard let raw else {
                self.enterRecoveryAfterBootFailure("ERROR: \(name) NXSlotMain returned no view controller")
                return
            }
            let slotRoot = Unmanaged<UIViewController>.fromOpaque(raw).takeRetainedValue()
            
            self.changableStatusBarHidden = false
            UIView.animate(withDuration: 0.3) {
                self.setNeedsStatusBarAppearanceUpdate()
            }
            
            if let slotCreateWindow, let slotWindow = self.makeSlotWindow(slotCreateWindow) {
                self.handOver(to: slotWindow, root: slotRoot)
            } else {
                self.handOver(to: slotRoot)
            }
            slotDidAppear?()
        }
    }
    
    private func presentUnsupportedROM(_ manifest: ROMManifest, verbose: Bool) {
        let active = activeSlotName()
        let other = otherSlotName(active)
        
        let alert = UIAlertController(title: "Update Nyxian", message: "\(manifest.name) \(manifest.version) in slot \(active) needs \(manifest.hostRequirement). This is Nyxian \(currentNyxianVersion()). Update Nyxian to boot this ROM.", preferredStyle: .alert)
        
        if let previous = slotManifest(other), previous.isHostCompatible {
            alert.addAction(UIAlertAction(title: "Revert to Slot \(other)", style: .default) { _ in
                setActiveSlot(other)
                DispatchQueue.global(qos: .utility).async {
                    self.bootSlot(forceSuperSlot: false, verbose: verbose)
                }
            })
        }
        alert.addAction(UIAlertAction(title: "Recovery", style: .cancel) { _ in
            self.enterRecovery(error: "slot \(active): \(manifest.name) \(manifest.version) needs \(manifest.hostRequirement), this is Nyxian \(currentNyxianVersion())")
        })
        
        self.present(alert, animated: true)
    }
    
    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        if splashView.superview != nil {
            let size = splashView.bounds.size
            if size.width > 0, size.height > 0, size != splashImageSize {
                logoView.image = NXTWRPBootSplashImage(size)
                splashImageSize = size
            }
        }
    }
    
    // MARK: - Transitions
    
    private func makeSlotWindow(_ create: NXSlotCreateWindowFn) -> UIWindow? {
        guard let scene = view.window?.windowScene else { return nil }
        guard let raw = create(Unmanaged.passUnretained(scene).toOpaque()) else { return nil }
        return Unmanaged<UIWindow>.fromOpaque(raw).takeRetainedValue()
    }
    
    private func handOver(to slotWindow: UIWindow, root: UIViewController) {
        let hostWindow = view.window
        slotWindow.rootViewController = root
        slotWindow.makeKeyAndVisible()
        hostWindow?.isHidden = true
        hostWindow?.rootViewController = nil
        if let scene = slotWindow.windowScene {
            (scene.delegate as? SceneDelegate)?.window = slotWindow
        }
    }
    
    private func handOver(to child: UIViewController) {
        let previousChildren = children
        addChild(child)
        child.view.frame = view.bounds
        child.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(child.view)
        splashView.removeFromSuperview()
        child.didMove(toParent: self)
        for previous in previousChildren {
            previous.willMove(toParent: nil)
            previous.view.removeFromSuperview()
            previous.removeFromParent()
        }
        bootRecoveryController = nil
    }
    
    private func makeRecoveryController(_ initial: NXRecoveryViewController? = nil) -> NXRecoveryViewController {
        if let window = view.window {
            window.windowLevel = UIWindow.Level(rawValue: UIWindow.Level.alert.rawValue + 100)
            window.makeKeyAndVisible()
        }
        if let bootRecoveryController { return bootRecoveryController }
        
        let recoveryController = initial ?? NXRecoveryViewController()
        bootRecoveryController = recoveryController
        
        return recoveryController
    }
    
    private var initialDownloadActive = false
    
    private func beginInitialROMDownload(verbose: Bool) {
        guard !initialDownloadActive else { return }
        guard shouldDownloadInitialROM(mode: 0) else {
            DispatchQueue.global(qos: .utility).async { self.continueNormalBoot(forceSuperSlot: false, verbose: verbose) }
            return
        }
        initialDownloadActive = true
        let recovery = makeRecoveryController()
        recoveryShowMenu(recoveryController: recovery)
        recovery.enterConsole()
        recovery.setOperationProgress(0, status: "Checking for updates…")
        self.transition(to: recovery, style: .crossfade)
        var previousStatus = ""
        fetchAndStageInitialROM(progress: { fraction, status in
            guard self.initialDownloadActive else { return }
            recovery.setOperationProgress(fraction, status: status)
            if status != previousStatus { recovery.recoveryLog(status); previousStatus = status }
        }) { stagedURL in
            guard self.initialDownloadActive else { return }
            self.initialDownloadActive = false
            guard initialROMSlotsAreEmpty() else {
                if let stagedURL { try? FileManager.default.removeItem(at: stagedURL) }
                recovery.clearOperationProgress()
                recovery.recoveryLog("Initial download skipped: a ROM is already installed.")
                recovery.finishConsole(selectAction: { controller in
                    guard let controller else { return }
                    controller.exitConsole();recoveryShowMenu(recoveryController: controller)
                })
                return
            }
            if let stagedURL {
                applyOTA(recovery, path: stagedURL.path, initialInstall: true)
            } else {
                recovery.clearOperationProgress()
                recovery.recoveryLogError("No compatible ROM could be downloaded. You can install a ROM manually from recovery or retry on the next normal boot.")
                recovery.finishConsole(selectAction: { controller in
                    guard let controller else { return }
                    controller.exitConsole();recoveryShowMenu(recoveryController: controller)
                })
            }
        }
    }
    
    private func enterRecoveryAfterBootFailure(_ message: String) {
        guard bootLockdownAttempted || NXBootLockdownActive() else {
            enterRecovery(error: message)
            return
        }
        let recoveryController = makeRecoveryController()
        recoveryController.recoveryLogError(message)
        recoveryController.recoveryLogError("The bootloader locked its write side for this boot, the recovery cannot run in it.")
        recoveryController.recoveryLog("Reboot boots again. Hold Volume Down while booting for the recovery.")
        recoveryShowMenu(recoveryController: recoveryController)
        recoveryController.enterConsole()
        recoveryController.finishConsole(selectAction: { _ in restartSelf() }, title: "Reboot", status: "Boot failed")
        self.transition(to: recoveryController, style: .crossfade)
    }
    
    private func enterRecovery(error: String?) {
        let recoveryController = makeRecoveryController()
        
        if let error {
            recoveryController.recoveryLogError(error)
        }
        recoveryShowMenu(recoveryController: recoveryController)
        if error != nil {
            recoveryController.enterConsole()
            recoveryController.finishConsole(selectAction: { controller in
                guard let controller else { return }
                controller.exitConsole()
                recoveryShowMenu(recoveryController: controller)
            })
        }
        self.transition(to: recoveryController, style: .crossfade)
    }
    
    private func enterOTA(path: String, initialInstall: Bool = false) {
        let recoveryController = makeRecoveryController()
        recoveryShowMenu(recoveryController: recoveryController)
        self.transition(to: recoveryController, style: .crossfade)
        applyOTA(recoveryController, path: path, initialInstall: initialInstall)
    }
    
    private func transition(to child: UIViewController,
                            style: BootTransition = .zoomThrough,
                            completion: (() -> Void)? = nil) {
        if child.parent === self { completion?(); return }
        let previousChildren = children
        addChild(child)
        child.view.frame = view.bounds
        child.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        if splashView.superview === view {
            view.insertSubview(child.view, belowSubview: splashView)
        } else {
            view.addSubview(child.view)
        }
        child.view.layoutIfNeeded()
        
        if let presentation = logoView.layer.presentation() {
            logoView.layer.transform = presentation.transform
        }
        logoView.layer.removeAnimation(forKey: "breathe")
        
        let finish = {
            self.splashView.removeFromSuperview()
            child.didMove(toParent: self)
            for previous in previousChildren {
                previous.willMove(toParent: nil)
                previous.view.removeFromSuperview()
                previous.removeFromParent()
            }
            if child !== self.bootRecoveryController { self.bootRecoveryController = nil }
            completion?()
        }
        
        if child is NXRecoveryViewController {
            finish()
            return
        }
        if style == .crossfade || UIAccessibility.isReduceMotionEnabled {
            UIView.animate(withDuration: 0.3, animations: {
                self.splashView.alpha = 0
            }, completion: { _ in
                finish()
            })
            return
        }
        
        child.view.transform = CGAffineTransform(scaleX: 0.97, y: 0.97)
        
        let splashOut = UIViewPropertyAnimator(duration: 0.4, curve: .easeOut) {
            self.logoView.transform = CGAffineTransform(scaleX: 1.15, y: 1.15)
            self.splashView.alpha = 0
        }
        
        let appIn = UIViewPropertyAnimator(duration: 0.55, dampingRatio: 1.0) {
            child.view.transform = .identity
        }
        
        appIn.addCompletion { _ in
            finish()
        }
        
        splashOut.startAnimation()
        appIn.startAnimation()
    }
    
    var changableStatusBarHidden = true
    override var prefersStatusBarHidden: Bool {
        return self.changableStatusBarHidden
    }
    
    override var preferredStatusBarUpdateAnimation: UIStatusBarAnimation {
        return .fade
    }
    
    override var childForStatusBarStyle: UIViewController? {
        splashView.superview == nil ? children.last : nil
    }
}

@main
class AppDelegate: UIResponder, UIApplicationDelegate {
    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey : Any]? = nil) -> Bool {
        return true
    }
}

class SceneDelegate: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?
    
    func scene(_ scene: UIScene, willConnectTo session: UISceneSession, options connectionOptions: UIScene.ConnectionOptions) {
        guard let windowScene = scene as? UIWindowScene else { return }
        
        let window = UIWindow(windowScene: windowScene)
        window.rootViewController = BootViewController()
        window.makeKeyAndVisible()
        self.window = window
    }
}
