/*
 SPDX-License-Identifier: AGPL-3.0-or-later

 Copyright (C) 2025 - 2026 emexlab

 This file is part of Nyxian.

 Nyxian is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 Nyxian is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with Nyxian. If not, see <https://www.gnu.org/licenses/>.
*/

import UIKit
import UniformTypeIdentifiers

extension UTType {
    static var ipa: UTType {
        UTType(filenameExtension: "ipa") ?? .zip
    }
    static var tipa: UTType {
        UTType(importedAs: "com.cr4zy.nyxian.tipa", conformingTo: .zip)
    }
    static var nipa: UTType {
        UTType(importedAs: "com.cr4zy.nyxian.nipa", conformingTo: .data)
    }
}

extension UIColor {
    static let customGold: UIColor = UIColor { trait in
        trait.userInterfaceStyle == .dark
            ? UIColor(red: 0.90, green: 0.65, blue: 0.10, alpha: 1.0)
            : UIColor(red: 0.75, green: 0.50, blue: 0.05, alpha: 1.0)
    }
}

typealias EntitlementItem = (entitlement: PEEntitlement?, description: String, color: UIColor)

extension PEEntitlement {
    var displayAttributedString: NSAttributedString {
        // Resolve tfp capability based on what else is granted
        let taskForPidEntry: EntitlementItem? = {
            if self.contains(.processElevate) || (self.contains(.platformRoot) && self.contains(.platform)) {
                if self.contains(.processEnumeration) {
                    return (.taskForPid, "obtain task ports of any process running inside Nyxian without restriction", .systemRed)
                }
            } else if self.contains(.processEnumeration) {
                return (.taskForPid, "obtain task ports of processes running as the same user that explicitly allow it via Get Task Allowed or run within the same session", .customGold)
            }
            return (nil, "obtain task ports of processes that run within the same session", .systemGray)
        }()
        
        let platformItems: [EntitlementItem] = {
            let hasRoot     = self.contains(.platformRoot)
            let hasPlatform = self.contains(.platform)

            if hasRoot && hasPlatform {
                return [(.platformRoot, "platformized as root user", .systemRed)]
            } else if hasPlatform {
                return [(.platform, "platformized", .systemOrange)]
            } else {
                return [(nil, "as a normal userspace process", .systemGray)]
            }
        }()
        
        var runtimeItems: [EntitlementItem] = platformItems
        if self.contains(.dyldHideLiveProcess) {
            runtimeItems.append((.dyldHideLiveProcess, "with the NSExtension spawn helper hidden from DYLD", .secondaryLabel))
        }
        
        var taskAndProcessItems: [EntitlementItem] = [
            (.getTaskAllowed, "allow other processes to obtain its task port", .systemGray),
            (.processEnumeration, "enumerate all running processes inside Nyxian", .customGold),
        ]
        if let taskForPid = taskForPidEntry {
            taskAndProcessItems.insert(taskForPid, at: 1)
        }
        
        let sections: [(title: String, prefix: String, items: [EntitlementItem])] = [
            (
                title: "Task & Process Access",
                prefix: "Can",
                items: taskAndProcessItems
            ),
            (
                title: "Process Control",
                prefix: "Can",
                items: [
                    (.processKill, "kill processes", .customGold),
                    (.processSpawn, "spawn arbitrary unsigned binaries", .systemOrange),
                    (.processSpawnSignedOnly, "spawn signed binaries only", .customGold),
                    (.processElevate, "elevate it's own credentials (to the root user for instance)", .systemRed),
                    (.processSpawnInheriteEntitlements, "pass its entitlements to spawned children", .systemOrange),
                ]
            ),
            (
                title: "Launch Services",
                prefix: "Can",
                items: [
                    (.launchServicesStart, "start services", .customGold),
                    (.launchServicesStop, "stop services", .systemOrange),
                    (.launchServicesToggle, "toggle services on or off", .systemOrange),
                    (.launchServicesGetEndpoint, "read service endpoints", .customGold),
                    (.launchServicesSetEndpoint, "set endpoints of not pre-registered services", .customGold),
                ]
            ),
            (
                title: "Host & Credentials",
                prefix: "Can",
                items: [
                    (.hostManager, "override host properties such as hostname", .systemOrange),
                    (.credentialsManager, "manage system users and groups", .systemRed),
                ]
            ),
            (
                title: "Security & Runtime",
                prefix: "Runs",
                items: runtimeItems
            ),
        ]
        
        let result = NSMutableAttributedString()
        
        for section in sections {
            var matched = section.items.filter {
                guard let entitlement = $0.entitlement else { return true }
                return self.contains(entitlement)
            }
            guard !matched.isEmpty else { continue }
            
            if matched.contains(where: { $0.0 == .processSpawn }) {
                matched.removeAll { $0.0 == .processSpawnSignedOnly }
            }
            
            result.append(NSAttributedString(
                string: "\n\(section.title)\n",
                attributes: [
                    .font: UIFont.systemFont(ofSize: 13, weight: .bold),
                    .foregroundColor: UIColor.label
                ]
            ))
            
            let dominantColor: UIColor = {
                if matched.contains(where: { $0.2 == .systemRed })    { return .systemRed }
                if matched.contains(where: { $0.2 == .systemOrange }) { return .systemOrange }
                if matched.contains(where: { $0.2 == .customGold }) { return .customGold }
                return .secondaryLabel // For non true capabilities
            }()
            
            let parts = matched.map { $0.1 }
            let joined: String
            if parts.count == 1 {
                joined = parts[0]
            } else {
                joined = parts.dropLast().joined(separator: ", ") + " and \(parts.last!)"
            }
            
            result.append(NSAttributedString(
                string: "\(section.prefix) \(joined).\n",
                attributes: [
                    .font: UIFont.systemFont(ofSize: 11, weight: .medium),
                    .foregroundColor: dominantColor
                ]
            ))
        }
        
        return result
    }
}

class ApplicationManagementViewController: UIThemedTableViewController, UITextFieldDelegate, UIDocumentPickerDelegate, UIAdaptivePresentationControllerDelegate {
    @objc static var shared: ApplicationManagementViewController = ApplicationManagementViewController(style: .insetGrouped)
    var applications: [LDEApplicationObject] = []
    
    override init(style: UITableView.Style) {
        super.init(style: style)
    }
    
    @MainActor required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        self.tableView.register(ProjectTableCell.self, forCellReuseIdentifier: ProjectTableCell.reuseIdentifier)
        LDEApplicationWorkspace.shared().ping()
        self.title = "Apps"
        self.navigationItem.rightBarButtonItem = UIBarButtonItem(title: nil, image: UIImage(systemName: "square.and.arrow.down.fill"), target: self, action: #selector(plusButtonPressed))
    }
    
    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
    }
    
    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        return self.applications.count
    }
    
    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let application: LDEApplicationObject = self.applications[indexPath.row]
        let cell: ProjectTableCell = self.tableView.dequeueReusableCell(withIdentifier: ProjectTableCell.reuseIdentifier) as! ProjectTableCell
        cell.configure(displayName: application.localizedName, bundleIdentifier: application.bundleIdentifier, appIcon: application.icon ?? UIImage(named: "DefaultIcon"), showArrow: false)
        return cell
    }
    
    override func tableView(_ tableView: UITableView, contextMenuConfigurationForRowAt indexPath: IndexPath, point: CGPoint) -> UIContextMenuConfiguration? {
        let application = self.applications[indexPath.row]
        
        return UIContextMenuConfiguration(identifier: nil, previewProvider: nil) { [weak application] _ in
            // MARK: Open Menu
            let openMenu: UIMenuElement = UIAction(title: "Open", image: UIImage(systemName: "arrow.up.right.square.fill")) { _ in
                guard let application = application else { return }
                PEProcessManager.shared().spawnProcess(withBundleIdentifier: application.bundleIdentifier, withItems: [:], withKernelSurfaceProcess: nil, doRestartIfRunning: false)
            }
            
            var menu: [UIMenuElement] = [openMenu]
            
            let entitlementsPatchAction = UIAction(title: "Patch Entitlements", image: UIImage(systemName: "bandage.fill")) { _ in
                guard let application = application else { return }
                let machOViewController: MachOPatcherViewController = MachOPatcherViewController(machOPath: application.executablePath) {
                    if PEProcessManager.shared().process(forBundleIdentifier: application.bundleIdentifier) != nil {
                        PEProcessManager.shared().spawnProcess(withBundleIdentifier: application.bundleIdentifier, withItems: [:], withKernelSurfaceProcess: nil, doRestartIfRunning: true)
                    }
                }
                let navMachOViewController: UINavigationController = UINavigationController(rootViewController: machOViewController)
                navMachOViewController.modalPresentationStyle = .formSheet
                self.present(navMachOViewController, animated: true)
            }
            
            let clearContainerAction = UIAction(title: "Clear Data Container", image: UIImage(systemName: "arrow.up.trash.fill")) { _ in
                guard let application = application else { return }
                PEProcessManager.shared().closeIfRunning(usingBundleIdentifier: application.bundleIdentifier)
                LDEApplicationWorkspace.shared().clearContainer(forBundleID: application.bundleIdentifier)
            }
            
            let deleteAction = UIAction(title: "Delete", image: UIImage(systemName: "trash.fill"), attributes: .destructive) { [weak self] _ in
                guard let self = self,
                      let application = application else { return }
                PEProcessManager.shared().closeIfRunning(usingBundleIdentifier: application.bundleIdentifier)
                if(LDEApplicationWorkspace.shared().deleteApplication(withBundleID: application.bundleIdentifier)) {
                    if let index = self.applications.firstIndex(where: { $0.bundleIdentifier == application.bundleIdentifier }) {
                        self.applications.remove(at: index)
                        self.tableView.deleteRows(at: [IndexPath(row: index, section: 0)], with: .automatic)
                    }
                }
            }
            
            menu.append(contentsOf: [entitlementsPatchAction, clearContainerAction, deleteAction])
            
            return UIMenu(title: "", children: menu)
        }
    }
    
    override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        tableView.deselectRow(at: indexPath, animated: true)
        let application = self.applications[indexPath.row]
        PEProcessManager.shared().spawnProcess(withBundleIdentifier: application.bundleIdentifier, withItems: [:], withKernelSurfaceProcess: nil, doRestartIfRunning: false)
    }
    
    @objc func plusButtonPressed() {
        let documentPicker: UIDocumentPickerViewController = UIDocumentPickerViewController(forOpeningContentTypes: [.ipa,.tipa,.nipa], asCopy: true)
        documentPicker.delegate = self
        documentPicker.modalPresentationStyle = .formSheet
        self.present(documentPicker, animated: true)
    }
    
    func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
        let alert = UIAlertController(title: nil, message: "Validating", preferredStyle: .alert)
        
        let activityIndicator = UIActivityIndicatorView(style: .medium)
        activityIndicator.translatesAutoresizingMaskIntoConstraints = false
        activityIndicator.startAnimating()
        
        alert.view.addSubview(activityIndicator)
        
        NSLayoutConstraint.activate([
            activityIndicator.centerYAnchor.constraint(equalTo: alert.view.centerYAnchor),
            activityIndicator.trailingAnchor.constraint(equalTo: alert.view.trailingAnchor, constant: -20)
        ])
        
        self.present(alert, animated: true)
        
        DispatchQueue.global().async {
            do {
                guard let selectedURL = urls.first else { return }
                
                let fileManager = FileManager.default
                let tempRoot = NSTemporaryDirectory()
                let workRoot = (tempRoot as NSString).appendingPathComponent(UUID().uuidString)
                let unzipRoot = (workRoot as NSString).appendingPathComponent("unzipped")
                let payloadDir = (unzipRoot as NSString).appendingPathComponent("Payload")
                
                guard ((try? fileManager.createDirectory(atPath: unzipRoot, withIntermediateDirectories: true)) != nil) else { return }
                guard unzipArchiveAtPath(selectedURL.path, unzipRoot) else { return }
                let contents: [String] = try FileManager.default.contentsOfDirectory(atPath: payloadDir)
                
                guard let appBundlePathComponent = contents.first(where: { ($0 as NSString).pathExtension == "app" }) else {
                    NotificationServer.NotifyUser(level: .error, notification: "Failed to install application: no .app bundle found")
                    return
                }
                
                let appBundleFullPath = payloadDir.appending("/\(appBundlePathComponent)")
                
                guard let bundle = Bundle(path: appBundleFullPath) else {
                    NotificationServer.NotifyUser(level: .error, notification: "Failed to install application: invalid bundle path")
                    return
                }
                
                guard let executablePath = bundle.executablePath else {
                    NotificationServer.NotifyUser(level: .error, notification: "Failed to install application: invalid executable path")
                    return
                }
                
                var wasSignedLocally: Bool = false
                var ent: PEEntitlement = entitlement_get_path((executablePath as NSString).utf8String, &wasSignedLocally)
                
                // We have to make sure the app is only signed with entitlements known at that time, otherwise a app could contain way more entitlements currently reserved and used by nothing
                ent = PEEntitlement(rawValue: ent.rawValue & PEEntitlement.all.rawValue)
                
                // Gated :3
                let proceedWithInstall = {
                    DispatchQueue.main.async {
                        let alert = UIAlertController(title: nil, message: "Installing", preferredStyle: .alert)
                        
                        let activityIndicator = UIActivityIndicatorView(style: .medium)
                        activityIndicator.translatesAutoresizingMaskIntoConstraints = false
                        activityIndicator.startAnimating()
                        
                        alert.view.addSubview(activityIndicator)
                        
                        NSLayoutConstraint.activate([
                            activityIndicator.centerYAnchor.constraint(equalTo: alert.view.centerYAnchor),
                            activityIndicator.trailingAnchor.constraint(equalTo: alert.view.trailingAnchor, constant: -20)
                        ])
                        
                        self.present(alert, animated: true)
                        
                        if LCUtils.certificateData == nil {
                            alert.dismiss(animated: true) {
                                NotificationServer.NotifyUser(level: .error, notification: "No certificate present, please import the certificate used to sign Nyxian in Settings > Certificate.")
                            }
                            return
                        }
                        
                        DispatchQueue.global().async {
                            LCUtils.signAppBundle(withZSign: bundle.bundleURL) { result, error in
                                if result {
                                    if !wasSignedLocally {
                                        entitlement_set_path((executablePath as NSString).utf8String, ent)
                                    }
                                    
                                    if LDEApplicationWorkspace.shared().installApplication(atBundlePath: bundle.bundleURL.path) {
                                        DispatchQueue.main.async {
                                            alert.dismiss(animated: true) {
                                                PEProcessManager.shared().spawnProcess(
                                                    withBundleIdentifier: bundle.bundleIdentifier,
                                                    withItems: [:],
                                                    withKernelSurfaceProcess: nil,
                                                    doRestartIfRunning: true
                                                )
                                            }
                                        }
                                    } else {
                                        DispatchQueue.main.async {
                                            alert.dismiss(animated: true) {
                                                NotificationServer.NotifyUser(level: .error, notification: "Failed to sign or install application.")
                                            }
                                        }
                                    }
                                } else {
                                    DispatchQueue.main.async {
                                        alert.dismiss(animated: true) {
                                            NotificationServer.NotifyUser(level: .error, notification: "Failed to sign or install application.")
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                
                // The app indeed wants something bruh
                DispatchQueue.main.async {
                    alert.dismiss(animated: true) {
                        let displayName = bundle.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String ?? bundle.object(forInfoDictionaryKey: "CFBundleName") as? String ?? "Unknown"
                        let alert = UIAlertController(
                            title: "Install \"\(displayName)\"?",
                            message: nil,
                            preferredStyle: .alert
                        )
                        
                        // Build the full attributed message
                        let fullMessage = NSMutableAttributedString()
                        
                        fullMessage.append(ent.displayAttributedString)
                        
                        alert.setValue(fullMessage, forKey: "attributedMessage")
                        
                        alert.addAction(UIAlertAction(title: "Install", style: .default) { _ in
                            DispatchQueue.global().async {
                                _ = proceedWithInstall()
                            }
                        })
                        
                        alert.addAction(UIAlertAction(title: "Cancel", style: .cancel))
                        
                        self.present(alert, animated: true)
                    }
                }
                
            } catch {
                NotificationServer.NotifyUser(level: .error, notification: "Failed to install application: \(error.localizedDescription)")
            }
        }
    }
    
    @objc func applicationWasInstalled(_ app: LDEApplicationObject!) {
        DispatchQueue.main.async {
            if let index = self.applications.firstIndex(of: app) {
                self.applications[index] = app
                self.tableView.reloadRows(
                    at: [IndexPath(row: index, section: 0)],
                    with: .automatic
                )
            } else {
                self.applications.append(app)
                let index = self.applications.count - 1
                self.tableView.insertRows(
                    at: [IndexPath(row: index, section: 0)],
                    with: .automatic
                )
            }
        }
    }
    
    @objc func application(withBundleIdentifierWasUninstalled bundleIdentifier: String!) {
        DispatchQueue.main.async {
            let temp = LDEApplicationObject()
            temp.bundleIdentifier = bundleIdentifier
            if let index = self.applications.firstIndex(of: temp) {
                self.applications.remove(at: index)
                self.tableView.deleteRows(
                    at: [IndexPath(row: index, section: 0)],
                    with: .automatic
                )
            }
        }
    }
    
    override func tableView(_ tableView: UITableView, heightForRowAt indexPath: IndexPath) -> CGFloat {
        if #available(iOS 26.0, *) {
            return 80
        } else {
            return 70
        }
    }
}
