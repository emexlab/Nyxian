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
import UniformTypeIdentifiers

struct BootSigningIdentity {
    let certificate: Data
    let password: String
    let profile: Data
    let context: Data
}

func currentBootSigningIdentity() throws -> BootSigningIdentity {
    guard let certificate = NXBootSigningCertificateData(),
          let profile = NXBootSigningProfileData() else {
        throw NSError(domain: "org.emexlabs.nyxian.boot-signing", code: 1, userInfo: [NSLocalizedDescriptionKey: "Import the certificate matching Nyxian's embedded provisioning profile before continuing."])
    }
    
    let password = NXBootSigningCertificatePassword() ?? ""
    var error: NSError?
    guard let context = NXBootValidateSigningIdentity(certificate, password, profile, Bundle.main.bundleIdentifier ?? "", Date(), &error) else {
        throw error ?? NSError(domain: "org.emexlabs.nyxian.boot-signing", code: 1, userInfo: [NSLocalizedDescriptionKey: "Signing certificate validation failed."])
    }
    
    return BootSigningIdentity(certificate: certificate, password: password, profile: profile, context: context)
}

func validateBootSigningSnapshot(_ identity: BootSigningIdentity) throws {
    var error: NSError?
    guard let context = NXBootValidateSigningIdentity(identity.certificate, identity.password, identity.profile, Bundle.main.bundleIdentifier ?? "", Date(), &error), context == identity.context else {
        throw error ?? NSError(domain: "org.emexlabs.nyxian.boot-signing", code: 1, userInfo: [NSLocalizedDescriptionKey: "The signing identity is no longer valid."])
    }
}

func requireBootSigning(showSetup: @escaping (BootSigningImportController) -> Void, completion: @escaping () -> Void) {
    DispatchQueue.global(qos: .userInitiated).async {
        importNyxLoaderCertificate()
        do {
            _ = try currentBootSigningIdentity()
            DispatchQueue.main.async {
                completion()
            }
        } catch {
            DispatchQueue.main.async {
                let importer = BootSigningImportController(completion: completion)
                showSetup(importer)
            }
        }
    }
}

final class BootSigningImportController: NSObject, UIDocumentPickerDelegate {
    let recoveryController = NXRecoveryViewController()
    private let imported: () -> Void
    private var selected: Data?
    private var selectedName = "Choose Certificate"
    private var password = ""
    private var message = ""
    private var working = false
    private var canvas: NXRecoverySurface {
        recoveryController.view as! NXRecoverySurface
    }
    
    init(completion: @escaping () -> Void) {
        self.imported = completion
        super.init()
        canvas.onPasswordChanged = { [weak self] value in
            self?.password = value
        }
        updateControls()
    }
    
    private func showMessage(_ text: String, isError: Bool = false) {
        message = text
        updateControls()
        if isError {
            UIAccessibility.post(notification: .announcement, argument: text)
        }
    }
    
    private func updateControls() {
        let choose: NXRecoveryItem = NXRecoveryItem(title: selectedName) { [weak self] _ in self?.pick() }
        let input: NXRecoveryItem = NXRecoveryItem(title: "Certificate password") { [weak self] _ in
            guard let self, !self.working else { return }
            self.canvas.focusCertificatePassword()
        }
        let submit: NXRecoveryItem = NXRecoveryItem(title: working ? "Validating certificate…" : "Validate and Continue") { [weak self] _ in self?.save() }
        choose.enabled = !working
        input.enabled = !working
        submit.enabled = !working && selected != nil
        recoveryController.enterRecovery(withHeader: "Signing Certificate", instructions: message, footer: nil, items: [choose, input, submit], onSelect: nil, onMove: nil)
        canvas.showCertificatePassword(password)
    }
    
    private func pick() {
        guard !working else {
            return
        }
        recoveryController.view.endEditing(true)
        let picker = UIDocumentPickerViewController(forOpeningContentTypes: [.data], asCopy: true)
        picker.delegate = self
        picker.allowsMultipleSelection = false
        recoveryController.present(picker, animated: true)
    }
    
    func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
        guard let url = urls.first else {
            return
        }
        let access = url.startAccessingSecurityScopedResource()
        defer { if access { url.stopAccessingSecurityScopedResource() } }
        do {
            let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
            guard size > 0 && size <= 16 * 1024 * 1024 else {
                throw NSError(domain: "org.emexlabs.nyxian.boot-signing", code: 1, userInfo: [NSLocalizedDescriptionKey: "Choose a PKCS#12 certificate smaller than 16 MB."])
            }
            let data = try Data(contentsOf: url)
            guard !data.isEmpty, data.count <= 16 * 1024 * 1024 else {
                throw NSError(domain: "org.emexlabs.nyxian.boot-signing", code: 1, userInfo: [NSLocalizedDescriptionKey: "Choose a PKCS#12 certificate smaller than 16 MB."])
            }
            selected = data
            selectedName = url.lastPathComponent
            password = ""
            message = ""
        } catch {
            selected = nil
            selectedName = "Choose Certificate"
            password = ""
            message = error.localizedDescription
            UIAccessibility.post(notification: .announcement, argument: message)
        }
        updateControls()
    }
    
    @objc private func save() {
        guard !working else {
            return
        }
        guard let data = selected else {
            showMessage("Choose a certificate first.", isError: true)
            return
        }
        
        recoveryController.view.endEditing(true)
        working = true
        updateControls()
        let pass = password
        showMessage("Validating certificate…")
        DispatchQueue.global(qos: .userInitiated).async {
            var failure: Error?
            do {
                var validationError: NSError?
                guard let profile = NXBootSigningProfileData(),
                      NXBootValidateSigningIdentity(data, pass, profile, Bundle.main.bundleIdentifier ?? "", Date(), &validationError) != nil else {
                    throw validationError ?? NSError(domain: "org.emexlabs.nyxian.boot-signing", code: 1, userInfo: [NSLocalizedDescriptionKey: "Could not read embedded.mobileprovision from Nyxian.app. Check the installed ap bundle and file permissions, then try again."])
                }
                let defaults = UserDefaults.standard
                let oldData = defaults.object(forKey: "LCCertificateData")
                let oldPassword = defaults.object(forKey: "LCCertificatePassword")
                NXBootSigningSetCredential(data, pass)
                if !CFPreferencesAppSynchronize(kCFPreferencesCurrentApplication) {
                    if let oldData {
                        defaults.set(oldData, forKey: "LCCertificateData")
                    } else {
                        defaults.removeObject(forKey: "LCCertificateData")
                    }
                    if let oldPassword {
                        defaults.set(oldPassword, forKey: "LCCertificatePassword")
                    } else {
                        defaults.removeObject(forKey: "LCCertificatePassword")
                    }
                    CFPreferencesAppSynchronize(kCFPreferencesCurrentApplication)
                    throw NSError(domain: "org.emexlabs.nyxian.boot-signing", code: 1, userInfo: [NSLocalizedDescriptionKey: "Could not save the signing certificate. Please try again."])
                }
            } catch {
                failure = error
            }
            
            DispatchQueue.main.async {
                self.working = false
                self.updateControls()
                if let failure {
                    self.showMessage(failure.localizedDescription, isError: true);
                    return
                }
                self.password = ""
                self.selected = nil
                self.canvas.onPasswordChanged = nil
                self.recoveryController.enterRecovery(withHeader: "Preparing boot", instructions: "Certificate saved.", footer: nil, items: [], onSelect: nil, onMove: nil)
                self.imported()
            }
        }
    }
}
