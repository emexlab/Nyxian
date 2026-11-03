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

import Foundation

func getTopViewController(base: UIViewController? = UIApplication.shared.connectedScenes
    .compactMap { $0 as? UIWindowScene }
    .flatMap { $0.windows }
    .first(where: { $0.isKeyWindow })?.rootViewController) -> UIViewController? {
    
    if let nav = base as? UINavigationController {
        return getTopViewController(base: nav.visibleViewController)
    }
    
    if let tab = base as? UITabBarController {
        return getTopViewController(base: tab.selectedViewController)
    }
    
    if let presented = base?.presentedViewController {
        return getTopViewController(base: presented)
    }
    
    return base
}

fileprivate func errorFallback(title: String, message: String) {
    let alert = UIAlertController(
        title: title,
        message: message,
        preferredStyle: .alert
    )
    
    alert.addAction(UIAlertAction(title: "Close", style: .default))

    DispatchQueue.main.async {
        NXWindowServer.shared().rootViewController?.present(
            alert,
            animated: true
        )
    }
}

func checkSigningSetup(completionHandler: @escaping (Bool) -> Void = { _ in }, showAlert: Bool = true) {
    if !NXApplicationState.extensionExists {
        if showAlert {
            errorFallback(title: "Extension Not Found", message: """
The required NSExtension could not be found.

Make sure the app was installed with its extension intact and that it wasn't removed during signing or installation.

App is now in extension-less mode, meaning apps cannot run within Nyxian until the problem has been resolved.
""")
        }
        completionHandler(false)
        return
    }
    
    if !NXApplicationState.extensionCorrectlyEntitled {
        if showAlert {
            errorFallback(title: "Unsupported Provisioning Profile", message: """
Extension doesn't have the "get-task-allow" entitlement.

Distribution certificates are not supported. You must use a Developer certificate issued by Apple.

The 7 day certificate is a Developer certificate.

App is now in extension-less mode, meaning apps cannot run within Nyxian until the problem has been resolved.
""")
        }
        completionHandler(false)
        return
    }
    
    LCUtils.validateCertificate { status, someWords in
        completionHandler(status == 0)
        if status == 0 || !showAlert {
            return
        }
        
        DispatchQueue.main.async {
            let alert = UIAlertController(
                title: {
                    switch status {
                    default:
                        return "Signing Isn't Set Up"
                    }
                }(),
                message: {
                    switch status {
                    default:
                        return "Nyxian needs a signing certificate to install and launch the apps you build. Without one you can still write and compile code, but you won't be able to run it on this device."
                    }
                }(), preferredStyle: .alert)
            
            alert.message = "Restart Nyxian to import a valid certificate matching its provisioning profile in the bootloader."
            alert.addAction(UIAlertAction(title: "Close", style: .cancel))
            alert.addAction(UIAlertAction(title: "Restart Nyxian", style: .default) { _ in
                if let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "PERestartSelf") {
                    unsafeBitCast(symbol, to: (@convention(c) () -> Void).self)()
                } else { exit(0) }
            })
            getTopViewController()?.present(alert, animated: true)
        }
    }
}
