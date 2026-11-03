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
import CoreFoundation

func romDataPartitionURL(_ raw: String, home: URL = URL(fileURLWithPath: NSHomeDirectory())) throws -> URL {
    func invalid(_ message: String) -> NSError {
        NSError(domain: "org.emexlabs.nyxian.rom-storage", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
    
    let prefix = "$(BOOTROOT)/"
    guard raw.hasPrefix(prefix) else { throw invalid("NXRomDataPartitionPath must start with $(BOOTROOT)/") }
    let suffix = String(raw.dropFirst(prefix.count))
    let components = suffix.split(separator: "/", omittingEmptySubsequences: false)
    guard !components.isEmpty, components.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." && !$0.contains("$") && !$0.contains("\0") }) else {
        throw invalid("NXRomDataPartitionPath contains invalid path components")
    }
    let root = home.standardizedFileURL.resolvingSymlinksInPath()
    let target = root.appendingPathComponent(suffix).standardizedFileURL
    guard target.path.hasPrefix(root.path + "/"), target.resolvingSymlinksInPath().path == target.path else {
        throw invalid("NXRomDataPartitionPath must remain in Nyxian's container without symlinks")
    }
    
    var cursor = root
    for component in components {
        cursor.appendPathComponent(String(component))
        do {
            let attributes = try FileManager.default.attributesOfItem(atPath: cursor.path)
            guard (attributes[.type] as? FileAttributeType) == .typeDirectory else {
                throw invalid("NXRomDataPartitionPath contains a symlink or non-directory component")
            }
        } catch let error as NSError {
            if error.domain == NSCocoaErrorDomain && [NSFileReadNoSuchFileError, NSFileNoSuchFileError].contains(error.code) { break }
            throw error
        }
    }
    for name in ["Library/Boot/Slot", "Library/Preferences", "Documents/Inbox", "Documents/TWRP", "Inbox", "tmp"] {
        let protected = root.appendingPathComponent(name).path
        if target.path == protected || target.path.hasPrefix(protected + "/") || protected.hasPrefix(target.path + "/") {
            throw invalid("NXRomDataPartitionPath overlaps protected bootloader, signing preferences or Inbox storage")
        }
    }
    return target
}

func resetPreferencesPreservingSigning(_ defaults: UserDefaults, domain: String) throws {
    let previous = defaults.persistentDomain(forName: domain) ?? [:]
    let preserved = previous.filter { ["LCCertificateData", "LCCertificatePassword"].contains($0.key) }
    defaults.setPersistentDomain(preserved, forName: domain)
    guard defaults.synchronize(), NSDictionary(dictionary: defaults.persistentDomain(forName: domain) ?? [:]).isEqual(to: preserved) else {
        defaults.setPersistentDomain(previous, forName: domain)
        _ = defaults.synchronize()
        throw NSError(domain: "org.emexlabs.nyxian.rom-storage", code: 2, userInfo: [NSLocalizedDescriptionKey: "Could not durably preserve signing credentials; reset cancelled."])
    }
}
