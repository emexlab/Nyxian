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
import CoreCompiler

class ToolChainController: UIThemedTableViewController {
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        tableView.register(ToggleTableCell.self, forCellReuseIdentifier: ToggleTableCell.reuseIdentifier)
        
        self.title = "Toolchain"
        
        self.tableView.translatesAutoresizingMaskIntoConstraints = false
        self.tableView.rowHeight = UITableView.automaticDimension
    }
    
    override func numberOfSections(in tableView: UITableView) -> Int {
        return 3
    }
    
    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        return (section == 2) ? 3 : 1
    }
    
    override func tableView(_ tableView: UITableView, titleForFooterInSection section: Int) -> String? {
        switch section {
        case 0:
            return "An incremental build compiles only the parts of the code that have changed, reducing build times by avoiding a full rebuild of the entire project."
        case 1:
            return "Threading in compilation refers to the compiler's ability to perform tasks in parallel like parsing, code generation, and optimization across multiple CPU threads to speed up the build process."
        case 2:
            return "This clears caches that were created for performance."
        default:
            return nil
        }
    }
    
    override func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
        switch section {
        case 0:
            return "Features"
        case 2:
            return "Actions"
        default:
            return nil
        }
    }
    
    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell: UITableViewCell
        
        switch indexPath.section {
        case 0:
            cell = tableView.dequeueReusableCell(withIdentifier: ToggleTableCell.reuseIdentifier, for: indexPath) as! ToggleTableCell
            (cell as! ToggleTableCell).configure(title: "Incremental Build", key: "LDEIncrementalBuild", defaultValue: true)
            break
        case 1:
            let optimCpuCount: Int = (Int)(CCGetMaximumPerformanceCores())
            cell = StepperTableCell(title: "Use Threads", key: "cputhreads", defaultValue: optimCpuCount, minValue: 1, maxValue: optimCpuCount)
            break
        default:
            switch(indexPath.row) {
            case 0:
                cell = UITableViewCell()
                cell.textLabel?.text = "Clear Module Cache"
                break
            case 1:
                cell = UITableViewCell()
                cell.textLabel?.text = "Clear Project Cache"
                break
             case 2:
                cell = UITableViewCell()
                cell.textLabel?.text = "Clear App Cache"
            default:
                cell = UITableViewCell()
                cell.textLabel?.text = "Unexpected Row"
            }
            break
        }
        
        return cell
    }
    
    override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        if(indexPath.section == 2) {
            // TODO: use the indication popup for cache clearing
            switch(indexPath.row) {
            case 0:
                NXBootstrap.shared().clear(NXBootstrap.shared().swiftModuleCacheURL)
                break
            case 1:
                NXBootstrap.shared().clear(NXBootstrap.shared().cacheURL)
                break
            case 2:
                clearGuestAppCaches()
                break
            default:
                break
            }
            try? FileManager.default.removeItem(at: NXBootstrap.shared().swiftModuleCacheURL)
        }
        tableView.deselectRow(at: indexPath, animated: true)
    }
    private func clearGuestAppCaches() {
        let fm = FileManager.default
        let emexCache = fm.urls(
            for: .cachesDirectory,
            in: .userDomainMask
        ).first
        if let emexCache {
            try? fm.removeItem(at: emexCache)
            try? fm.createDirectory(
                at: emexCache,
                withIntermediateDirectories: true
            )
        }
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
        if fm.fileExists(atPath: tmp.path) {
            try? fm.removeItem(at: tmp)
            try? fm.createDirectory(
                at: tmp,
                withIntermediateDirectories: true
            )
        }
        let documents = FileManager.default.urls(
            for: .documentDirectory,
            in: .userDomainMask
        ).first!
        let dataApplication = documents
            .appendingPathComponent("Data/Application")
        guard fm.fileExists(atPath: dataApplication.path)
        else {
            return
        }
        if let containers = try? fm.contentsOfDirectory(
            at: dataApplication,
            includingPropertiesForKeys: nil
        ) {
            for container in containers {
                let cache = container
                    .appendingPathComponent("Library/Caches")
                let tmp = container
                    .appendingPathComponent("Tmp")
                try? fm.removeItem(at: cache)
                try? fm.createDirectory(
                    at: cache,
                    withIntermediateDirectories: true
                )
                try? fm.removeItem(at: tmp)
                try? fm.createDirectory(
                    at: tmp,
                    withIntermediateDirectories: true
                )
            }
        }
    }
}
