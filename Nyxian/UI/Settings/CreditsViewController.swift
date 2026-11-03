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
import UIKit

class CreditsViewController: NXUITableViewController {
    
    struct CreditSection {
        let title: String
        let credits: [Credit]
    }
    
    private let sections: [CreditSection] = [
        CreditSection(
            title: "Team",
            credits: [
                Credit(
                    name: "emexLabs",
                    role: "Maintainer",
                    ghuser: "emexlab"
                ),
                Credit(
                    name: "Nyxia",
                    role: "Maintainer",
                    ghuser: "mach-port-t"
                ),
                Credit(
                    name: "RoothideDev",
                    role: "Developer",
                    ghuser: "roothider"
                ),
                Credit(
                    name: "LucaVmu",
                    role: "Developer",
                    ghuser: "lucavmu"
                ),
            ]
        ),
        
        CreditSection(
            title: "Security Researchers",
            credits: [
                Credit(
                    name: "semvis123",
                    role: "Security Researcher",
                    ghuser: "semvis123"
                ),
                Credit(
                    name: "zipgod",
                    role: "Security Researcher",
                    ghuser: "zipgod24"
                )
            ]
        ),
        
        CreditSection(
            title: "Contributors",
            credits: [
                Credit(
                    name: "Kyle",
                    role: "Swift Support",
                    ghuser: "Kyle-Ye"
                ),
                Credit(
                    name: "Ruri",
                    role: "Clearing application caches",
                    ghuser: "ruri1208"
                ),
                Credit(
                    name: "Vinogradov Daniil",
                    role: "LLVM-On-iOS",
                    ghuser: "XITRIX"
                ),
                Credit(
                    name: "엄세환",
                    role: "Contributor",
                    ghuser: "op06072"
                ),
                Credit(
                    name: "L0tsen",
                    role: "Contributor",
                    ghuser: "l0tsen"
                ),
                Credit(
                    name: "Offihito",
                    role: "Contributor",
                    ghuser: "Offihito"
                )
            ]
        ),
        
        CreditSection(
            title: "Design & Icons",
            credits: [
                Credit(
                    name: "ayame09",
                    role: "Original Nyxian app icons",
                    ghuser: "ayayame09"
                ),
                Credit(
                    name: "sxdev",
                    role: "Drawn app icons",
                    ghuser: "SamoXcZ"
                ),
                Credit(
                    name: "xzadik",
                    role: "Nyxcat app icons",
                    ghuser: "xzadik"
                )
            ]
        ),
        
        CreditSection(
            title: "Open Source Projects",
            credits: [
                Credit(
                    name: "LiveContainer",
                    role: "LiveContainer",
                    ghuser: "livecontainer"
                ),
                Credit(
                    name: "LLVM",
                    role: "llvm-project",
                    ghuser: "llvm"
                ),
                Credit(
                    name: "The Swift Programming Language",
                    role: "swift",
                    ghuser: "swiftlang"
                ),
                Credit(
                    name: "Android Open Source Project",
                    role: "Android Recovery Styling",
                    ghuser: "aosp-mirror"
                )
            ]
        ),
        
        CreditSection(
            title: "Externals",
            credits: [
                Credit(
                    name: "Simon Støvring",
                    role: "Runestone",
                    ghuser: "simonbs"
                ),
                Credit(
                    name: "light-tech",
                    role: "LLVM-On-iOS",
                    ghuser: "light-tech"
                ),
                Credit(
                    name: "Lars Fröder",
                    role: "Litehook",
                    ghuser: "opa334"
                ),
                Credit(
                    name: "lascic",
                    role: "UIOnboarding",
                    ghuser: "lascic"
                ),
                Credit(
                    name: "Miguel de Icaza",
                    role: "SwiftTerm",
                    ghuser: "migueldeicaza"
                )
            ]
        )
    ]
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        self.title = "Credits"
        
        self.tableView.register(CreditCell.self, forCellReuseIdentifier: CreditCell.identifier)
    }
    
    override func numberOfSections(in tableView: UITableView) -> Int {
        sections.count
    }
    
    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        sections[section].credits.count
    }
    
    override func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
        sections[section].title
    }
    
    override func tableView(_ tableView: UITableView, heightForRowAt indexPath: IndexPath) -> CGFloat {
        if #available(iOS 26.0, *) {
            return 90
        } else {
            return 80
        }
    }
    
    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        guard let cell = tableView.dequeueReusableCell(withIdentifier: CreditCell.identifier, for: indexPath) as? CreditCell else {
            return UITableViewCell()
        }
        
        let credit = sections[indexPath.section].credits[indexPath.row]
        
        cell.nameLabel.text = credit.name
        cell.roleLabel.text = credit.role
        
        downloadImage(from: "https://avatars.githubusercontent.com/\(credit.ghuser)") { image in
            cell.configureImage(image ?? UIImage(systemName: "person.fill"))
            cell.layoutSubviews()
        }
        
        return cell
    }
    
    func downloadImage(from urlString: String, completion: @escaping (UIImage?) -> Void) {
        guard let url = URL(string: urlString) else {
            completion(nil)
            return
        }
        
        URLSession.shared.dataTask(with: url) { data, _, error in
            if let data = data, let image = UIImage(data: data) {
                DispatchQueue.main.async { completion(image) }
            } else {
                DispatchQueue.main.async { completion(nil) }
            }
        }.resume()
    }
    
    override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        let credit = sections[indexPath.section].credits[indexPath.row]
        
        if let url = URL(string: "https://github.com/\(credit.ghuser)") {
            UIApplication.shared.open(url)
        }
        
        tableView.deselectRow(at: indexPath, animated: true)
    }
}
