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
import UIOnboarding

struct UIOnboardingHelper {
    static func setUpIcon() -> UIImage {
        return Bundle.main.appIcon ?? .init(named: "IconPreviewDefaultOld")!
    }
    
    static func setUpFirstTitleLine() -> NSMutableAttributedString {
        .init(string: "Welcome to", attributes: [.foregroundColor: UIColor.label])
    }
    
    static func setUpSecondTitleLine() -> NSMutableAttributedString {
        .init(string: Bundle.main.displayName ?? "emexDE", attributes: [
            .foregroundColor: UIColor { trait in
                trait.userInterfaceStyle == .dark
                ? UIColor(red: 0.85, green: 0.74, blue: 0.93, alpha: 1.0)
                : UIColor(red: 0.62, green: 0.48, blue: 0.78, alpha: 1.0)
            }
        ])
    }
    
    static func setUpFeatures() -> Array<UIOnboardingFeature> {
        return .init([
            // I was lazy so I just wrapped them in like that
            .init(icon: UIImage(systemName: "hammer.fill")!,
                  iconTint: UIColor { trait in trait.userInterfaceStyle == .dark
                      ? UIColor(red: 0.55, green: 0.78, blue: 0.98, alpha: 1.0)
                      : UIColor(red: 0.30, green: 0.58, blue: 0.88, alpha: 1.0)
                  },
                  title: "Development",
                  description: "A full fledged Xcode alternative supporting Swift, C, C++, Objective-C and Objective-C++ that runs on any iOS 18.0+ iPhone or iPad."),
            
                .init(icon: UIImage(systemName: "swift")!,
                      iconTint: UIColor { trait in
                          trait.userInterfaceStyle == .dark
                          ? UIColor(red: 0.99, green: 0.70, blue: 0.55, alpha: 1.0)
                          : UIColor(red: 0.92, green: 0.50, blue: 0.30, alpha: 1.0)
                      },
                      title: "Swift",
                      description: "Write, compile, and run Swift code on-device with a full integrated Swift frontend."),
            
                .init(icon: UIImage(systemName: "wrench.and.screwdriver.fill")!,
                      iconTint: UIColor { trait in
                          trait.userInterfaceStyle == .dark
                          ? UIColor(red: 0.78, green: 0.71, blue: 0.95, alpha: 1.0)
                          : UIColor(red: 0.55, green: 0.45, blue: 0.85, alpha: 1.0)
                      },
                      title: "MobileDevelopmentKit",
                      description: "A complete LLVM, Swift, Clang, and LLD toolchain running natively on iOS, powering compilation and linking completely on-device without any overpriced cloud services or subscriptions."),
            
                .init(icon: UIImage(systemName: "cpu.fill")!,
                      iconTint: UIColor { trait in
                          trait.userInterfaceStyle == .dark
                          ? UIColor(red: 0.60, green: 0.88, blue: 0.80, alpha: 1.0)
                          : UIColor(red: 0.30, green: 0.68, blue: 0.58, alpha: 1.0)
                      },
                      title: "Native Performance",
                      description: "A custom kernel virtualization layer providing real process management, Mach IPC, and POSIX semantics directly on-device."),
        ])
    }
    
    static func setUpNotice() -> UIOnboardingTextViewConfiguration {
        return .init(icon: UIImage(systemName: "heart.fill")!,
                     text: "Contributions, feedback, and stars keep the project alive.",
                     linkTitle: "Contribute on GitHub",
                     link: "https://github.com/emexlab/emexDE",
                     linkColor: UIColor { trait in
                         trait.userInterfaceStyle == .dark
                             ? UIColor(red: 0.85, green: 0.74, blue: 0.93, alpha: 1.0)
                             : UIColor(red: 0.62, green: 0.48, blue: 0.78, alpha: 1.0)
                     })
    }
    
    static func setUpButton() -> UIOnboardingButtonConfiguration {
        return .init(title: "Continue", titleColor: currentTheme!.backgroundColor, backgroundColor: UIColor { trait in
            trait.userInterfaceStyle == .dark
            ? UIColor(red: 0.85, green: 0.74, blue: 0.93, alpha: 1.0)
            : UIColor(red: 0.62, green: 0.48, blue: 0.78, alpha: 1.0)
        })
    }
}

class SceneDelegate: UIResponder, UIWindowSceneDelegate, UITabBarControllerDelegate, UIOnboardingViewControllerDelegate {
    var window: NXWindowServer?
    
    func scene(_ scene: UIScene, willConnectTo session: UISceneSession, options connectionOptions: UIScene.ConnectionOptions) {
        guard let windowScene = scene as? UIWindowScene else { return }
        
        // swizzle swizzle swizzle :3
        UIViewController.swizzlePresentAndDismissOnce
        UIBarButtonItem.swizzleBarButtonitem
        
        self.window = NXWindowServer.shared(with: windowScene)
        if(self.window == nil)
        {
            return;
        }
        
        if(!liveProcessIsAvailable())
        {
            let label = UILabel()
            label.text = "NSExtension missing, make sure you keep the extension when installing."
            label.frame = UIScreen.main.bounds
            label.numberOfLines = 0
            self.window?.addSubview(label)
            self.window?.makeKeyAndVisible()
            self.window?.bringSubviewToFront(label)
            return
        }
        
        NXBootstrap.shared().bootstrap()

        let themedTabViewController: UIThemedTabViewController = UIThemedTabViewController()
        
        

        let contentViewController: ContentViewController = ContentViewController()
        let settingsViewController: SettingsViewController = SettingsViewController()
        let appsViewController: ApplicationManagementViewController = ApplicationManagementViewController.shared
        
        let contentNavigationController: UINavigationController = UINavigationController(rootViewController: contentViewController)
        let settingsNavigationController: UINavigationController = UINavigationController(rootViewController: settingsViewController)
        let appsNavigationController: UINavigationController = UINavigationController(rootViewController: appsViewController)
        var viewControllers: [UIViewController] = [contentNavigationController, settingsNavigationController, appsNavigationController] 
        contentNavigationController.tabBarItem = UITabBarItem(title: "Projects", image: UIImage(systemName: "square.grid.2x2.fill"), tag: 0)
        settingsNavigationController.tabBarItem = UITabBarItem(title: "Settings", image: UIImage(systemName: "gear"), tag: 1)
        appsNavigationController.tabBarItem = UITabBarItem(title: "Apps", image: UIImage(systemName: "app.badge"), tag: 2) 


        
        
        //if UIDevice.current.userInterfaceIdiom == .phone {
            //if #available(iOS 26.0, *) {
                //let fakeViewController: UIViewController = UIViewController()
                //fakeViewController.tabBarItem = UITabBarItem(tabBarSystemItem: .search, tag: 2)
                //fakeViewController.tabBarItem.title = "Switcher"
                //fakeViewController.tabBarItem.image = UIImage(systemName: "iphone.app.switcher")
                //viewControllers.append(fakeViewController)
            //}
        //}
        
        themedTabViewController.viewControllers = viewControllers
        themedTabViewController.delegate = self
        
        self.window?.rootViewController = themedTabViewController
        self.window?.makeKeyAndVisible()
        
        if let _: NSNumber = UserDefaults.standard.object(forKey: "NXOnboardingSentinel") as? NSNumber {
            return
        }
        
        let onboardingConfiguration = UIOnboardingViewConfiguration(appIcon: UIOnboardingHelper.setUpIcon(), firstTitleLine: UIOnboardingHelper.setUpFirstTitleLine(), secondTitleLine: UIOnboardingHelper.setUpSecondTitleLine(), features: UIOnboardingHelper.setUpFeatures(), textViewConfiguration: UIOnboardingHelper.setUpNotice(), buttonConfiguration: UIOnboardingHelper.setUpButton())
        let onboardingController: UIOnboardingViewController = UIOnboardingViewController(withConfiguration: onboardingConfiguration)
        onboardingController.delegate = self
        onboardingController.loadViewIfNeeded()
        DispatchQueue.main.async {
            for subview in onboardingController.view.subviews {
                if let scrollView = subview as? UIScrollView {
                    scrollView.backgroundColor = currentTheme!.backgroundColor
                }
            }
        }
        
        self.window?.rootViewController?.present(onboardingController, animated: false)
    }
    
    func tabBarController(_ tabBarController: UITabBarController, shouldSelect viewController: UIViewController) -> Bool {
        if tabBarController.selectedViewController === viewController && Builder.builds {
            return false
        }
        //if viewController.tabBarItem.tag == 2 {
            //self.window?.showAppSwitcherExternal()
            //return false
        //}
        return true
    }
    
    func didFinishOnboarding(onboardingViewController: UIOnboarding.UIOnboardingViewController) {
        onboardingViewController.modalTransitionStyle = .crossDissolve
        onboardingViewController.dismiss(animated: true, completion: nil)
        
        // storing sentinel so it will not appear again
        UserDefaults.standard.set(NSNumber(booleanLiteral: true), forKey: "NXOnboardingSentinel")
    }
}
