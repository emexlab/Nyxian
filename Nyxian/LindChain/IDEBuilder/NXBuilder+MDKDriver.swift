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

import MobileDevelopmentKit

extension NXBuilder: MDKDriverDelegate {
    func driver(_ driver: MDKDriver,
                outputPathForInputFile file: MDKFile) -> String? {
        return "\(self.project.cacheURL.path)/\(NXExpectedObjectFileURLForFileURL(NXRelativeURLFromBaseURLToFullURL(self.project.url, file.fileURL)).path)"
    }
    
    func driver(_ driver: MDKDriver, editJobListForJobList jobs: [MDKJob]) -> [MDKJob]? {
        if driver.type != .clang {
            return jobs
        }
        
        // This can now in theory run in parallel ?:3
        // Lets make incremental build fast again >=3
        print("[#] JOBS.IN: \(jobs)");
        var newJobs: [MDKJob] = []
        
        let userSelectedValue: NSNumber? = UserDefaults.standard.object(forKey: "cputhreads") as? NSNumber
        let userSelected = userSelectedValue?.intValue ?? CCGetMaximumPerformanceCores()
        let threads = CFIndex(userSelected == 0 ? 1 : userSelected)
        
        let mdkThreadPoolGroup: MDKThreadPoolGroup = MDKThreadPoolGroup(threads: threads)
        for job in jobs {
            // Only need the compiler jobs lol
            if job.type == .compiler,
               let inputFileURLs = job.inputFileURLs,
               inputFileURLs.count == 1,    // If it is over 1, tf did it emit
               let _ = job.outputFileURL {
                mdkThreadPoolGroup.enter()
            }
        }
        
        // So we don't get a race condition, the thread safety expert Duy Tran would skip this step ^^
        //
        // Duy Tran quote: "MDKThreadPoolGroup only has 8 threads on a 8 core SoC."
        //
        var osUnfairLock: os_unfair_lock = .init()
        
        for job in jobs {
            // Only need the compiler jobs lol
            if job.type == .compiler,
               let inputFileURLs = job.inputFileURLs,
               inputFileURLs.count == 1,    // If it is over 1, tf did it emit
               let outputFileURL = job.outputFileURL {
                
                let inputFileURL = inputFileURLs[0]
                
                mdkThreadPoolGroup.dispatchExecution({
                    // Checking if the source file is newer than the compiled object file
                    guard let sourceDate = try? FileManager.default.attributesOfItem(atPath: inputFileURL.path)[.modificationDate] as? Date,
                          let objectDate = try? FileManager.default.attributesOfItem(atPath: outputFileURL.path)[.modificationDate] as? Date,
                          objectDate > sourceDate else {
                        self.database.removeFileDebug(ofPath: inputFileURL.path)
                        os_unfair_lock_lock(&osUnfairLock)
                        newJobs.append(job)
                        os_unfair_lock_unlock(&osUnfairLock)
                        return
                    }
                    
                    // Checking if the header files included by the source code are newer than the object file
                    let inputFile: MDKFile = MDKFile(url: inputFileURL)
                    guard let headers = self.dependencyScanner.headerFiles(for: inputFile) else {
                        self.database.removeFileDebug(ofPath: inputFile.fileURL.path)
                        os_unfair_lock_lock(&osUnfairLock)
                        newJobs.append(job)
                        os_unfair_lock_unlock(&osUnfairLock)
                        return
                    }
                    
                    var needsRebuild = false
                    for header in headers {
                        guard let fileURL = header.fileURL,
                              let headerDate = try? FileManager.default.attributesOfItem(atPath: fileURL.path)[.modificationDate] as? Date,
                              objectDate > headerDate else {
                            self.database.removeFileDebug(ofPath: inputFileURL.path)
                            needsRebuild = true
                            break
                        }
                    }
                    
                    if needsRebuild {
                        self.database.removeFileDebug(ofPath: inputFileURL.path)
                        os_unfair_lock_lock(&osUnfairLock)
                        newJobs.append(job)
                        os_unfair_lock_unlock(&osUnfairLock)
                    }
                }, withCompletion: nil)
            }
        }
        
        mdkThreadPoolGroup.wait()
        
        for job in jobs {
            // Only need the compiler jobs lol
            if job.type == .compiler,
               let inputFileURLs = job.inputFileURLs,
               inputFileURLs.count == 1,    // If it is over 1, tf did it emit
               let _ = job.outputFileURL {
            } else {
                // Not a hack, usually this can only be a linker job
                newJobs.append(job)
            }
        }
        
        print("[#] JOBS.OUT: \(newJobs)");
        return newJobs
    }
}
