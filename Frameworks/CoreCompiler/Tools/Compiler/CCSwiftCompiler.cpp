/*
 * MIT License
 *
 * Copyright (c) 2026 Kyle-Ye
 * Copyright (c) 2026 emexlab
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <CoreCompiler/CCSwiftCompiler.h>
#include <CoreCompiler/CCDiagnostic.h>
#include <CoreCompiler/CCFile.h>
#include <CoreCompiler/CCUtils.h>
#include <CoreCompiler/CCUtilsPrivate.h>
#include <swift/FrontendTool/FrontendTool.h>
#include <swift/Frontend/Frontend.h>
#include <swift/Frontend/PrintingDiagnosticConsumer.h>
#include <swift/Basic/InitializeSwiftModules.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/Path.h>
#include <llvm/Support/ErrorHandling.h>
#include <fcntl.h>
#include <mutex>
#include <unistd.h>

struct CapturedDiag {
    swift::DiagID id;
    swift::DiagnosticKind kind;
    std::string message;
    std::string file;
    unsigned line = 0, column = 0;
};

class CapturingConsumer : public swift::DiagnosticConsumer {
public:
    std::vector<CapturedDiag> diags;

    void handleDiagnostic(swift::SourceManager &SM,
                          const swift::DiagnosticInfo &Info) override
    {
        CapturedDiag d;
        d.id = Info.ID;
        d.kind = Info.Kind;
        
        llvm::SmallString<256> buf;
        {
            llvm::raw_svector_ostream os(buf);
            swift::DiagnosticEngine::formatDiagnosticText(os, Info.FormatString, Info.FormatArgs);
        }
        d.message = std::string(buf);

        if(Info.Loc.isValid())
        {
            auto lc = SM.getPresumedLineAndColumnForLoc(Info.Loc);
            d.line = lc.first;
            d.column = lc.second;
            d.file = SM.getDisplayNameForLoc(Info.Loc).str();
        }
        diags.push_back(std::move(d));
    }
};

class CCSwiftObserver : public swift::FrontendObserver {
public:
    std::string primaryFile;
    CapturingConsumer consumer;
    
    void parsedArgs(swift::CompilerInvocation &invocation) override
    {
        auto &io = invocation.getFrontendOptions().InputsAndOutputs;
        if(io.hasPrimaryInputs())
        {
            io.forEachPrimaryInput([&](const swift::InputFile &f) -> bool
            {
                primaryFile = f.getFileName();
                return true;
            });
        }
        else
        {
            /* TODO: implement wmo support */
            primaryFile = "wmo";
        }
    }
    
    void configuredCompiler(swift::CompilerInstance &CI) override
    {
        CI.addDiagnosticConsumer(&consumer);
    }
};

CC_EXPORT Boolean CCSwiftCompilerJobExecute(CCJobRef job,
                                            CFArrayRef *outDiagnostics,
                                            CFStringRef *outMainSource)
{
    assert(job != nullptr);
    assert(CCJobGetType(job) == kCCJobTypeSwiftCompiler);
    
    CFArrayRef argsArray = CCJobCreateArguments(CFGetAllocator(job), job);
    
    llvm::SmallVector<std::string, 64> argStorage = CCArrayToStringVector(argsArray);
    llvm::SmallVector<const char *, 64> args = StringVectorToCStrings(argStorage);
    
    /* get_-frontend_out_of_my_way type shii */
    if(!args.empty() && std::strcmp(args.front(), "-frontend") == 0)
    {
        args.erase(args.begin());
    }
    
    CCInitializeSwiftModulesOnce();
    
    CCSwiftObserver obs;
    llvm::remove_fatal_error_handler();
    int status = swift::performFrontend(args, "swift-frontend", nullptr, &obs);
    CCInstallLLVMFatalErrorHandler();
    
    if(outDiagnostics == nullptr)
    {
        return status == 0;
    }
    
    *outDiagnostics = CFArrayCreateMutable(kCFAllocatorSystemDefault, obs.consumer.diags.size(), &kCFTypeArrayCallBacks);
    if(*outDiagnostics == nullptr)
    {
        return status == 0;
    }
    
    if(obs.primaryFile.empty())
    {
        return status == 0;
    }
    
    CFStringRef mainSource = CFStringCreateWithCString(kCFAllocatorSystemDefault, obs.primaryFile.c_str(), kCFStringEncodingUTF8);
    if(mainSource == nullptr)
    {
        return status == 0;
    }
    
    for(auto &d : obs.consumer.diags)
    {
        CCDiagnosticLevel level = kCCDiagnosticLevelUnknown;
        
        switch(d.kind)
        {
            case swift::DiagnosticKind::Error:
                level = kCCDiagnosticLevelError;
                break;
            case swift::DiagnosticKind::Warning:
                level = kCCDiagnosticLevelWarning;
                break;
            case swift::DiagnosticKind::Remark:
                level = kCCDiagnosticLevelRemark;
                break;
            case swift::DiagnosticKind::Note:
                level = kCCDiagnosticLevelNote;
                break;
            default:
                break;
        }
        
        if(level == kCCDiagnosticLevelUnknown)
        {
            continue;
        }
        
        CFStringRef messageStr = CFStringCreateWithCString(kCFAllocatorSystemDefault, d.message.c_str(), kCFStringEncodingUTF8);
        if(messageStr == nullptr)
        {
            continue;
        }
        
        CFStringRef fileSource = CFStringCreateWithCString(kCFAllocatorDefault, d.file.c_str(), kCFStringEncodingUTF8);
        if(fileSource == nullptr)
        {
            CFRelease(messageStr);
            continue;
        }
        
        CCFileSourceLocationRef fileSourceLocation = nullptr;
        CCFileRef file = CCFileCreateWithCString(kCFAllocatorSystemDefault, d.file.c_str(), kCFStringEncodingUTF8);
        if(file != nullptr)
        {
            CFURLRef fileURL = CCFileGetFileURL(file);
            fileSourceLocation = CCFileSourceLocationCreate(kCFAllocatorSystemDefault, fileURL, CCSourceLocationMake(d.line, d.column));
            CFRelease(file);
        }
        
        CCDiagnosticRef diagnostic = CCDiagnosticCreate(kCFAllocatorSystemDefault, kCCDiagnosticTypeFile, level, fileSource, fileSourceLocation, messageStr);
        CFRelease(messageStr);
        if(fileSourceLocation != nullptr)
        {
            CFRelease(fileSourceLocation);
        }
        if(diagnostic == nullptr)
        {
            continue;
        }
        
        CFArrayAppendValue((CFMutableArrayRef)*outDiagnostics, diagnostic);
        CFRelease(diagnostic);
    }
    
    if(outMainSource == nullptr)
    {
        CFRelease(mainSource);
    }
    else
    {
        *outMainSource = mainSource;
    }
    
    return status == 0;
}
