/*
 * MIT License
 *
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

#include <CoreCompiler/CCDriver.h>
#include <CoreCompiler/CCUtils.h>
#include <CoreCompiler/CCUtilsPrivate.h>
#include <clang/Basic/Diagnostic.h>
#include <clang/Basic/DiagnosticOptions.h>
#include <clang/Basic/SourceManager.h>
#include <clang/CodeGen/CodeGenAction.h>
#include <clang/Driver/Compilation.h>
#include <clang/Driver/Driver.h>
#include <clang/Driver/Tool.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/CompilerInvocation.h>
#include <clang/Frontend/FrontendDiagnostic.h>
#include <clang/Frontend/TextDiagnosticPrinter.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/ManagedStatic.h>
#include <llvm/Support/Path.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Target/TargetMachine.h>
#include <llvm/Support/TargetSelect.h>
#include <swift/Basic/LLVMInitialize.h>
#include <swift/Basic/SourceManager.h>
#include <swift/AST/DiagnosticEngine.h>
#include <swift/Frontend/PrintingDiagnosticConsumer.h>
#include <swift/Driver/Driver.h>
#include <swift/Driver/ToolChain.h>
#include <swift/Driver/Compilation.h>
#include <swift/Driver/Job.h>
#include <swift/Driver/Action.h>

using namespace llvm;
using namespace llvm::opt;

static CFTypeID gCCDriverTypeID = _kCFRuntimeNotATypeID;

struct __CCDriver {
    CFRuntimeBase _base;
    CCDriverType type;

    /* clang driver properties */
    IntrusiveRefCntPtr<clang::DiagnosticsEngine> clangDiagnosticEngine;
    std::unique_ptr<clang::driver::Driver> clangDriver;
    std::unique_ptr<clang::driver::Compilation> clangCompilation;

    /* swift driver properties */
    swift::SourceManager swiftSourceManager;
    swift::PrintingDiagnosticConsumer swiftPrintingDiagnosticConsumer;
    std::unique_ptr<swift::DiagnosticEngine> swiftDiagnosticEngine;
    std::unique_ptr<swift::driver::Driver> swiftDriver;
    std::unique_ptr<swift::driver::Compilation> swiftCompilation;
    std::unique_ptr<swift::driver::ToolChain> swiftToolChain;

    /* shared driver properties */
    void *outputPathCallbackContext;
    CCOutputPathCallback callback;
    llvm::SmallVector<std::string, 64> argStorage;
    llvm::SmallVector<const char *, 64> argPtr;
};

static CFTypeRef CCDriverCopy(CFAllocatorRef allocator,
                              CFTypeRef cf)
{
    return CFRetain(cf);
}

static void CCDriverInit(CFTypeRef cf)
{
    CCDriverRef driverRef = (CCDriverRef)cf;
    new (&driverRef->clangDiagnosticEngine) IntrusiveRefCntPtr<clang::DiagnosticsEngine>();
    new (&driverRef->clangDriver) std::unique_ptr<clang::driver::Driver>();
    new (&driverRef->clangCompilation) std::unique_ptr<clang::driver::Compilation>();
    new (&driverRef->swiftSourceManager) swift::SourceManager();
    new (&driverRef->swiftPrintingDiagnosticConsumer) swift::PrintingDiagnosticConsumer();
    new (&driverRef->swiftDiagnosticEngine) std::unique_ptr<swift::DiagnosticEngine>();
    new (&driverRef->swiftDriver) std::unique_ptr<swift::driver::Driver>();
    new (&driverRef->swiftCompilation) std::unique_ptr<swift::driver::Compilation>();
    new (&driverRef->swiftToolChain) std::unique_ptr<swift::driver::ToolChain>();
    driverRef->outputPathCallbackContext = nullptr;
    driverRef->callback = nullptr;
}

static void CCDriverFinalize(CFTypeRef cf)
{
    CCDriverRef driverRef = (CCDriverRef)cf;
    if(driverRef->type == kCCDriverTypeSwift)
    {
        std::destroy_at(&driverRef->swiftCompilation);
        std::destroy_at(&driverRef->swiftToolChain);
        std::destroy_at(&driverRef->swiftDriver);
        std::destroy_at(&driverRef->swiftDiagnosticEngine);
    }
    else if(driverRef->type == kCCDriverTypeClang)
    {
        std::destroy_at(&driverRef->clangCompilation);
        std::destroy_at(&driverRef->clangDriver);
        std::destroy_at(&driverRef->clangDiagnosticEngine);
    }
    
    std::destroy_at(&driverRef->argPtr);
    std::destroy_at(&driverRef->argStorage);
}

static const CFRuntimeClass gCCDriverClass = {
    0,                              /* version */
    "CCDriver",                     /* class name */
    CCDriverInit,                   /* init */
    CCDriverCopy,                   /* copy */
    CCDriverFinalize,               /* finalize */
    NULL,                           /* equal */
    NULL,                           /* hash */
    NULL,                           /* copyFormattingDesc */
    NULL,                           /* copyDebugDesc */
    NULL,
    NULL,
    0
};

CFTypeID CCDriverGetTypeID(void)
{
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        gCCDriverTypeID = _CFRuntimeRegisterClass(&gCCDriverClass);
    });
    return gCCDriverTypeID;
}

CCDriverRef CCDriverCreate(CFAllocatorRef allocator,
                           CFArrayRef arguments,
                           CCDriverType type)
{
    assert(arguments != nullptr);

    CCDriverRef driverRef = (CCDriverRef)_CFRuntimeCreateInstance(allocator, CCDriverGetTypeID(), sizeof(struct __CCDriver) + sizeof(CFRuntimeBase), NULL);
    if(!driverRef)
    {
        return nullptr;
    }

    driverRef->type = type;
    driverRef->argStorage = CCArrayToStringVector(arguments);

    if(type == kCCDriverTypeClang)
    {
        driverRef->argStorage.insert(driverRef->argStorage.begin(), "-fuse-ld=lld");
        driverRef->argStorage.insert(driverRef->argStorage.begin(), "clang");
    }
    else
    {
        driverRef->argStorage.insert(driverRef->argStorage.begin(), "swiftc");
    }
    
    new (&driverRef->argPtr) llvm::SmallVector<const char *, 64>();
    for(const std::string &arg : driverRef->argStorage)
    {
        driverRef->argPtr.push_back(arg.c_str());
    }

    switch(type)
    {
        case kCCDriverTypeClang:
        {
            IntrusiveRefCntPtr<clang::DiagnosticIDs> DiagID(new clang::DiagnosticIDs());
            clang::DiagnosticOptions DiagOpts;
            driverRef->clangDiagnosticEngine = IntrusiveRefCntPtr<clang::DiagnosticsEngine>(new clang::DiagnosticsEngine(DiagID, DiagOpts, new clang::IgnoringDiagConsumer(), /*ShouldOwnClient=*/true));
            
            try
            {
                driverRef->clangDriver = std::make_unique<clang::driver::Driver>("clang", "", *driverRef->clangDiagnosticEngine);
            }
            catch (...)
            {
                CFRelease(driverRef);
                return nullptr;
            }
            
            break;
        }
        case kCCDriverTypeSwift:
        {
            driverRef->swiftDiagnosticEngine = std::make_unique<swift::DiagnosticEngine>(driverRef->swiftSourceManager);
            driverRef->swiftDiagnosticEngine->addConsumer(driverRef->swiftPrintingDiagnosticConsumer);
            
            try
            {
                driverRef->swiftDriver = std::make_unique<swift::driver::Driver>("swiftc", "swiftc", driverRef->argPtr, *driverRef->swiftDiagnosticEngine);
            }
            catch (...)
            {
                CFRelease(driverRef);
                return nullptr;
            }
            
            break;
        }
        default:
            CFRelease(driverRef);
            return nullptr;
    }

    return driverRef;
}

static CCJobType _CCJobTypeGetFromClangCommand(const clang::driver::Command *Cmd)
{
    const clang::driver::Action &source = Cmd->getSource();

    if(clang::isa<clang::driver::CompileJobAction>(source) ||
       clang::isa<clang::driver::AssembleJobAction>(source))
    {
        return kCCJobTypeCompiler;
    }
    else if(clang::isa<clang::driver::LinkJobAction>(source))
    {
        return kCCJobTypeLinker;
    }
    else
    {
        return kCCJobTypeUnknown;
    }
}

static CCJobType _CCJobTypeGetFromSwiftJob(const swift::driver::Job *J)
{
    using K = swift::driver::Action::Kind;

    switch(J->getSource().getKind())
    {
        case K::CompileJob:
        case K::BackendJob:
        case K::MergeModuleJob:
        case K::ModuleWrapJob:
        case K::GeneratePCHJob:
        case K::AutolinkExtractJob:
        case K::VerifyModuleInterfaceJob:
            return kCCJobTypeSwiftCompiler;
        case K::DynamicLinkJob:
        case K::StaticLinkJob:
            return kCCJobTypeDriver;
        case K::InterpretJob:
        case K::REPLJob:
        default:
            return kCCJobTypeUnknown;
    }
}

static std::string _CCStringToStd(CFStringRef s)
{
    if(const char *fast = CFStringGetCStringPtr(s, kCFStringEncodingUTF8))
    {
        return std::string(fast);
    }
    CFIndex len = CFStringGetLength(s);
    CFIndex max = CFStringGetMaximumSizeForEncoding(len, kCFStringEncodingUTF8) + 1;
    std::string out; out.resize(max);
    CFIndex used = 0;
    CFStringGetBytes(s, CFRangeMake(0, len), kCFStringEncodingUTF8, 0, false, (UInt8 *)out.data(), max, &used);
    out.resize(used);
    return out;
}

static void _AppendCStr(CFMutableArrayRef arr, CFAllocatorRef a, const char *str)
{
    if(CFStringRef s = CFStringCreateWithCString(a, str, kCFStringEncodingUTF8))
    {
        CFArrayAppendValue(arr, s);
        CFRelease(s);
    }
}

static void _AppendJob(CFMutableArrayRef out, CFAllocatorRef a,
                       CCJobType type, const llvm::opt::ArgStringList &argv)
{
    CFMutableArrayRef argsArray = CFArrayCreateMutable(a, argv.size(), &kCFTypeArrayCallBacks);
    for(const char *arg : argv)
    {
        if(arg)
        {
            _AppendCStr(argsArray, a, arg);
        }
    }
    CCJobRef jobRef = CCJobCreate(a, type, argsArray);
    CFRelease(argsArray);
    if(jobRef)
    {
        CFArrayAppendValue(out, jobRef);
        CFRelease(jobRef);
    }
}

static Boolean IsDriverInputArg(CFStringRef arg)
{
    static const CFStringRef kInputSuffixes[] = {
        CFSTR(".c"), CFSTR(".cc"), CFSTR(".cpp"), CFSTR(".cxx"),
        CFSTR(".m"), CFSTR(".mm"), CFSTR(".S"), CFSTR(".s"),
    };
    for(size_t i = 0; i < sizeof(kInputSuffixes)/sizeof(*kInputSuffixes); i++)
    {
        if(CFStringHasSuffix(arg, kInputSuffixes[i]))
        {
            return true;
        }
    }
    return false;
}

static void CollapseArgsToWl(CFMutableArrayRef argsArray)
{
    CFIndex count = CFArrayGetCount(argsArray);
    if(count == 0)
    {
        return;
    }

    CFMutableArrayRef passthrough = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    CFMutableStringRef wl = CFStringCreateMutable(kCFAllocatorDefault, 0);
    CFStringAppend(wl, CFSTR("-Wl"));
    Boolean haveWlPayload = false;

    for(CFIndex i = 0; i < count; i++)
    {
        CFStringRef arg = (CFStringRef)CFArrayGetValueAtIndex(argsArray, i);

        if(CFEqual(arg, CFSTR("-o")))
        {
            CFArrayAppendValue(passthrough, arg);
            if(i + 1 < count)
            {
                CFArrayAppendValue(passthrough, CFArrayGetValueAtIndex(argsArray, i + 1));
                i++;
            }
            continue;
        }

        if(IsDriverInputArg(arg))
        {
            CFArrayAppendValue(passthrough, arg);
            continue;
        }

        CFStringAppend(wl, CFSTR(","));
        CFStringAppend(wl, arg);
        haveWlPayload = true;
    }

    CFArrayRemoveAllValues(argsArray);
    if(haveWlPayload)
    {
        CFArrayAppendValue(argsArray, wl);
    }
    CFArrayAppendArray(argsArray, passthrough, CFRangeMake(0, CFArrayGetCount(passthrough)));

    CFRelease(wl);
    CFRelease(passthrough);
}

CFArrayRef CCDriverCreateJobs(CFAllocatorRef allocator,
                              CCDriverRef driver)
{
    llvm::SmallVector<const char *, 64> Args;
    Args.reserve(driver->argStorage.size());
    for(const auto &s : driver->argStorage)
    {
        Args.push_back(s.c_str());
    }
    
    CFMutableArrayRef jobsArray = CFArrayCreateMutable(allocator, 0, &kCFTypeArrayCallBacks);
    
    switch(driver->type)
    {
        case kCCDriverTypeClang:
        {
            using namespace clang::driver;
            using llvm::isa; using llvm::cast; using llvm::dyn_cast;
            
            driver->clangCompilation.reset(driver->clangDriver->BuildCompilation(Args));
            if(!driver->clangCompilation)
            {
                CFRelease(jobsArray);
                return nullptr;
            }
            
            llvm::StringMap<const char *> pathRemap;
            llvm::SmallPtrSet<const Command *, 8> skippedJobs;
            
            if(driver->callback)
            {
                for(auto &Job : driver->clangCompilation->getJobs())
                {
                    if(!isa<Command>(Job))
                    {
                        continue;
                    }
                    
                    Command &Cmd = const_cast<Command &>(cast<Command>(Job));
                    const clang::driver::Action &Src = Cmd.getSource();
                    if(!isa<CompileJobAction>(Src) && !isa<AssembleJobAction>(Src))
                    {
                        continue;
                    }
                    
                    const clang::driver::Action *leaf = &Src;
                    while(!leaf->getInputs().empty())
                    {
                        leaf = leaf->getInputs()[0];
                    }
                    
                    const char *baseInput = nullptr;
                    if(auto *IA = dyn_cast<InputAction>(leaf))
                    {
                        baseInput = IA->getInputArg().getValue();
                    }
                    
                    bool skip = false;
                    CFStringRef newCF = driver->callback(baseInput, &skip, driver->outputPathCallbackContext);
                    if(!newCF)
                    {
                        continue;
                    }
                    
                    std::string s = _CCStringToStd(newCF);
                    CFRelease(newCF);
                    
                    const char *newArg = driver->clangCompilation->getArgs().MakeArgString(s);
                    
                    llvm::opt::ArgStringList newArgs;
                    const auto &old = Cmd.getArguments();
                    for(size_t i = 0; i < old.size(); ++i)
                    {
                        if(llvm::StringRef(old[i]) == "-o" && i + 1 < old.size())
                        {
                            pathRemap[old[i + 1]] = newArg;
                            newArgs.push_back(old[i]);
                            newArgs.push_back(newArg);
                            ++i;
                        }
                        else
                        {
                            newArgs.push_back(old[i]);
                        }
                    }
                    Cmd.replaceArguments(newArgs);
                    if(skip)
                    {
                        skippedJobs.insert(&Cmd);
                    }
                }
            }
            
            if(!pathRemap.empty())
            {
                for(auto &Job : driver->clangCompilation->getJobs())
                {
                    if(!isa<Command>(Job))
                    {
                        continue;
                    }
                    
                    Command &Cmd = const_cast<Command &>(cast<Command>(Job));
                    if(!isa<LinkJobAction>(Cmd.getSource()))
                    {
                        continue;
                    }
                    
                    llvm::opt::ArgStringList newArgs;
                    for(const char *a : Cmd.getArguments())
                    {
                        auto it = pathRemap.find(a);
                        newArgs.push_back(it != pathRemap.end() ? it->second : a);
                    }
                    
                    Cmd.replaceArguments(newArgs);
                }
            }
            
            for(auto &Job : driver->clangCompilation->getJobs())
            {
                if(!isa<Command>(Job))
                {
                    continue;
                }
                const Command &Cmd = cast<Command>(Job);
                if(skippedJobs.contains(&Cmd))
                {
                    continue;
                }
                
                CCJobType type = _CCJobTypeGetFromClangCommand(&Cmd);
                _AppendJob(jobsArray, allocator, type, Cmd.getArguments());
            }
            break;
        }
        case kCCDriverTypeSwift:
        {
            using llvm::dyn_cast;
            using K = swift::driver::Action::Kind;
            
            auto ArgList = driver->swiftDriver->parseArgStrings(llvm::ArrayRef<const char *>(Args).slice(1));
            if(!ArgList || driver->swiftDiagnosticEngine->hadAnyError())
            {
                CFRelease(jobsArray);
                return nullptr;
            }
            
            driver->swiftToolChain = driver->swiftDriver->buildToolChain(*ArgList);
            if(!driver->swiftToolChain)
            {
                CFRelease(jobsArray);
                return nullptr;
            }
            
            driver->swiftCompilation = driver->swiftDriver->buildCompilation(*driver->swiftToolChain, std::move(ArgList));
            if(!driver->swiftCompilation || driver->swiftDiagnosticEngine->hadAnyError())
            {
                CFRelease(jobsArray);
                return nullptr;
            }
            
            llvm::StringMap<std::string> pathRemap;
            llvm::DenseMap<const swift::driver::Job *, std::string> jobOwnOutput;
            llvm::SmallPtrSet<const swift::driver::Job *, 8> skippedJobs;
            
            if(driver->callback)
            {
                for(const swift::driver::Job *J : driver->swiftCompilation->getJobs())
                {
                    K k = J->getSource().getKind();
                    if(k != K::CompileJob && k != K::BackendJob)
                    {
                        continue;
                    }
                    
                    const swift::driver::Action *leaf = &J->getSource();
                    while(auto *JA = llvm::dyn_cast<swift::driver::JobAction>(leaf))
                    {
                        if(JA->getInputs().empty())
                        {
                            break;
                        }
                        leaf = JA->getInputs()[0];
                    }
                    
                    const char *baseInput = nullptr;
                    if(auto *IA = llvm::dyn_cast<swift::driver::InputAction>(leaf))
                    {
                        baseInput = IA->getInputArg().getValue();
                    }
                    
                    bool skip = false;
                    CFStringRef newCF = driver->callback(baseInput, &skip, driver->outputPathCallbackContext);
                    if(!newCF)
                    {
                        continue;
                    }
                    
                    std::string s = _CCStringToStd(newCF);
                    CFRelease(newCF);
                    
                    llvm::StringRef oldOut = J->getOutput().getPrimaryOutputFilename();
                    if(!oldOut.empty())
                    {
                        pathRemap[oldOut] = s;
                    }
                    jobOwnOutput[J] = std::move(s);
                    if(skip)
                    {
                        skippedJobs.insert(J);
                    }
                }
            }
            
            for(const swift::driver::Job *J : driver->swiftCompilation->getJobs())
            {
                if(skippedJobs.contains(J))
                {
                    continue;
                }
                
                CCJobType type = _CCJobTypeGetFromSwiftJob(J);
                const llvm::opt::ArgStringList &cmdArgs = J->getArguments();
                
                auto ownIt = jobOwnOutput.find(J);
                const std::string *ownNew = (ownIt != jobOwnOutput.end()) ? &ownIt->second : nullptr;
                llvm::StringRef ownOldOut = J->getOutput().getPrimaryOutputFilename();
                
                CFMutableArrayRef argsArray = CFArrayCreateMutable(allocator, cmdArgs.size(), &kCFTypeArrayCallBacks);
                
                for(size_t i = 0; i < cmdArgs.size(); ++i)
                {
                    const char *arg = cmdArgs[i];
                    if(!arg)
                    {
                        continue;
                    }
                    
                    if(ownNew && llvm::StringRef(arg) == "-o" && i + 1 < cmdArgs.size() && llvm::StringRef(cmdArgs[i + 1]) == ownOldOut)
                    {
                        _AppendCStr(argsArray, allocator, "-o");
                        _AppendCStr(argsArray, allocator, ownNew->c_str());
                        ++i;
                        continue;
                    }
                    
                    auto it = pathRemap.find(arg);
                    _AppendCStr(argsArray, allocator, it != pathRemap.end() ? it->second.c_str() : arg);
                }
                
                /*
                 * in-case the swift driver emits a clang driver job
                 * we gonna have to convert all args to a linker flag
                 * due to swiftc legacy driver creating a linker instead
                 * of a clang driver arg, what is even funnier is that
                 * it adds c and objc files to the linker flags lmfao.
                 */
                if(type == kCCJobTypeDriver)
                {
                    CollapseArgsToWl(argsArray);
                    
                    /* TODO: translate some swift flags into clang driver flags */
                }
            
            out_append_swift_job:
                {
                    
                    CCJobRef jobRef = CCJobCreate(allocator, type, argsArray);
                    CFRelease(argsArray);
                    if(jobRef)
                    {
                        CFArrayAppendValue(jobsArray, jobRef);
                        CFRelease(jobRef);
                    }
                }
            }
            break;
        }
        default:
            CFRelease(jobsArray);
            return nullptr;
    }
    
    return jobsArray;
}

void CCDriverSetOutputPathCallback(CCDriverRef driver,
                                   CCOutputPathCallback callback,
                                   void *context)
{
    driver->callback = callback;
    driver->outputPathCallbackContext = context;
}

void *CCDriverGetOutputPathCallbackContext(CCDriverRef driver)
{
    return driver->outputPathCallbackContext;
}

CFURLRef CCDriverCopySysrootURL(CCDriverRef driver)
{
    std::string cxxstr;

    switch(driver->type)
    {
        case kCCDriverTypeClang:
            if(!driver->clangCompilation)
            {
                return nullptr;
            }
            cxxstr = driver->clangCompilation->getSysRoot().str();
            break;
        case kCCDriverTypeSwift:
        {
            if(!driver->swiftCompilation)
            {
                return nullptr;
            }
            const auto &Args = driver->swiftCompilation->getArgs();
            if(const llvm::opt::Arg *A = Args.getLastArg(swift::options::OPT_sdk))
            {
                cxxstr = A->getValue();
            }
            break;
        }
        default:
            return nullptr;
    }
    
    if(cxxstr.empty())
    {
        return nullptr;
    }
        
    CFAllocatorRef allocator = CFGetAllocator(driver);
    CFStringRef str = CFStringCreateWithCString(allocator, cxxstr.c_str(), kCFStringEncodingUTF8);
    if(!str)
    {
        return nullptr;
    }
    CFURLRef url = CFURLCreateWithFileSystemPath(allocator, str, kCFURLPOSIXPathStyle, true);
    CFRelease(str);
    return url;
}

CCSDKRef CCDriverCopySDK(CCDriverRef driver)
{
    CFURLRef sdkRoot = CCDriverCopySysrootURL(driver);
    if(sdkRoot == nullptr)
    {
        return nullptr;
    }

    CCSDKRef sdk = CCSDKCreateWithDirectoryURL(CFGetAllocator(driver), sdkRoot);
    CFRelease(sdkRoot);
    return sdk;
}
