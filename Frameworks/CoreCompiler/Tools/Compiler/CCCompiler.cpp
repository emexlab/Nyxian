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

#include <CoreCompiler/CCCompiler.h>
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

using namespace clang;
using namespace clang::driver;

CC_CXX_EXPORT CCASTUnitRef CCASTUnitCreateWithASTUnit(CFAllocatorRef allocator, std::unique_ptr<clang::ASTUnit> astUnit);

CCASTUnitRef CCCompilerJobExecute(CCJobRef job)
{
    assert(job != nullptr);
    assert(CCJobGetType(job) == kCCJobTypeCompiler);

    CFArrayRef argsArray = CCJobCreateArguments(CFGetAllocator(job), job);

    llvm::SmallVector<std::string, 64> argStorage = CCArrayToStringVector(argsArray);
    llvm::SmallVector<const char *, 64> Args = StringVectorToCStrings(argStorage);

    /* setting up clang driver */
    auto DiagOpts = std::make_shared<DiagnosticOptions>();
    IntrusiveRefCntPtr<DiagnosticIDs> DiagID(new DiagnosticIDs());
    IntrusiveRefCntPtr<DiagnosticsEngine> Diags(new DiagnosticsEngine(DiagID, *DiagOpts, new IgnoringDiagConsumer(), /*ShouldOwnClient=*/true));

    /* creating clang invocation */
    auto CI = std::make_shared<CompilerInvocation>();
    CompilerInvocation::CreateFromArgs(*CI, Args, *Diags);

    /*
     * enabling free
     *
     * this is very important to prevent memory leak, clang is usually
     * designed to run in a one hit way, but this is a iOS app so it
     * cannot run in one hit.
     */
    CI->getFrontendOpts().DisableFree = false;
    
    /* fixup cache path*/
    std::string cachePath = std::string(std::getenv("HOME")) + "/Library/Caches/Clang";
    std::error_code EC = llvm::sys::fs::create_directories(cachePath);
    if(!EC)
    {
        CI->getHeaderSearchOpts().ModuleCachePath = cachePath;
    }
    
    /* compiling */
    auto Act = std::make_unique<EmitObjAction>();

    ASTUnit *ASTUnit = ASTUnit::LoadFromCompilerInvocationAction(
        CI,
        std::make_shared<PCHContainerOperations>(),
        DiagOpts,
        Diags,
        Act.release(),
        nullptr,
        true,
        "",
        false,
        CaptureDiagsKind::All
    );

    return ASTUnit ? CCASTUnitCreateWithASTUnit(CFGetAllocator(job), std::unique_ptr<clang::ASTUnit>(ASTUnit)) : nullptr;
}
