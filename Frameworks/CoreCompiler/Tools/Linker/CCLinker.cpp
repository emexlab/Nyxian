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

#include <CoreCompiler/CCLinker.h>
#include <CoreCompiler/CCUtils.h>
#include <CoreCompiler/CCUtilsPrivate.h>
#include <lld/Common/Driver.h>
#include <lld/Common/ErrorHandler.h>
#include <llvm/ADT/ArrayRef.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/CrashRecoveryContext.h>
#include <lld/Common/CommonLinkerContext.h>
#include <os/lock.h>

namespace lld {
namespace macho {

bool link(llvm::ArrayRef<const char *> args, llvm::raw_ostream &stdoutOS,
          llvm::raw_ostream &stderrOS, bool exitEarly, bool disableOutput);

} // namespace macho
} // namespace lld

Boolean CCLinkerJobExecute(CCJobRef job,
                           CFArrayRef *outDiagnostics)
{
    static os_unfair_lock lock = OS_UNFAIR_LOCK_INIT;
    os_unfair_lock_lock(&lock);
    
    assert(job != nullptr);
    assert(CCJobGetType(job) == kCCJobTypeLinker);
    
    CFArrayRef argsArray = CCJobCreateArguments(CFGetAllocator(job), job);
    
    llvm::SmallVector<std::string, 64> argStorage = CCArrayToStringVector(argsArray);
    llvm::SmallVector<const char *, 64> Args = StringVectorToCStrings(argStorage);
    
    argStorage.push_back("ld64.lld");   /* have to inject */
    Args.insert(Args.begin(), argStorage.back().c_str());
    
    std::string errBuf;
    int retCode;
    
    llvm::CrashRecoveryContext CRC;
    CRC.RunSafely([&]{
        const lld::DriverDef drivers[] = {
            {lld::Darwin, &lld::macho::link},
        };
        
        llvm::raw_string_ostream errStream(errBuf);
        
        lld::Result result = lld::lldMain(Args, errStream, errStream, drivers);
        
        errStream.flush();
        retCode = result.retCode;
        
        lld::CommonLinkerContext::destroy();
    });
    
    CFAllocatorRef allocator = CFGetAllocator(job);
    CFMutableArrayRef result = CFArrayCreateMutable(allocator, 1, &kCFTypeArrayCallBacks);
    
    if(!errBuf.empty())
    {
        if(errBuf.back() == '\n')
        {
            errBuf.pop_back();
        }
        
        /* process error returns */
        if(result == nullptr)
        {
            os_unfair_lock_unlock(&lock);
            return retCode == 0;
        }
        
        CCDiagnosticLevel level = (retCode == 0) ? kCCDiagnosticLevelWarning : kCCDiagnosticLevelError;
        CFStringRef message = CFStringCreateWithCString(allocator, errBuf.c_str(), kCFStringEncodingUTF8);
        CCDiagnosticRef diagnosticRef = CCDiagnosticCreate(allocator, kCCDiagnosticTypeInternal, level, CFSTR("linker"), nullptr, message);
        CFRelease(message);
        if(diagnosticRef != nullptr)
        {
            CFArrayAppendValue(result, diagnosticRef);
            CFRelease(diagnosticRef);
        }
    }
    
    if(outDiagnostics != nullptr)
    {
        *outDiagnostics = result;
    }
    
    os_unfair_lock_unlock(&lock);
    
    return retCode == 0;
}
