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

#include <CoreCompiler/CCJob.h>
#include <CoreCompiler/CCDriver.h>
#include <CoreCompiler/CCCompiler.h>
#include <CoreCompiler/CCSwiftCompiler.h>
#include <CoreCompiler/CCLinker.h>

static CFTypeID gCCJobTypeID = _kCFRuntimeNotATypeID;

struct __CCJob {
    CFRuntimeBase _base;
    CCJobType type;
    CFArrayRef baseArguments;
    CFArrayRef inputFileURLs;
    CFURLRef outputFileURL;
};

static CFTypeRef CCJobCopy(CFAllocatorRef allocator,
                           CFTypeRef cf)
{
    return CFRetain(cf);
}

static void CCJobFinalize(CFTypeRef cf)
{
    CCJobRef jobRef = (CCJobRef)cf;
    if(jobRef->baseArguments != nil)
    {
        CFRelease(jobRef->baseArguments);
    }
    if(jobRef->outputFileURL != nil)
    {
        CFRelease(jobRef->outputFileURL);
    }
    if(jobRef->inputFileURLs != nil)
    {
        CFRelease(jobRef->inputFileURLs);
    }
}

static const CFRuntimeClass gCCJobClass = {
    0,                              /* version */
    "CCJob",                        /* class name */
    NULL,                           /* init */
    CCJobCopy,                      /* copy */
    CCJobFinalize,                  /* finalize */
    NULL,                           /* equal */
    NULL,                           /* hash */
    NULL,                           /* copyFormattingDesc */
    NULL,                           /* copyDebugDesc */
    NULL,
    NULL,
    0
};

CFTypeID CCJobGetTypeID(void)
{
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        gCCJobTypeID = _CFRuntimeRegisterClass(&gCCJobClass);
    });
    return gCCJobTypeID;
}

CCJobRef CCJobCreate(CFAllocatorRef allocator,
                     CCJobType type,
                     CFArrayRef CC1Arguments,
                     CFArrayRef inputFileURLs,
                     CFURLRef outputFileURL)
{
    assert(CC1Arguments != nil);
    
    CCJobRef jobRef = (CCJobRef)_CFRuntimeCreateInstance(allocator, CCJobGetTypeID(), sizeof(struct __CCJob) - sizeof(CFRuntimeBase), NULL);
    if(jobRef == nil)
    {
        return nil;
    }
    
    jobRef->type = type;
    jobRef->baseArguments = CFRetain(CC1Arguments);
    
    /* those can be NULL */
    if(inputFileURLs)
    {
        jobRef->inputFileURLs = CFRetain(inputFileURLs);
    }
    if(outputFileURL)
    {
        jobRef->outputFileURL = CFRetain(outputFileURL);
    }
    
    return jobRef;
}

CCJobType CCJobGetType(CCJobRef job)
{
    return job->type;
}

CFArrayRef CCJobGetBaseArguments(CCJobRef job)
{
    return job->baseArguments;
}

CFArrayRef CCJobGetInputFileURLs(CCJobRef job)
{
    return job->inputFileURLs;
}

CFURLRef CCJobGetOutputFileURL(CCJobRef job)
{
    return job->outputFileURL;
}

CFArrayRef CCJobCreateArguments(CFAllocatorRef allocator,
                                CCJobRef job)
{
    CFMutableArrayRef mutableArguments = CFArrayCreateMutableCopy(allocator, 0, job->baseArguments);
    if(mutableArguments == NULL)
    {
        return NULL;
    }
    
    CFIndex insert = 0;
    if(CFArrayGetCount(job->baseArguments) > 0)
    {
        CFStringRef first = CFArrayGetValueAtIndex(job->baseArguments, 0);
        if(CFEqual(first, CFSTR("-cc1")) || CFEqual(first, CFSTR("-cc1as")))
        {
            insert = 1;
        }
    }
    
    if(job->outputFileURL != NULL)
    {
        CFStringRef path = CFURLCopyFileSystemPath(job->outputFileURL, kCFURLPOSIXPathStyle);
        if(path != NULL)
        {
            CFArrayInsertValueAtIndex(mutableArguments, insert, path);
            CFArrayInsertValueAtIndex(mutableArguments, insert, CFSTR("-o"));
            CFRelease(path);
        }
    }
    
    if(job->inputFileURLs != NULL)
    {
        CFIndex inputFileURLCount = CFArrayGetCount(job->inputFileURLs);
        for(CFIndex index = 0; index < inputFileURLCount; index++)
        {
            CFURLRef url = CFArrayGetValueAtIndex(job->inputFileURLs, index);
            CFStringRef path = CFURLCopyFileSystemPath(url, kCFURLPOSIXPathStyle);
            if(path != NULL)
            {
                CFArrayInsertValueAtIndex(mutableArguments, insert, path);
                CFRelease(path);
            }
        }
    }
    
    return mutableArguments;
}

CC_EXPORT Boolean CCJobExecuteJob(CCJobRef job,
                                  CFArrayRef *outDiagnostic,
                                  CFStringRef *outMainSource)
{
    switch(job->type)
    {
        case kCCJobTypeCompiler:
        {
            CCASTUnitRef ASTUnit = CCCompilerJobExecute(job);
            if(ASTUnit == nil)
            {
                return false;
            }
            
            CCFileRef file = CCASTUnitGetFile(ASTUnit);
            if(file != nil)
            {
                CFStringRef mainSource = CFURLCopyFileSystemPath(CCFileGetFileURL(file), kCFURLPOSIXPathStyle);
                if(mainSource != nil && outMainSource != nil)
                {
                    *outMainSource = mainSource;
                }
            }
            
            CFArrayRef diagnostics = CCASTUnitCopyDiagnostics(ASTUnit);
            if(diagnostics)
            {
                *outDiagnostic = diagnostics;
            }
            
            Boolean didErrorOccur = CCASTUnitErrorOccured(ASTUnit);
            
            CFRelease(ASTUnit);
            
            return !didErrorOccur;
        }
        case kCCJobTypeSwiftCompiler:
        {
            return CCSwiftCompilerJobExecute(job, outDiagnostic, outMainSource);
        }
        case kCCJobTypeLinker:
        {
            if(outMainSource != nil)
            {
                *outMainSource = CFSTR("linker");
            }
            return CCLinkerJobExecute(job, outDiagnostic);
        }
        case kCCJobTypeUnknown:
            /* fallthrough */
        default:
            return false;
    }
}

Boolean CCJobTypeSupportsMultithreading(CCJobType type)
{
    /* TODO: implement multithreading support for the swift compiler */
    return (type == kCCJobTypeCompiler);
}
