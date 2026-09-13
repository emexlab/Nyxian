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

#ifndef CCJOB_H
#define CCJOB_H

#include <CoreCompiler/CCBase.h>
#include <CoreCompiler/CCDiagnostic.h>

typedef CF_ENUM(UInt8, CCJobType) {
    kCCJobTypeCompiler = 0,
    kCCJobTypeDriver,
    kCCJobTypeSwiftCompiler,
    kCCJobTypeSwiftDriver,
    kCCJobTypeLinker,
    kCCJobTypeUnknown
};

typedef struct __CCJob *CCJobRef;

CC_EXPORT CFTypeID CCJobGetTypeID(void);

CC_EXPORT CCJobRef CCJobCreate(CFAllocatorRef allocator, CCJobType type, CFArrayRef CC1Arguments, CFArrayRef inputFileURLs, CFURLRef outputFileURL);

CC_EXPORT CCJobType CCJobGetType(CCJobRef job);
CC_EXPORT CFArrayRef CCJobGetBaseArguments(CCJobRef job);
CC_EXPORT CFArrayRef CCJobGetInputFileURLs(CCJobRef job);
CC_EXPORT CFURLRef CCJobGetOutputFileURL(CCJobRef job);

CC_EXPORT CFArrayRef CCJobCreateArguments(CFAllocatorRef allocator, CCJobRef job);

CC_EXPORT Boolean CCJobExecuteJob(CCJobRef job, CFArrayRef *outDiagnostic, CFStringRef *outMainSource);

CC_EXPORT Boolean CCJobTypeSupportsMultithreading(CCJobType type);

#endif /* CCJOB_H */
