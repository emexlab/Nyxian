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

#ifndef CCDRIVER_H
#define CCDRIVER_H

#include <CoreCompiler/CCBase.h>
#include <CoreCompiler/CCJob.h>
#include <CoreCompiler/CCSDK.h>

typedef CF_ENUM(UInt8, CCDriverType) {
    kCCDriverTypeClang = 0,
    kCCDriverTypeSwift,
};

typedef struct __CCDriver *CCDriverRef;
typedef CFStringRef (*CCOutputPathCallback)(const char *baseInput, bool *skip, void *context);

CC_EXPORT CFTypeID CCDriverGetTypeID(void);

CC_EXPORT CCDriverRef CCDriverCreate(CFAllocatorRef allocator, CFArrayRef arguments, CCDriverType type);

CC_EXPORT CCDriverType CCDriverGetType(CCDriverRef driver);

CC_EXPORT CFArrayRef CCDriverCreateJobs(CFAllocatorRef allocator, CCDriverRef driver);

CC_EXPORT void CCDriverSetOutputPathCallback(CCDriverRef driver, CCOutputPathCallback callback, void *context);
CC_EXPORT void *CCDriverGetOutputPathCallbackContext(CCDriverRef driver);

CC_EXPORT CFURLRef CCDriverCopySysrootURL(CCDriverRef driver);
CC_EXPORT CCSDKRef CCDriverCopySDK(CCDriverRef driver);

#endif /* CCDRIVER_H */
