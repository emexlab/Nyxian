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

#import <MobileDevelopmentKit/MDKJob.h>

@implementation MDKJob

+ (void)load
{
    _CFRuntimeBridgeClasses(CCJobGetTypeID(), "MDKJob");
}

+ (instancetype)jobWithType:(CCJobType)type
              withArguments:(NSArray<NSString*>*)arguments
          withInputFileURLs:(NSArray<NSURL *> *)inputFileURLs
          withOutputFileURL:(NSURL *)outputFileURL
{
    return (__bridge_transfer MDKJob*)CCJobCreate(kCFAllocatorSystemDefault, type, (__bridge CFArrayRef)arguments, (__bridge CFArrayRef)inputFileURLs, (__bridge CFURLRef)outputFileURL);
}

- (CCJobType)type
{
    return CCJobGetType((__bridge void*)self);
}

- (NSArray<NSString*>*)baseArguments
{
    return (__bridge NSArray<NSString*>*)CCJobGetBaseArguments((__bridge CCJobRef)self);
}

- (NSArray<NSURL*>*)inputFileURLs
{
    return (__bridge NSArray<NSURL*>*)CCJobGetInputFileURLs((__bridge CCJobRef)self);
}

- (NSURL*)outputFileURL
{
    return (__bridge NSURL*)CCJobGetOutputFileURL((__bridge CCJobRef)self);
}

- (NSArray<NSString*>*)arguments
{
    return (__bridge_transfer NSArray<NSString*>*)CCJobCreateArguments(kCFAllocatorSystemDefault, (__bridge CCJobRef)self);
}

- (BOOL)executeJobWithOutDiagnostics:(NSArray<MDKDiagnostic*>**)outDiagnostic
                   withOutMainSource:(NSString**)outMainSource
{
    CFArrayRef array = nil;
    CFStringRef string = nil;
    BOOL success = CCJobExecuteJob((__bridge CCJobRef)self, &array, &string);
    
    if(array != nil)
    {
        if(outDiagnostic != nil)
        {
            *outDiagnostic = (__bridge_transfer NSArray<MDKDiagnostic*>*)array;
        }
        else
        {
            CFRelease(array);
        }
    }
    
    if(string != nil)
    {
        if(outMainSource != nil)
        {
            *outMainSource = (__bridge_transfer NSString*)string;
        }
        else
        {
            CFRelease(string);
        }
    }
    
    return success;
}

@end
