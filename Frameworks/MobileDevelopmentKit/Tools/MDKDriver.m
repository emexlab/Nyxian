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

#import <MobileDevelopmentKit/MDKDriver.h>
#import <CoreCompiler/CCDriver.h>
#import <Block.h>
#import <objc/runtime.h>

static CFStringRef MDKDriverOutputPathBridge(const char *baseInput,
                                             bool *skip,
                                             void *ctx)
{
    MDKDriver *driver = (__bridge MDKDriver*)ctx;
    id<MDKDriverDelegate> delegate = driver.delegate;

    MDKFile *file = [MDKFile fileWithCString:baseInput encoding:NSUTF8StringEncoding];
    if(file == nil)
    {
        /* file creation failure */
        return nil;
    }

    if([delegate respondsToSelector:@selector(driver:skipCompileForInputFile:)])
    {
        *skip = [delegate driver:driver skipCompileForInputFile:file];
    }

    if(![delegate respondsToSelector:@selector(driver:outputPathForInputFile:)])
    {
        return nil;
    }

    NSString *result = [delegate driver:driver outputPathForInputFile:file];
    return (__bridge_retained CFStringRef)result;
}

static const void *MDKDriverDelegateKey = &MDKDriverDelegateKey;

@interface MDKWeakWrapper : NSObject
@property (nonatomic, weak) id<MDKDriverDelegate> delegate;
@end

@implementation MDKWeakWrapper
@end

@implementation MDKDriver

+ (void)load
{
    _CFRuntimeBridgeClasses(CCDriverGetTypeID(), "MDKDriver");
}

+ (instancetype)driverWithArguments:(NSArray<NSString*>*)arguments
                           withType:(CCDriverType)type
{
    return (__bridge_transfer MDKDriver*)CCDriverCreate(kCFAllocatorSystemDefault, (__bridge CFArrayRef)arguments, type);
}

- (NSArray<MDKJob*>*)generateJobs
{
    NSArray<MDKJob*> *jobs = (__bridge_transfer NSArray<MDKJob*>*)CCDriverCreateJobs(kCFAllocatorSystemDefault, (__bridge CCDriverRef)self);
    if(jobs == nil)
    {
        return nil;
    }
    
    MDKWeakWrapper *wrapper = objc_getAssociatedObject(self, MDKDriverDelegateKey);
    if([wrapper.delegate respondsToSelector:@selector(driver:editJobListForJobList:)])
    {
        jobs = [wrapper.delegate driver:self editJobListForJobList:jobs];
        if(jobs == nil)
        {
            return nil;
        }
    }
    
    return jobs;
}

- (NSURL*)sysrootURL
{
    return (__bridge_transfer NSURL*)CCDriverCopySysrootURL((__bridge CCDriverRef)self);
}

- (MDKSDK*)sdk
{
    return (__bridge_transfer MDKSDK*)CCDriverCopySDK((__bridge CCDriverRef)self);
}

- (CCDriverType)type
{
    return CCDriverGetType((__bridge CCDriverRef)self);
}

- (void)setDelegate:(id<MDKDriverDelegate>)delegate
{
    MDKWeakWrapper *wrapper = nil;
    
    if(delegate)
    {
        wrapper = [MDKWeakWrapper new];
        wrapper.delegate = delegate;
    }
    
    objc_setAssociatedObject(self, MDKDriverDelegateKey, wrapper, OBJC_ASSOCIATION_RETAIN);
    
    if(!delegate)
    {
        CCDriverSetOutputPathCallback((__bridge CCDriverRef)self, nil, nil);
        return;
    }
    
    CCDriverSetOutputPathCallback((__bridge CCDriverRef)self, MDKDriverOutputPathBridge, (__bridge void*)self);
}

- (id<MDKDriverDelegate>)delegate
{
    MDKWeakWrapper *wrapper = objc_getAssociatedObject(self, MDKDriverDelegateKey);
    return wrapper.delegate;
}

- (void)dealloc
{
    self.delegate = nil;
}

@end
