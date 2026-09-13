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

#import <MobileDevelopmentKit/MDKPhaseEngine.h>

@interface MDKPhaseEngine ()

@property (nonatomic, readonly) NSArray<NSString*> *otherClangFlags;
@property (nonatomic, readonly) NSArray<NSString*> *otherLinkerFlags;

@end

static MDKJob *MDKPhaseGenerationJobByAppendingArgumentsHelper(MDKJob *job,
                                                               NSArray<NSString*> *arguments)
{
    return [MDKJob jobWithType:job.type withArguments:[job.arguments arrayByAddingObjectsFromArray:arguments]];
}

static void MDKPhaseGenerationEndHelper(MDKPhaseEngine *engine,
                                        CCJobType *type,
                                        NSMutableArray *phases,
                                        NSMutableArray<MDKJob*> *jobs)
{
    switch(*type)
    {
        case kCCJobTypeCompiler:
            [phases addObject:[MDKPhase phaseWithJobs:[jobs copy] withJobType:kCCJobTypeCompiler withMultithreadingSupport:YES]];
            break;
        case kCCJobTypeSwiftCompiler:
        case kCCJobTypeLinker:
            [phases addObject:[MDKPhase phaseWithJobs:[jobs copy] withJobType:*type withMultithreadingSupport:NO]];
            /* fallthrough */
        default:
            break;
    }
    
    /* resetting generation flags and arrays to sentinel */
    [jobs removeAllObjects];
    *type = kCCJobTypeUnknown;
}

static void MDKPhaseGenerationAppendHelper(MDKPhaseEngine *engine,
                                           CCJobType *type,
                                           NSMutableArray *phases,
                                           NSMutableArray<MDKJob*> *jobs,
                                           MDKJob *job)
{
    switch(job.type)
    {
        case kCCJobTypeCompiler:
            if(*type == kCCJobTypeUnknown)
            {
            switch_to_compiler_job:
                *type = kCCJobTypeCompiler;
                [jobs addObject:job];
            }
            else if(*type == kCCJobTypeCompiler)
            {
                [jobs addObject:job];
            }
            else
            {
                MDKPhaseGenerationEndHelper(engine, type, phases, jobs);
                goto switch_to_compiler_job;
            }
            break;
        case kCCJobTypeDriver:
        {
            MDKPhaseGenerationEndHelper(engine, type, phases, jobs);
            
            MDKPhaseEngine *subPhaseEngine = [MDKPhaseEngine engineWithClangFlags:[job.arguments arrayByAddingObjectsFromArray:engine.otherClangFlags] withOtherLinkerFlags:engine.otherLinkerFlags];
            subPhaseEngine.delegate = engine.delegate;
            [phases addObject:subPhaseEngine];
            
            MDKPhaseGenerationEndHelper(engine, type, phases, jobs);
            
            break;
        }
        case kCCJobTypeSwiftCompiler:
            if(*type == kCCJobTypeUnknown)
            {
            switch_to_swift_compiler_job:
                *type = kCCJobTypeSwiftCompiler;
                [jobs addObject:job];
            }
            else if(*type == kCCJobTypeSwiftCompiler)
            {
                [jobs addObject:job];
            }
            else
            {
                MDKPhaseGenerationEndHelper(engine, type, phases, jobs);
                goto switch_to_swift_compiler_job;
            }
            break;
        case kCCJobTypeSwiftDriver:
            break;
        case kCCJobTypeLinker:
            if(*type == kCCJobTypeUnknown)
            {
            switch_to_linker_job:
                *type = kCCJobTypeLinker;
                [jobs addObject:MDKPhaseGenerationJobByAppendingArgumentsHelper(job, engine.otherLinkerFlags)];
            }
            else if(*type == kCCJobTypeLinker)
            {
                [jobs addObject:MDKPhaseGenerationJobByAppendingArgumentsHelper(job, engine.otherLinkerFlags)];
            }
            else
            {
                MDKPhaseGenerationEndHelper(engine, type, phases, jobs);
                goto switch_to_linker_job;
            }
            break;
        default:
            break;
    }
}

@implementation MDKPhaseEngine {
    MDKDriver *_driver;
}

@dynamic delegate;

+ (instancetype)engineWithDriver:(MDKDriver*)driver
             withOtherClangFlags:(NSArray<NSString*>*)clangFlags
            withOtherLinkerFlags:(NSArray<NSString*>*)linkerFlags
{
    MDKPhaseEngine *phaseEngine = super.alloc.init;
    if(phaseEngine)
    {
        phaseEngine->_otherClangFlags = clangFlags;
        phaseEngine->_otherLinkerFlags = linkerFlags;
        phaseEngine->_driver = driver;
    }
    return phaseEngine;
}

+ (instancetype)engineWithClangFlags:(NSArray<NSString*>*)clangFlags
                withOtherLinkerFlags:(NSArray<NSString*>*)linkerFlags
{
    MDKPhaseEngine *phaseEngine = super.alloc.init;
    if(phaseEngine)
    {
        phaseEngine->_otherClangFlags = clangFlags;
        phaseEngine->_otherLinkerFlags = linkerFlags;
        phaseEngine->_driver = [MDKDriver driverWithArguments:clangFlags withType:kCCDriverTypeClang];
    }
    return phaseEngine;
}

+ (instancetype)engineWithSwiftFlags:(NSArray<NSString*>*)swiftFlags
                 withOtherClangFlags:(NSArray<NSString*>*)clangFlags
                withOtherLinkerFlags:(NSArray<NSString*>*)linkerFlags
{
    MDKPhaseEngine *phaseEngine = super.alloc.init;
    if(phaseEngine)
    {
        phaseEngine->_otherClangFlags = clangFlags;
        phaseEngine->_otherLinkerFlags = linkerFlags;
        phaseEngine->_driver = [MDKDriver driverWithArguments:swiftFlags withType:kCCDriverTypeSwift];
    }
    return phaseEngine;
}

- (id<MDKDriverDelegate>)delegate
{
    return _driver.delegate;
}

- (void)setDelegate:(id<MDKDriverDelegate>)delegate
{
    _driver.delegate = delegate;
}

- (NSArray*)generatePhases
{
    NSMutableArray *phases = [NSMutableArray array];
    
    CCJobType currentPhasesType = kCCJobTypeUnknown;
    NSMutableArray<MDKJob*> *currentPhasesJobs = [NSMutableArray array];
    
    NSArray<MDKJob*> *mainDriverJobs = [_driver generateJobs];
    if(mainDriverJobs == nil)
    {
        /* phase creation failed */
        return nil;
    }
    for(MDKJob *job in mainDriverJobs)
    {
        MDKPhaseGenerationAppendHelper(self, &currentPhasesType, phases, currentPhasesJobs, job);
    }
    MDKPhaseGenerationEndHelper(self, &currentPhasesType, phases, currentPhasesJobs);
    
    return phases;
}

@end
