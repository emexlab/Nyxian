/*
 SPDX-License-Identifier: LicenseRef-EPSL-1.1

 Copyright (C) 2025 - 2026 emexlab

 This file is part of Nyxian.

 Licensed under the emexLabs Public Source License, version 1.1
 (EPSL 1.1).

 Private use and modification are permitted under the license.
 Redistribution of source or binaries, modified or unmodified,
 requires prior written permission from emexLabs.

 External deployment is subject to the source-availability
 requirements and other conditions of the license.

 Provided "AS IS", without warranty, to the extent permitted by law.

 See LICENSE for the full license terms.
*/

#import <Foundation/Foundation.h>
#import <LindChain/Utils/Swizzle.h>
#import <LindChain/Private/UIKitPrivate.h>
#import <Frameworks/LiveProcessLegacy/LindChain/Services/bootstrapd/LDEApplicationWorkspace.h>
#import <Frameworks/LiveProcessLegacy/LindChain/Services/bootstrapd/ISIcon.h>
#import <LindChain/Utils/IconUtils.h>

/* WIP TO A HUGE EXTEND! */

@interface _LSDiskUsage : NSObject
@property (readonly, nullable, nonatomic) NSNumber *staticUsage;
@property (readonly, nullable, nonatomic) NSNumber *dynamicUsage;
@property (readonly, nullable, nonatomic) NSNumber *onDemandResourcesUsage;
@property (readonly, nullable, nonatomic) NSNumber *sharedUsage;
@end

@interface LDEApplicationProxy : NSObject

@property (nonatomic, readonly) LDEApplicationObject *applicationObject;
@property (nonatomic, readonly) NSNumber *ODRDiskUsage;
@property (nonatomic, readonly) NSArray *UIBackgroundModes;
@property (nonatomic, readonly) NSArray *VPNPlugins;
@property (nonatomic, readonly) NSArray *activityTypes;
@property (getter=isAdHocCodeSigned, nonatomic, readonly) bool adHocCodeSigned;
@property (nonatomic, readonly) NSString *appIDPrefix;
@property (nonatomic, readonly) id appState;
@property (nonatomic, readonly) NSString *appStoreToolsBuildVersion;
@property (getter=isAppStoreVendable, nonatomic, readonly) bool appStoreVendable;
@property (nonatomic, readonly) NSArray *appTags;
@property (getter=isAppUpdate, nonatomic, readonly) bool appUpdate;
@property (nonatomic, readonly) NSString *applicationDSID;
@property (nonatomic, readonly) NSString *applicationIdentifier;
@property (nonatomic, readonly) NSString *applicationType;
@property (nonatomic, readonly) NSString *applicationVariant;
@property (getter=isArcadeApp, nonatomic, readonly) bool arcadeApp;
@property (nonatomic, readonly) NSArray *audioComponents;
@property (nonatomic, readonly) NSArray *backgroundTaskSchedulerPermittedIdentifiers;
@property (getter=isBetaApp, nonatomic, readonly) bool betaApp;
@property (nonatomic, readonly) NSNumber *betaExternalVersionIdentifier;
@property (nonatomic, readonly) int bundleModTime;
@property (nonatomic, readonly) bool canHandleWebAuthentication;
@property (nonatomic, readonly) NSArray *carPlayInstrumentClusterURLSchemes;
@property (nonatomic, readonly) NSSet *claimedDocumentContentTypes;
@property (nonatomic, readonly) NSSet *claimedURLSchemes;
@property (nonatomic, readonly) NSString *companionApplicationIdentifier;
@property (nonatomic, readonly) NSString *complicationPrincipalClass;
@property (nonatomic, readonly) id correspondingApplicationRecord;
@property (nonatomic, readonly) NSArray *counterpartIdentifiers;
@property (nonatomic, readonly) id cslprf_safeCorrespondingApplicationRecord;
@property (readonly, copy) NSString *debugDescription; /* unknown property attribute: ? */
@property (getter=isDeletable, nonatomic, readonly) bool deletable;
@property (readonly, copy) NSString *description;
@property (getter=isDeviceBasedVPP, nonatomic, readonly) bool deviceBasedVPP;
@property (nonatomic, readonly) NSArray *deviceFamily;
@property (nonatomic, readonly) NSUUID *deviceIdentifierForAdvertising;
@property (nonatomic, readonly) NSUUID *deviceIdentifierForVendor;
@property (nonatomic, readonly) long long deviceManagementPolicy;
@property (nonatomic, readonly) NSArray *directionsModes;
@property (nonatomic, readonly) id diskUsage;
@property (nonatomic, readonly) NSNumber *downloaderDSID;
@property (nonatomic, readonly) NSNumber *dynamicDiskUsage;
@property (nonatomic, readonly) NSArray *externalAccessoryProtocols;
@property (nonatomic, readonly) NSNumber *externalVersionIdentifier;
@property (nonatomic, readonly) NSNumber *familyID;
@property (nonatomic, readonly) bool fileSharingEnabled;
@property (getter=isGameCenterEnabled, nonatomic, readonly) bool gameCenterEnabled;
@property (nonatomic, readonly) bool gameCenterEverEnabled;
@property (nonatomic, readonly) NSString *genre;
@property (nonatomic, readonly) NSNumber *genreID;
@property (nonatomic, readonly) bool hasComplication;
@property (nonatomic, readonly) bool hasCustomNotification;
@property (nonatomic, readonly) bool hasGlance;
@property (nonatomic, readonly) bool hasMIDBasedSINF;
@property (nonatomic, readonly) bool hasParallelPlaceholder;
@property (nonatomic, readonly) bool hasSettingsBundle;
@property (readonly) unsigned long long hash;
@property (nonatomic, readonly) bool hf_isInstalledForLaunching;
@property (nonatomic, readonly) bool iconIsPrerendered;
@property (nonatomic, readonly) bool iconUsesAssetCatalog;
@property (readonly) NSArray *if_userActivityTypes;
@property (nonatomic, readonly) NSNumber *installFailureReason;
@property (nonatomic, readonly) NSProgress *installProgress;
@property (nonatomic, readonly) unsigned long long installType;
@property (getter=isInstalled, nonatomic, readonly) bool installed;
@property (nonatomic, readonly) NSNumber *itemID;
@property (nonatomic, readonly) NSString *itemName;
@property (getter=isLaunchProhibited, nonatomic, readonly) bool launchProhibited;
@property (nonatomic, readonly) NSArray *managedPersonas;
@property (nonatomic, readonly) NSString *maximumSystemVersion;
@property (nonatomic, readonly) NSString *minimumSystemVersion;
@property (nonatomic, readonly) bool missingRequiredSINF;
@property (getter=isNewsstandApp, nonatomic, readonly) bool newsstandApp;
@property (nonatomic, readonly) unsigned long long originalInstallType;
@property (getter=isPlaceholder, nonatomic, readonly) bool placeholder;
@property (nonatomic, readonly) NSNumber *platform;
@property (nonatomic, readonly) NSArray *plugInKitPlugins;
@property (nonatomic, readonly) NSString *preferredArchitecture;
@property (getter=isPurchasedReDownload, nonatomic, readonly) bool purchasedReDownload;
@property (nonatomic, readonly) NSNumber *purchaserDSID;
@property (nonatomic, readonly) NSString *ratingLabel;
@property (nonatomic, readonly) NSNumber *ratingRank;
@property (nonatomic, readonly) NSDate *registeredDate;
@property (getter=isRemoveableSystemApp, nonatomic, readonly) bool removeableSystemApp;
@property (getter=isRemovedSystemApp, nonatomic, readonly) bool removedSystemApp;
@property (nonatomic, readonly) NSArray *requiredDeviceCapabilities;
@property (getter=isRestricted, nonatomic, readonly) bool restricted;
@property (nonatomic, readonly) bool runsIndependentlyOfCompanionApp;
@property (nonatomic, readonly) NSString *shortVersionString;
@property (nonatomic, readonly) bool shouldSkipWatchAppInstall;
@property (nonatomic, readonly) NSDictionary *siriActionDefinitionURLs;
@property (nonatomic, readonly) NSString *sourceAppIdentifier;
@property (getter=isStandaloneWatchApp, nonatomic, readonly) bool standaloneWatchApp;
@property (nonatomic, readonly) NSNumber *staticDiskUsage;
@property (nonatomic, readonly) NSArray *staticShortcutItems;
@property (nonatomic, readonly) NSString *storeCohortMetadata;
@property (nonatomic, readonly) NSNumber *storeFront;
@property (nonatomic, readonly) NSArray *subgenres;
@property (nonatomic, readonly) NSArray *supportedComplicationFamilies;
@property (nonatomic, readonly) bool supportsAlternateIconNames;
@property (nonatomic, readonly) bool supportsAudiobooks;
@property (nonatomic, readonly) bool supportsExternallyPlayableContent;
@property (nonatomic, readonly) bool supportsMultiwindow;
@property (nonatomic, readonly) bool supportsODR;
@property (nonatomic, readonly) bool supportsOpenInPlace;
@property (nonatomic, readonly) bool supportsPurgeableLocalStorage;
@property (nonatomic, readonly) NSString *teamID;
@property (nonatomic) bool userInitiatedUninstall;
@property (nonatomic, readonly) NSString *vendorName;
@property (getter=isWatchKitApp, nonatomic, readonly) bool watchKitApp;
@property (nonatomic, readonly) NSString *watchKitVersion;
@property (getter=isWhitelisted, nonatomic, readonly) bool whitelisted;

+ (id)applicationProxyForLDEObject:(LDEApplicationObject*)object;
+ (bool)supportsSecureCoding;

- (id)ODRDiskUsage;
- (bool)UPPValidated;
- (id)_localizedNameWithPreferredLocalizations:(id)arg1 useShortNameOnly:(bool)arg2;
- (id)_managedPersonas;
- (id)_stringLocalizerForTable:(id)arg1;
- (bool)_usesSystemPersona;
- (id)activityTypes;
- (id)alternateIconName;
- (id)appIDPrefix;
- (id)appState;
- (id)applicationDSID;
- (id)applicationIdentifier;
- (id)applicationType;
- (id)applicationVariant;
- (id)betaExternalVersionIdentifier;
- (int)bundleModTime;
- (id)bundleType;
- (id)claimedDocumentContentTypes;
- (id)claimedURLSchemes;
- (void)clearAdvertisingIdentifier;
- (id)companionApplicationIdentifier;
- (id)complicationPrincipalClass;
- (id)correspondingApplicationRecord;
- (id)dataContainerURL;
- (id)description;
- (void)detach;
- (id)deviceFamily;
- (long long)deviceManagementPolicy;
- (id)downloaderDSID;
- (id)dynamicDiskUsage;
- (void)encodeWithCoder:(id)arg1;
- (id)environmentVariables;
- (id)externalVersionIdentifier;
- (id)familyID;
- (bool)fileSharingEnabled;
- (id)forwardingTargetForSelector:(SEL)arg1;
- (bool)freeProfileValidated;
- (bool)gameCenterEverEnabled;
- (id)genre;
- (id)genreID;
- (id)getBundleMetadata;
- (void)getDeviceManagementPolicyWithCompletionHandler:(id /* block */)arg1;
- (bool)getGenericTranslocationTargetURL:(id*)arg1 error:(id*)arg2;
- (id)groupContainerURLs;
- (id)handlerRankOfClaimForContentType:(id)arg1;
- (bool)hasMIDBasedSINF;
- (id)iconDataForVariant:(int)arg1;
- (id)iconDataForVariant:(int)arg1 withOptions:(int)arg2;
- (bool)iconIsPrerendered;
- (bool)iconUsesAssetCatalog;
- (id)initWithCoder:(id)arg1;
- (id)installFailureReason;
- (id)installProgress;
- (id)installProgressSync;
- (unsigned long long)installType;
- (bool)isAppUpdate;
- (bool)isBetaApp;
- (bool)isDeletableIgnoringRestrictions;
- (bool)isDeviceBasedVPP;
- (bool)isGameCenterEnabled;
- (bool)isInstalled;
- (bool)isNewsstandApp;
- (bool)isPlaceholder;
- (bool)isPurchasedReDownload;
- (bool)isRemoveableSystemApp;
- (bool)isRemovedSystemApp;
- (bool)isRestricted;
- (bool)isStandaloneWatchApp;
- (bool)isWatchKitApp;
- (bool)isWhitelisted;
- (id)itemID;
- (id)itemName;
- (id)localizedNameForContext:(id)arg1;
- (id)localizedNameForContext:(id)arg1 preferredLocalizations:(id)arg2;
- (id)localizedNameForContext:(id)arg1 preferredLocalizations:(id)arg2 useShortNameOnly:(bool)arg3;
- (id)managedPersonas;
- (id)methodSignatureForSelector:(SEL)arg1;
- (bool)missingRequiredSINF;
- (unsigned long long)originalInstallType;
- (id)platform;
- (id)plugInKitPlugins;
- (id)preferredArchitecture;
- (id)primaryIconDataForVariant:(int)arg1;
- (bool)profileValidated;
- (id)purchaserDSID;
- (id)ratingLabel;
- (id)ratingRank;
- (id)registeredDate;
- (id)requiredDeviceCapabilities;
- (bool)respondsToSelector:(SEL)arg1;
- (void)setAlternateIconName:(id)arg1 withResult:(id /* block */)arg2;
- (void)setUserInitiatedUninstall:(bool)arg1;
- (id)signerIdentity;
- (id)signerOrganization;
- (id)siriActionDefinitionURLs;
- (id)sourceAppIdentifier;
- (id)staticDiskUsage;
- (id)storeCohortMetadata;
- (id)storeFront;
- (id)subgenres;
- (bool)supportsODR;
- (id)teamID;
- (bool)userInitiatedUninstall;
- (id)valueForUndefinedKey:(id)arg1;
- (id)vendorName;

@end

@implementation LDEApplicationProxy

/* inits */
+ (id)applicationProxyForLDEObject:(LDEApplicationObject*)object
{
    LDEApplicationProxy *applicationProxy = [[LDEApplicationProxy alloc] init];
    if(self)
    {
        applicationProxy->_applicationObject = object;
    }
    return applicationProxy;
}

- (id)ODRDiskUsage
{
    return nil;
}

- (bool)UPPValidated
{
    return YES;
}

- (id)_localizedNameWithPreferredLocalizations:(id)arg1
                              useShortNameOnly:(bool)arg2
{
    return _applicationObject.localizedName;
}

- (id)_managedPersonas
{
    return nil;
}

- (id)_stringLocalizerForTable:(id)arg1
{
    return nil;
}

- (NSString*)localizedName
{
    return _applicationObject.localizedName;
}

- (NSArray<NSURL*>*)groupContainerURLs
{
    /* this is a test, remove if not needed */
    return @[];
}

- (id)dataContainerURL
{
    return [NSURL fileURLWithPath:_applicationObject.containerPath];
}

- (bool)isInstalled
{
    return YES;
}

- (bool)_usesSystemPersona
{
    return NO;
}

- (id)activityTypes
{
    return nil;
}

- (id)alternateIconName
{
    return nil;
}

- (id)appIDPrefix
{
    return nil;
}

- (id)appState
{
    return nil;
}

- (id)applicationDSID
{
    return nil;
}


- (id)applicationIdentifier
{
    return _applicationObject.bundleIdentifier;
}

- (id)applicationType
{
    return @"User";
}

- (id)applicationVariant
{
    return nil;
}

- (id)betaExternalVersionIdentifier
{
    return nil;
}

- (int)bundleModTime
{
    return 0;
}

- (id)bundleType
{
    return nil;
}

- (id)claimedDocumentContentTypes
{
    return nil;
}

- (id)claimedURLSchemes
{
    return [NSSet set];
}

- (void)clearAdvertisingIdentifier
{
    return;
}

- (id)companionApplicationIdentifier
{
    return nil;
}

- (id)complicationPrincipalClass
{
    return nil;
}

- (id)correspondingApplicationRecord
{
    return nil;
}

- (id)description
{
    return nil;
}

- (void)detach
{
    return;
}

- (id)deviceFamily
{
    return nil;
}

- (long long)deviceManagementPolicy
{
    return 0;
}

- (id)downloaderDSID
{
    return nil;
}

- (id)dynamicDiskUsage
{
    return nil;
}

- (id)environmentVariables
{
    return @{};
}

- (id)externalVersionIdentifier
{
    return nil;
}

- (id)familyID
{
    return nil;
}

- (bool)fileSharingEnabled
{
    return false;
}

- (bool)freeProfileValidated
{
    return false;
}

- (bool)gameCenterEverEnabled
{
    return false;
}

- (id)genre
{
    return nil;
}

- (id)genreID
{
    return nil;
}

- (id)getBundleMetadata
{
    return nil;
}

- (void)getDeviceManagementPolicyWithCompletionHandler:(id)arg1
{
    
}

- (bool)getGenericTranslocationTargetURL:(id*)arg1 error:(id*)arg2
{
    return false;
}

- (bool)isBetaApp
{
    return false;
}

- (bool)isDeletable
{
    return true;
}

- (bool)isRestricted
{
    return false;
}

- (bool)isContainerized
{
    return true;
}

- (bool)isAdHocCodeSigned
{
    return false;
}

- (bool)isAppStoreVendable
{
    return false;
}

- (bool)isLaunchProhibited
{
    return !_applicationObject.isLaunchAllowed;
}

- (NSString*)teamID
{
    return @"";
}

- (NSString*)sdkVersion
{
    return _applicationObject.sdkVersion;
}

- (NSDictionary<NSString*,id<NSCoding>>*)entitlements
{
    return _applicationObject.entitlements;
}

- (NSURL*)bundleContainerURL
{
    return [NSURL fileURLWithPath:_applicationObject.bundlePath];
}

- (_LSDiskUsage*)diskUsage
{
    NSLog(@"wants diskUsage!\n");
    return nil;
}

- (NSDate*)registeredDate
{
    return [NSDate now];
}

- (NSString*)vendorName
{
    return @"";
}

- (NSString*)minimumSystemVersion
{
    return _applicationObject.minimumSystemVersion;
}

- (NSURL*)bundleURL
{
    return [NSURL fileURLWithPath:_applicationObject.bundlePath];
}

- (NSURL*)containerURL
{
    return [NSURL fileURLWithPath:_applicationObject.containerPath];
}

- (NSData *)iconDataForVariant:(int)variant
{
    UIImage *icon = _applicationObject.icon;
    return UIImagePNGRepresentation(icon);
}

- (NSData *)iconDataForVariant:(int)variant
                   withOptions:(int)options
{
    return [self iconDataForVariant:variant];
}

- (NSString*)bundleVersion
{
    return _applicationObject.bundleVersion;
}

- (NSString*)shortVersionString
{
    return _applicationObject.shortVersionString;
}

- (NSDictionary*)iconsDictionary
{
    return _applicationObject.iconDictionary;
}

- (id)handlerRankOfClaimForContentType:(id)arg1
{
    return nil;
}

- (bool)hasMIDBasedSINF
{
    return false;
}

- (bool)iconIsPrerendered
{
    return _applicationObject.icon == nil;
}

- (bool)iconUsesAssetCatalog
{
    return false;   /* FIXME: properly check for it in LDEApplicationObject */
}

- (id)installFailureReason
{
    return nil; /* no reason */
}

- (id)installProgress
{
    return nil; /* no progress */
}

- (id)installProgressSync
{
    return nil;
}

- (unsigned long long)installType
{
    return 0;
}

- (bool)isAppUpdate
{
    return false;
}

- (bool)isDeletableIgnoringRestrictions
{
    return false;
}

/*
- (bool)isGameCenterEnabled;
- (bool)isNewsstandApp;
- (bool)isPlaceholder;
- (bool)isPurchasedReDownload;
- (bool)isRemoveableSystemApp;
- (bool)isRemovedSystemApp;
- (bool)isRestricted;
- (bool)isStandaloneWatchApp;
- (bool)isWatchKitApp;
- (bool)isWhitelisted;
- (id)itemID;
- (id)itemName;
- (id)localizedNameForContext:(id)arg1;
- (id)localizedNameForContext:(id)arg1 preferredLocalizations:(id)arg2;
- (id)localizedNameForContext:(id)arg1 preferredLocalizations:(id)arg2 useShortNameOnly:(bool)arg3;
- (id)managedPersonas;
- (id)methodSignatureForSelector:(SEL)arg1;
- (bool)missingRequiredSINF;
- (unsigned long long)originalInstallType;
- (id)platform;
- (id)plugInKitPlugins;
- (id)preferredArchitecture;
- (id)primaryIconDataForVariant:(int)arg1;
- (bool)profileValidated;
- (id)purchaserDSID;
- (id)ratingLabel;
- (id)ratingRank;
- (id)registeredDate;
- (id)requiredDeviceCapabilities;
- (bool)respondsToSelector:(SEL)arg1;
- (void)setAlternateIconName:(id)arg1 withResult:(id)arg2;
- (void)setUserInitiatedUninstall:(bool)arg1;
- (id)signerIdentity;
- (id)signerOrganization;
- (id)siriActionDefinitionURLs;
- (id)sourceAppIdentifier;
- (id)staticDiskUsage;
- (id)storeCohortMetadata;
- (id)storeFront;
- (id)subgenres;
- (bool)supportsODR;
- (bool)userInitiatedUninstall;
- (id)valueForUndefinedKey:(id)arg1;
- (id)vendorName;
 */

- (BOOL)isKindOfClass:(Class)cls
{
   if(cls == PrivClass(LSApplicationProxy))
   {
       return YES;
   }
   return [super isKindOfClass:cls];
}

- (Class)class
{
    return PrivClass(LSApplicationProxy);
}

- (NSMethodSignature *)methodSignatureForSelector:(SEL)sel
{
    NSMethodSignature *sig = [super methodSignatureForSelector:sel];
    if(sig)
    {
        return sig;
    }
    return [PrivClass(LSApplicationProxy) instanceMethodSignatureForSelector:sel];
}

- (void)forwardInvocation:(NSInvocation *)inv
{
    SEL sel = inv.selector;
    static NSMutableSet *seen;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ seen = [NSMutableSet set]; });
    NSString *name = NSStringFromSelector(sel);
    @synchronized(seen)
    {
        if(![seen containsObject:name])
        {
            [seen addObject:name];
        }
    }

    NSUInteger len = inv.methodSignature.methodReturnLength;
    if(len)
    {
        void *buf = calloc(1, len);
        [inv setReturnValue:buf];
        free(buf);
    }
}

- (BOOL)respondsToSelector:(SEL)sel
{
    if([super respondsToSelector:sel])
    {
        return YES;
    }
    return [PrivClass(LSApplicationProxy) instancesRespondToSelector:sel];
}

@end

@interface LSApplicationWorkspaceHooks: NSObject
@end

@implementation LSApplicationWorkspaceHooks {
    
}

+ (void)load
{
    [super load];
    
    SwizzleObjCMethod(@selector(defaultWorkspace), PrivClass(LSApplicationWorkspace), @selector(hook_defaultWorkspace), [LSApplicationWorkspaceHooks class], kSwizzleMethodTypeClass);
}

+ (instancetype)hook_defaultWorkspace
{
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        SwizzleObjCMethod(@selector(allApplications), PrivClass(LSApplicationWorkspace), @selector(hook_allApplications), [LSApplicationWorkspaceHooks class], kSwizzleMethodTypeInstance);
        SwizzleObjCMethod(@selector(allInstalledApplications), PrivClass(LSApplicationWorkspace), @selector(hook_allInstalledApplications), [LSApplicationWorkspaceHooks class], kSwizzleMethodTypeInstance);
        SwizzleObjCMethod(@selector(uninstallApplication:withOptions:error:usingBlock:), PrivClass(LSApplicationWorkspace), @selector(hook_uninstallApplication:withOptions:error:usingBlock:), [LSApplicationWorkspaceHooks class], kSwizzleMethodTypeInstance);
        SwizzleObjCMethod(@selector(openApplicationWithBundleID:), PrivClass(LSApplicationWorkspace), @selector(hook_openApplicationWithBundleID:), [LSApplicationWorkspaceHooks class], kSwizzleMethodTypeInstance);
        SwizzleObjCMethod(@selector(_applicationIconImageForBundleIdentifier:format:scale:), [UIImage class], @selector(hook_iconForBundleID:format:scale:), [UIImage class], kSwizzleMethodTypeClass);
    });
    return [self hook_defaultWorkspace];
}

+ (NSArray<LDEApplicationProxy*>*)giveAllApps
{
    LDEApplicationWorkspace *workspace = [LDEApplicationWorkspace shared];
    [workspace ping];
    
    NSArray<LDEApplicationObject*> *allApplicationObjects = [workspace allApplicationObjects];
    NSMutableArray<LDEApplicationProxy*> *apps = [NSMutableArray array];
    for(LDEApplicationObject *object in allApplicationObjects)
    {
        LDEApplicationProxy *proxy = [LDEApplicationProxy applicationProxyForLDEObject:object];
        [apps addObject:proxy];
    }
    
    return apps;
}

- (NSArray<LDEApplicationProxy*>*)hook_allApplications
{
    return [LSApplicationWorkspaceHooks giveAllApps];
}

- (NSArray<LDEApplicationProxy*>*)hook_allInstalledApplications
{
    return [LSApplicationWorkspaceHooks giveAllApps];
}

- (BOOL)hook_uninstallApplication:(NSString *)bundleID
                      withOptions:(NSDictionary<NSString *, id> *_Nullable)arg1
                            error:(NSError **)arg2
                       usingBlock:(_Nullable id)arg3 __attribute__((swift_error(nonnull_error)))
{
    return [[LDEApplicationWorkspace shared] deleteApplicationWithBundleID:bundleID];
}

- (BOOL)hook_openApplicationWithBundleID:(NSString*)bundleIdentifier
{
    return [[LDEApplicationWorkspace shared] openApplicationWithBundleID:bundleIdentifier];
}

@end

@implementation UIImage (PrivateHook)

+ (UIImage *)hook_iconForBundleID:(NSString *)bundleIdentifier
                           format:(int)format
                            scale:(CGFloat)scale
{
    LDEApplicationObject *obj = [[LDEApplicationWorkspace shared] applicationObjectForBundleID:bundleIdentifier];
    if(obj && obj.icon)
    {
        CGSize targetSize;
        {
            static NSMutableDictionary<NSString *, NSValue *> *sizeCache;
            static dispatch_once_t once;
            dispatch_once(&once, ^{
                sizeCache = [NSMutableDictionary new];
            });
            
            NSString *key = [NSString stringWithFormat:@"%d@%.1f", format, scale];
            @synchronized(sizeCache)
            {
                NSValue *found = sizeCache[key];
                if(found)
                {
                    targetSize = found.CGSizeValue;
                    goto got_size;
                }
            }
            
            /* dw apple tells us what their size and scale is dw ^^ */
            UIImage *probe = [self hook_iconForBundleID:@"com.apple.Preferences" format:format scale:scale];
            targetSize = probe ? probe.size : CGSizeMake(60, 60);
            
            @synchronized(sizeCache)
            {
                sizeCache[key] = [NSValue valueWithCGSize:targetSize];
            }
        }
    got_size:
        {
            if(@available(iOS 26.0, *))
            {
                /* the asking apple way */
                UIImage *image = Gib26Icon(obj.icon, obj.darkIcon, targetSize, scale);
                if(image == nil)
                {
                    goto manual_way;
                }
                return image;
            }
            
        manual_way:
            {
                /* the doing it my self way */
                CGRect r = (CGRect){ .origin = CGPointZero, .size = targetSize };
                UIBezierPath *mask = [UIBezierPath bezierPathWithRoundedRect:r cornerRadius:targetSize.width * 0.2237];
                UIGraphicsImageRendererFormat *fmt = [UIGraphicsImageRendererFormat defaultFormat];
                fmt.scale = scale;
                UIGraphicsImageRenderer *rr = [[UIGraphicsImageRenderer alloc] initWithSize:targetSize format:fmt];
                UIImage *curvedImage = [rr imageWithActions:^(UIGraphicsImageRendererContext *ctx){
                    [mask addClip];
                    [obj.icon drawInRect:r];
                }];
                return curvedImage;
            }
        }
    }
    return [self hook_iconForBundleID:bundleIdentifier format:format scale:scale];
}

@end
