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

#import "LDEApplicationObject.h"
#import "LDEApplicationWorkspaceInternal.h"
#import "ISIcon.h"
#import <LindChain/Private/UIKitPrivate.h>
#import <LindChain/ProcEnvironment/Surface/trust/signing.h>

#import <UIKit/UIKit.h>

@implementation LDEApplicationObject

- (instancetype)initWithNSBundle:(NSBundle*)bundle
{
    self = [super init];
    
    ksurface_nxt2_t result;
    kern_return_t kr = trust_nxt2_read([[bundle executablePath] UTF8String], &result);
    if(kr == KERN_SUCCESS)
    {
        self.entitlements = (__bridge_transfer NSDictionary*)result.entitlements;
    }
    else
    {
        self.entitlements = @{};
    }
    
    self.iconDictionary = [bundle objectForInfoDictionaryKey:@"CFBundleIcons"];
    self.bundleVersion = [bundle objectForInfoDictionaryKey:@"CFBundleVersion"];
    self.shortVersionString = [bundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"]?: self.bundleVersion;
    self.sdkVersion = [bundle objectForInfoDictionaryKey:@"DTPlatformVersion"];
    self.minimumSystemVersion = [bundle objectForInfoDictionaryKey:@"MinimumOSVersion"];
    
    self.supportedInterfaceOrientations = 0;
    NSArray *orientations;
    if(UIDevice.currentDevice.userInterfaceIdiom == UIUserInterfaceIdiomPad)
    {
        orientations = [bundle objectForInfoDictionaryKey:@"UISupportedInterfaceOrientations~ipad"] ?: [bundle objectForInfoDictionaryKey:@"UISupportedInterfaceOrientations"];
    }
    else
    {
        orientations = [bundle objectForInfoDictionaryKey:@"UISupportedInterfaceOrientations"];
    }
    
    for(NSString *orientation in orientations)
    {
        if([orientation isEqualToString:@"UIInterfaceOrientationPortrait"])
        {
            self.supportedInterfaceOrientations |= UIInterfaceOrientationMaskPortrait;
        }
        else if([orientation isEqualToString:@"UIInterfaceOrientationPortraitUpsideDown"])
        {
            self.supportedInterfaceOrientations |= UIInterfaceOrientationMaskPortraitUpsideDown;
        }
        else if([orientation isEqualToString:@"UIInterfaceOrientationLandscapeLeft"])
        {
            self.supportedInterfaceOrientations |= UIInterfaceOrientationMaskLandscapeLeft;
        }
        else if([orientation isEqualToString:@"UIInterfaceOrientationLandscapeRight"])
        {
            self.supportedInterfaceOrientations |= UIInterfaceOrientationMaskLandscapeRight;
        }
    }
    
    self.bundleIdentifier = bundle.bundleIdentifier;
    
    id fullScreen = [bundle objectForInfoDictionaryKey:@"UIRequiresFullScreen"];
    if([fullScreen isKindOfClass:[NSNumber class]])
    {
        self.isFullscreenRequired = [fullScreen boolValue];
    }
    else
    {
        self.isFullscreenRequired = NO;
    }
    
    NSString *localizedDisplayName = [bundle objectForInfoDictionaryKey:@"CFBundleDisplayName"];
    if(!localizedDisplayName)
    {
        localizedDisplayName = [bundle objectForInfoDictionaryKey:@"CFBundleName"];
    }
    self.localizedName = NSLocalizedStringFromTableInBundle(localizedDisplayName, @"InfoPlist", bundle, localizedDisplayName);
#if !HOST_ENV
    self.isLaunchAllowed = [[LDEApplicationWorkspaceInternal shared] doWeTrustThatBundle:bundle];
    if(self.isLaunchAllowed)
    {
        self.bundlePath = [[bundle bundleURL] path];
        self.executablePath = [[bundle executableURL] path];
        self.containerPath = [[[LDEApplicationWorkspaceInternal shared] applicationContainerForBundleID:bundle.bundleIdentifier] path];
    }
#endif /* !HOST_ENV */
    
    ISBundleIcon *bundleIcon = [[PrivClass(ISBundleIcon) alloc] initWithBundleURL:bundle.bundleURL type:nil];
    if(bundleIcon)
    {
        ISResourceProvider *provider = [bundleIcon _makeAppResourceProvider];
        if(provider.isGenericProvider) return self;
        
        ISAssetCatalogResource *resource = [provider iconResource];
        if([resource isKindOfClass:NSClassFromString(@"IFImageBag")])
        {
            /* legacy iOS app icon */
            IFImageBag *imageBag = (IFImageBag*)resource;
            IFImage *image = [imageBag imageForSize:CGSizeMake(1024, 1024) scale:3.0];
            self.icon = [UIImage imageWithCGImage:image.CGImage scale:3.0 orientation:UIImageOrientationUp];
            self.darkIcon = self.icon;  /* it's the same here */
            return self;
        }
        
        IFImage *image = [resource imageForSize:CGSizeMake(1024, 1024) scale:UIScreen.mainScreen.scale];
        self.icon = [UIImage imageWithCGImage:image.CGImage scale:3.0 orientation:UIImageOrientationUp];
        
        if([resource respondsToSelector:@selector(hasDarkResource)] && resource.hasDarkResource)
        {
            resource.appearance = 1;
            IFImage *darkImage = [resource imageForSize:CGSizeMake(1024, 1024) scale:UIScreen.mainScreen.scale];
            self.darkIcon = [UIImage imageWithCGImage:darkImage.CGImage scale:3.0 orientation:UIImageOrientationUp];
        }
        else
        {
            self.darkIcon = self.icon;
        }
    }

    return self;
}

+ (BOOL)supportsSecureCoding {
    return YES;
}

- (void)encodeWithCoder:(nonnull NSCoder *)coder
{
    [coder encodeObject:self.bundleIdentifier forKey:@"bundleIdentifier"];
    [coder encodeObject:self.bundlePath forKey:@"bundlePath"];
    [coder encodeObject:self.executablePath forKey:@"executablePath"];
    [coder encodeObject:self.localizedName forKey:@"localizedName"];
    [coder encodeObject:self.containerPath forKey:@"containerPath"];
    [coder encodeObject:self.icon forKey:@"icon"];
    [coder encodeObject:self.darkIcon forKey:@"darkIcon"];
    [coder encodeObject:self.iconDictionary forKey:@"iconDictionary"];
    [coder encodeObject:self.bundleVersion forKey:@"bundleVersion"];
    [coder encodeObject:self.shortVersionString forKey:@"shortVersionString"];
    [coder encodeObject:self.sdkVersion forKey:@"sdkVersion"];
    [coder encodeObject:self.minimumSystemVersion forKey:@"minimumSystemVersion"];
    [coder encodeObject:self.entitlements forKey:@"entitlements"];
    [coder encodeObject:@(self.supportedInterfaceOrientations) forKey:@"supportedInterfaceOrientations"];
    [coder encodeObject:@(self.isLaunchAllowed) forKey:@"isLaunchAllowed"];
    [coder encodeObject:@(self.isFullscreenRequired) forKey:@"isFullscreenRequired"];
}

- (nullable instancetype)initWithCoder:(nonnull NSCoder *)coder
{
    if(self = [super init])
    {
        _bundleIdentifier = [coder decodeObjectOfClass:[NSString class] forKey:@"bundleIdentifier"];
        _bundlePath = [coder decodeObjectOfClass:[NSString class] forKey:@"bundlePath"];
        _executablePath = [coder decodeObjectOfClass:[NSString class] forKey:@"executablePath"];
        _localizedName = [coder decodeObjectOfClass:[NSString class] forKey:@"localizedName"];
        _containerPath = [coder decodeObjectOfClass:[NSString class] forKey:@"containerPath"];
        _icon = [coder decodeObjectOfClass:[UIImage class] forKey:@"icon"];
        _darkIcon = [coder decodeObjectOfClass:[UIImage class] forKey:@"darkIcon"];
        _iconDictionary = [coder decodeObjectOfClasses:[NSSet setWithArray:@[[NSDictionary class], [NSArray class], [NSString class], [NSNumber class], [NSData class]]] forKey:@"iconDictionary"];
        _bundleVersion = [coder decodeObjectOfClass:[NSString class] forKey:@"bundleVersion"];
        _shortVersionString = [coder decodeObjectOfClass:[NSString class] forKey:@"shortVersionString"];
        _sdkVersion = [coder decodeObjectOfClass:[NSString class] forKey:@"sdkVersion"];
        _minimumSystemVersion = [coder decodeObjectOfClass:[NSString class] forKey:@"minimumSystemVersion"];
        _entitlements = [coder decodeObjectOfClasses:[NSSet setWithArray:@[[NSDictionary class], [NSArray class], [NSString class], [NSNumber class], [NSData class]]] forKey:@"entitlements"];
        _supportedInterfaceOrientations = [[coder decodeObjectOfClass:[NSNumber class] forKey:@"supportedInterfaceOrientations"] unsignedLongValue];
        _isLaunchAllowed = [[coder decodeObjectOfClass:[NSNumber class] forKey:@"isLaunchAllowed"] boolValue];
        _isFullscreenRequired = [[coder decodeObjectOfClass:[NSNumber class] forKey:@"isFullscreenRequired"] boolValue];
    }
    return self;
}

- (BOOL)isEqual:(id)object
{
    if (self == object) return YES;
    if (![object isKindOfClass:[LDEApplicationObject class]]) return NO;
    LDEApplicationObject *other = (LDEApplicationObject *)object;
    return [self.bundleIdentifier isEqualToString:other.bundleIdentifier];
}

- (NSUInteger)hash
{
    return self.bundleIdentifier.hash;
}

@end
