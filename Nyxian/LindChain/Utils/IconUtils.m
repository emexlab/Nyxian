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

#import <UIKit/UIKit.h>
#import <Frameworks/LiveProcessLegacy/LindChain/Services/bootstrapd/ISIcon.h>
#import <LindChain/Utils/IconUtils.h>
#import <LindChain/Private/UIKitPrivate.h>

static ISImageDescriptor *ISIDescriptorFor(CGSize size,
                                           CGFloat scale,
                                           BOOL darkMode)
{
    static NSMutableDictionary *cache;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ cache = [NSMutableDictionary new]; });

    NSString *key = [NSString stringWithFormat:@"%.1fx%.1f@%.1f.%@", size.width, size.height, scale, @(darkMode)];
    @synchronized(cache)
    {
        ISImageDescriptor *descriptor = cache[key];
        if(!descriptor)
        {
            descriptor = [[PrivClass(ISImageDescriptor) alloc] initWithSize:size scale:scale];
            descriptor.shape = 1;
            descriptor.appearance = darkMode ? ISImageDescriptorApparanceDarkMode : ISImageDescriptorApparanceLightMode;
            descriptor.appearanceVariant = ISImageDescriptorApparanceVariantDefault;
            descriptor.shouldApplyMask = YES;
            descriptor.drawBorder = YES;
            cache[key] = descriptor;
        }
        return descriptor;
    }
}

UIImage *Gib26Icon(UIImage *rawLightIcon,
                   UIImage *rawDarkIcon,
                   CGSize size,
                   CGFloat scale)
{
    if(!rawLightIcon.CGImage || !rawDarkIcon.CGImage)
    {
        return nil;
    }
    
    /* like black and white hole from the universe x3 (white hole, black hole, tight ...) */
    IFImage *lightSource = [[PrivClass(IFImage) alloc] initWithCGImage:rawLightIcon.CGImage scale:rawLightIcon.scale];  /* like from my flashlight */
    IFImage *darkSource = [[PrivClass(IFImage) alloc] initWithCGImage:rawDarkIcon.CGImage scale:rawDarkIcon.scale];
    if(!lightSource || !darkSource)
    {
        return nil;
    }
    
    ISIcon *lightIcon = [[PrivClass(ISIcon) alloc] initWithImages:@[lightSource]];
    ISIcon *darkIcon = [[PrivClass(ISIcon) alloc] initWithImages:@[darkSource]];
    if(!lightIcon || !darkIcon)
    {
        return nil;
    }
    
    /* more research is needed on how apple applies the format :c */
    ISImageDescriptor *descriptor = ISIDescriptorFor(size, scale, NO);
    
    /* apperently what apple uses */
    IFImage *lightRendered = [lightIcon prepareImageForDescriptor:descriptor];
    IFImage *darkRendered = [darkIcon prepareImageForDescriptor:descriptor];
    if(!lightRendered || !lightRendered.CGImage ||
       !darkRendered || !darkRendered.CGImage)
    {
        return nil;
    }
    
    UIImage *lightImage = [UIImage imageWithCGImage:lightRendered.CGImage scale:scale orientation:UIImageOrientationUp];
    UIImage *darkImage = [UIImage imageWithCGImage:darkRendered.CGImage scale:scale orientation:UIImageOrientationUp];
    
    UIImageAsset *asset = [[UIImageAsset alloc] init];
    
    UITraitCollection *lightTraits = [UITraitCollection traitCollectionWithUserInterfaceStyle:UIUserInterfaceStyleLight];
    UITraitCollection *darkTraits = [UITraitCollection traitCollectionWithUserInterfaceStyle:UIUserInterfaceStyleDark];
    
    [asset registerImage:lightImage withTraitCollection:lightTraits];
    [asset registerImage:darkImage withTraitCollection:darkTraits];
    
    return [asset imageWithTraitCollection:UITraitCollection.currentTraitCollection];
}

UIImage *Gib26FallbackIcon(CGSize size, CGFloat scale)
{
    ISIcon *icon = [PrivClass(ISIcon) genericApplicationIcon];
    if(!icon)
    {
        return nil;
    }
    
    ISImageDescriptor *lightDescriptor = ISIDescriptorFor(size, scale, NO);
    ISImageDescriptor *darkDescriptor = ISIDescriptorFor(size, scale, YES);
    
    IFImage *lightRendered = [icon prepareImageForDescriptor:lightDescriptor];
    IFImage *darkRendered = [icon prepareImageForDescriptor:darkDescriptor];
    if(!lightRendered || !lightRendered.CGImage ||
       !darkRendered || !darkRendered.CGImage)
    {
        return nil;
    }
    
    UIImage *lightImage = [UIImage imageWithCGImage:lightRendered.CGImage scale:scale orientation:UIImageOrientationUp];
    UIImage *darkImage = [UIImage imageWithCGImage:darkRendered.CGImage scale:scale orientation:UIImageOrientationUp];
    
    UIImageAsset *asset = [[UIImageAsset alloc] init];
    
    UITraitCollection *lightTraits = [UITraitCollection traitCollectionWithUserInterfaceStyle:UIUserInterfaceStyleLight];
    UITraitCollection *darkTraits = [UITraitCollection traitCollectionWithUserInterfaceStyle:UIUserInterfaceStyleDark];
    
    [asset registerImage:lightImage withTraitCollection:lightTraits];
    [asset registerImage:darkImage withTraitCollection:darkTraits];
    
    return [asset imageWithTraitCollection:UITraitCollection.currentTraitCollection];
}
