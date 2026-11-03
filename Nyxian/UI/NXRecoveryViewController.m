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

#import "NXRecoveryViewController.h"
#import "NXRecoverySurface.h"
#import "NXVolumeButtonMonitor.h"
#import "NXRecoveryTerminal.h"
#include <sys/stat.h>
#import "TWRP/NXTWRPThemeStore.h"
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>

const CGFloat NXRecoveryFontSize=13;
@implementation NXRecoveryItem

- (instancetype)initWithTitle:(NSString *)title
                       action:(NXRecoveryAction)action
{
    self = [super init];
    if(self)
    {
        _enabled = YES;
        _title = [title copy];
        _action = [action copy];
    }
    return self;
}

+ (instancetype)itemWithTitle:(NSString *)title
{
    return [[self alloc] initWithTitle:title action:nil];
}

+ (instancetype)itemWithTitle:(NSString *)title
                       action:(NXRecoveryAction)action
{
    return [[self alloc] initWithTitle:title action:action];
}

@end

@interface NXRecoveryEntry : NSObject

@property (nonatomic, copy) NSString *name;
@property (nonatomic, copy) NSString *path;
@property (nonatomic, copy, nullable) NSString *linkDestination;
@property (nonatomic) BOOL isSymlink;
@property (nonatomic) BOOL isDirectory;
@property (nonatomic) BOOL isBroken;
@property (nonatomic, readonly) NSString *displayTitle;

@end

@implementation NXRecoveryEntry

- (NSString *)displayTitle
{
    NSString *base = self.isDirectory ? [self.name stringByAppendingString:@"/"] : self.name;
    if(!self.isSymlink)
    {
        return base;
    }
    
    NSString *dest = self.linkDestination ?: @"?";
    
    return self.isBroken ? [NSString stringWithFormat:@"%@ -> %@ (broken)", self.name, dest] : [NSString stringWithFormat:@"%@ -> %@", base, dest];
}

@end

@interface NXRecoveryPage : NSObject
@property NSString *header, *instructions;
@property NSArray<NXRecoveryItem *> *items;
@property NSInteger index;
@property (copy) NXRecoveryIndexHandler select, move;
@end
@implementation NXRecoveryPage @end

@interface NXRecoveryViewController () <UIDocumentPickerDelegate>
@property NXRecoverySurface *surface;
@property NSMutableArray<NXRecoveryItem *> *mutableItems;
@property NSMutableArray<NXRecoveryPage *> *pages;
@property NSMutableArray<NSAttributedString *> *logLines;
@property NSString *headerText, *instructionsText;
@property (nonatomic, readwrite, getter=isRecoveryActive) BOOL recoveryActive;
@property (nonatomic, readwrite, getter=isConsoleActive) BOOL consoleActive;
@property (nonatomic, readwrite, getter=isTerminalActive) BOOL terminalActive;
@property (copy) NXRecoveryIndexHandler onSelect, onMove;
@property (copy) NXRecoveryAction consoleSelectAction;
@property NSInteger savedLogMax;
@property (copy) NSString *browserRoot, *browserHeader, *browserPath;
@property (copy) NXRecoveryAction browserOnBack;
@property (copy) NXRecoveryFileHandler browserOnFile;
/* TWRP's file manager (filemanagerlist and the pages behind it) */
@property BOOL fmActive, fmTargetIsFolder, fmInputPage;
@property (copy) NSString *fmRoot, *fmListPath, *fmTarget;
@property (copy) NXRecoveryAction fmOnBack;
@property NSInteger fmPending;      /* the copy or move choosedestinationfolder picks for */
@property (readonly) BOOL fmPickingDestination;
- (void)fmShowList;
- (void)fmShowOptions;
- (void)fmShowOptionsForPath:(NSString *)path folder:(BOOL)folder;
- (void)fmConfirmDestination:(NSString *)folder;
@end

typedef NS_ENUM(NSInteger, NXRecoveryFileOperation) {
    NXRecoveryFileCopy,
    NXRecoveryFileMove,
    NXRecoveryFileChmod,
    NXRecoveryFileDelete,
    NXRecoveryFileRename,
};

@implementation NXRecoveryViewController
+ (UIColor *)recoveryBackgroundColor { return [UIColor colorWithWhite:26/255.0 alpha:1]; }
+ (UIColor *)recoveryHeaderColor { return [UIColor colorWithRed:0 green:144/255.0 blue:202/255.0 alpha:1]; }
+ (UIColor *)recoveryInfoColor { return UIColor.whiteColor; }
+ (UIColor *)recoveryItemColor { return UIColor.whiteColor; }
+ (UIColor *)recoveryHighlightColor { return self.recoveryHeaderColor; }
+ (UIColor *)recoveryHighlightTextColor { return UIColor.whiteColor; }
+ (UIColor *)recoveryFooterColor { return [UIColor colorWithWhite:0.8 alpha:1]; }
+ (UIColor *)recoveryLogInfoColor { return [UIColor colorWithWhite:0.93 alpha:1]; }
+ (UIColor *)recoveryLogErrorColor { return [UIColor colorWithRed:1 green:0.25 blue:0.25 alpha:1]; }
- (instancetype)initWithNibName:(NSString *)nib bundle:(NSBundle *)bundle {
    if((self=[super initWithNibName:nib bundle:bundle])) {
        _mutableItems=[NSMutableArray array]; _pages=[NSMutableArray array]; _logLines=[NSMutableArray array];
        _headerText=@"Nyxian Recovery"; _instructionsText=@""; _recoveryLogMax=30;
    }
    return self;
}
- (void)loadView { self.surface=[NXRecoverySurface new]; self.view=self.surface; }
- (void)viewDidLoad {
    [super viewDidLoad]; self.view.hidden=YES;
    __weak typeof(self) weakSelf=self;
    self.surface.onSelect=^(NSInteger index) { NXRecoveryViewController *c=weakSelf;
        if(!c || c.consoleActive || index<0 || index>=(NSInteger)c.mutableItems.count || !c.mutableItems[index].enabled) return;
        c->_recoveryIndex=index; [c performRecoverySelect];
    };
    self.surface.onBack=^{ [weakSelf goBack]; };
    self.surface.onHome=^{ [weakSelf goHome]; };
    self.surface.onComplete=^{ [weakSelf finishOperation]; };
    [self renderPage];
}
- (void)createRecoveryView { [self loadViewIfNeeded]; }
- (BOOL)prefersStatusBarHidden { return YES; }
- (void)attachToViewController:(UIViewController *)parent {
    if(!parent) return;
    [parent addChildViewController:self]; self.view.translatesAutoresizingMaskIntoConstraints=NO; [parent.view addSubview:self.view];
    [NSLayoutConstraint activateConstraints:@[[self.view.topAnchor constraintEqualToAnchor:parent.view.topAnchor],
        [self.view.bottomAnchor constraintEqualToAnchor:parent.view.bottomAnchor],
        [self.view.leadingAnchor constraintEqualToAnchor:parent.view.leadingAnchor],
        [self.view.trailingAnchor constraintEqualToAnchor:parent.view.trailingAnchor]]];
    [self didMoveToParentViewController:parent];
}
- (void)renderPage {
    NSMutableArray *titles=[NSMutableArray array], *enabled=[NSMutableArray array], *checks=[NSMutableArray array], *paths=[NSMutableArray array];
    for(NXRecoveryItem *item in self.mutableItems) { [titles addObject:item.title?:@""]; [enabled addObject:@(item.enabled)]; [checks addObject:@(item.toggle?((item.radio?2:0)+(item.checked?1:0)):-1)]; [paths addObject:item.filePath?:@""]; }
    BOOL home=[self.headerText isEqual:@"Nyxian Recovery"] || [self.headerText hasPrefix:@"Nyxian Recovery\n"];
    BOOL confirmation=self.mutableItems.count==2 && [self.mutableItems.firstObject.title isEqual:@"Cancel"] && !self.fmInputPage;
    NSString *instructions=self.instructionsText;
    for(NXRecoveryItem *item in self.mutableItems)if(item.toggle && !item.radio && ![self.headerText hasPrefix:@"Wipe"]){instructions=[NSString stringWithFormat:@"%@%@Theme: %@",instructions?:@"",instructions.length?@"\n":@"",NXTWRPThemeStore.activeName];break;}
    [self.surface showHeader:self.headerText instructions:instructions titles:titles enabled:enabled checks:checks browserPath:self.browserPath filePaths:paths selected:self.recoveryIndex
                       home:home confirmation:confirmation canGoBack:self.pages.count>0 || self.browserPath!=nil];
}
- (NXRecoveryPage *)snapshot {
    NXRecoveryPage *p=[NXRecoveryPage new]; p.header=self.headerText; p.instructions=self.instructionsText;
    p.items=self.mutableItems.copy; p.index=self.recoveryIndex; p.select=self.onSelect; p.move=self.onMove; return p;
}
- (void)restorePage:(NXRecoveryPage *)p {
    self.headerText=p.header; self.instructionsText=p.instructions; [self.mutableItems setArray:p.items];
    _recoveryIndex=p.index; self.onSelect=p.select; self.onMove=p.move; self.browserPath=nil;
    self.fmActive=NO; self.fmInputPage=NO;
    [self renderPage];
}
- (void)goBack {
    if(self.consoleActive) return;
    if(self.terminalActive) { [self exitTerminal]; return; }
    /* Confirmation pages must run Cancel to release a worker waiting for an answer. */
    if(self.mutableItems.count==2 && [self.mutableItems.firstObject.title isEqual:@"Cancel"]) {
        self.recoveryIndex=0; [self performRecoverySelect]; return;
    }
    if(self.browserPath) {
        if(![self.browserPath isEqualToString:self.browserRoot]) {
            [self browsePath:[self fmParentOfPath:self.browserPath]];
        } else {
            NXRecoveryAction onBack=self.browserOnBack;self.browserPath=nil;
            if(onBack)onBack(self);
            else if(self.pages.count){NXRecoveryPage *p=self.pages.lastObject;[self.pages removeLastObject];[self restorePage:p];}
            else [self exitRecovery];
        }
        return;
    }
    /* Choose Action goes back to the list (its name/permissions inputs and confirmations run Cancel above) */
    if(self.fmActive) { [self fmShowList]; return; }
    NXRecoveryPage *p=self.pages.lastObject; if(!p) return; [self.pages removeLastObject]; [self restorePage:p];
}
- (void)goHome {
    if(self.consoleActive) return;
    if(self.terminalActive) [self exitTerminal];
    if(self.mutableItems.count==2 && [self.mutableItems.firstObject.title isEqual:@"Cancel"]) { [self goBack]; return; }
    NXRecoveryPage *p=self.pages.firstObject; if(!p) return; [self.pages removeAllObjects]; [self restorePage:p];
}
- (void)setRecoveryHeader:(NSString *)text { [self createRecoveryView]; self.headerText=text?:@""; [self renderPage]; }
- (void)setRecoveryInstructions:(NSString *)text { [self createRecoveryView]; self.instructionsText=text?:@""; [self renderPage]; }
- (void)setRecoveryFooter:(NSString *)text { [self clearRecoveryLog]; if(text.length) [self recoveryLog:text]; }
- (NSArray<NXRecoveryItem *> *)recoveryItems { return self.mutableItems.copy; }
- (void)setRecoveryItems:(NSArray<NXRecoveryItem *> *)items {
    [self createRecoveryView];NSInteger previous=self.recoveryIndex;
    [self.mutableItems setArray:items?:@[]];_recoveryIndex=[self.headerText isEqual:@"Settings"]?MIN(previous,MAX(0,(NSInteger)self.mutableItems.count-1)):0;[self renderPage];
}
- (void)setRecoveryIndex:(NSInteger)index {
    NSInteger count=self.mutableItems.count; _recoveryIndex=count?((index%count)+count)%count:0;
    [self.surface setSelectedIndex:_recoveryIndex];
}
- (NXRecoveryItem *)currentRecoveryItem {
    return self.recoveryIndex>=0 && self.recoveryIndex<(NSInteger)self.mutableItems.count?self.mutableItems[self.recoveryIndex]:nil;
}
- (void)showRecovery:(BOOL)visible { [self createRecoveryView]; [self.view.superview bringSubviewToFront:self.view]; self.view.hidden=!visible; }
- (void)enterRecoveryWithHeader:(NSString *)header instructions:(NSString *)instructions footer:(NSString *)footer
                         items:(NSArray<NXRecoveryItem *> *)items onSelect:(NXRecoveryIndexHandler)onSelect onMove:(NXRecoveryIndexHandler)onMove {
    [self createRecoveryView]; if(self.consoleActive) [self exitConsole]; if(self.terminalActive) [self exitTerminal];
    if([header isEqual:@"Nyxian Recovery"] || [header hasPrefix:@"Nyxian Recovery\n"]) [self.pages removeAllObjects];
    else if(self.recoveryActive && ![header isEqual:self.headerText]) [self.pages addObject:[self snapshot]];
    self.browserPath=nil; self.headerText=header?:self.headerText; self.instructionsText=instructions?:@"";
    self.fmActive=NO; self.fmInputPage=NO;
    [self.mutableItems setArray:items?:@[]]; _recoveryIndex=0; self.onSelect=onSelect; self.onMove=onMove;
    if(footer) [self setRecoveryFooter:footer]; self.recoveryActive=YES; [self renderPage]; [self showRecovery:YES];
}
- (void)enterTerminal {
    [self createRecoveryView]; if(self.consoleActive) [self exitConsole];
    self.terminalActive=YES; [self.surface setTerminal:YES]; [self showRecovery:YES];
}
- (void)exitTerminal {
    if(!self.terminalActive) return;
    self.terminalActive=NO; [self.surface setTerminal:NO]; [self renderPage];
}
- (void)exitRecovery { if(self.terminalActive) [self exitTerminal]; self.recoveryActive=NO; [NXVolumeButtonMonitor disarm]; [self showRecovery:NO]; }
- (void)focusWipeConfirmation { [self.surface focusCertificatePassword]; }
- (void)performRecoverySelect {
    if ([self.headerText isEqual:@"Wipe\nFormat Data"] && self.recoveryIndex==1 && ![self.surface formatDataConfirmed]) return;
    NXRecoveryItem *item=self.currentRecoveryItem; if(!item || !item.enabled) return;
    if(item.action) item.action(self);
    if(self.recoveryActive && self.onSelect) self.onSelect(self,self.recoveryIndex,item);
}
- (void)setRecoveryLogMax:(NSInteger)maximum { _recoveryLogMax=MAX(1,maximum); [self paintRecoveryLog]; }
- (void)paintRecoveryLog {
    while(self.logLines.count>(NSUInteger)self.recoveryLogMax) [self.logLines removeObjectAtIndex:0];
    NSMutableAttributedString *text=[[NSMutableAttributedString alloc] initWithString:@""];
    for(NSAttributedString *line in self.logLines) [text appendAttributedString:line];
    [self.surface setLog:text];
}
- (void)recoveryLog:(NSString *)line { [self recoveryLog:line level:NXRecoveryLogLevelInfo]; }
- (void)recoveryLog:(NSString *)line level:(NXRecoveryLogLevel)level {
    if(!NSThread.isMainThread) { dispatch_async(dispatch_get_main_queue(),^{ [self recoveryLog:line level:level]; }); return; }
    [self createRecoveryView];
    NSDictionary *attributes=@{NSFontAttributeName:[UIFont monospacedSystemFontOfSize:13 weight:UIFontWeightRegular],
        NSForegroundColorAttributeName:level==NXRecoveryLogLevelError?self.class.recoveryLogErrorColor:self.class.recoveryLogInfoColor};
    for(NSString *part in [(line?:@"") componentsSeparatedByString:@"\n"])
        [self.logLines addObject:[[NSAttributedString alloc] initWithString:[part stringByAppendingString:@"\n"] attributes:attributes]];
    [self paintRecoveryLog];
}
- (void)recoveryLogError:(NSString *)line { [self recoveryLog:line level:NXRecoveryLogLevelError]; }
- (void)clearRecoveryLog { [self createRecoveryView]; [self.logLines removeAllObjects]; [self paintRecoveryLog]; }
- (void)importRecoveryTheme {
    if(self.consoleActive)return;
    UIDocumentPickerViewController *picker=[[UIDocumentPickerViewController alloc] initForOpeningContentTypes:@[UTTypeZIP] asCopy:YES];
    picker.delegate=self;picker.allowsMultipleSelection=NO;[self presentViewController:picker animated:YES completion:nil];
}
- (void)documentPicker:(UIDocumentPickerViewController *)picker didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
    NSURL *url=urls.firstObject;if(!url)return;
    [picker dismissViewControllerAnimated:YES completion:^{
        [self enterConsole];[self recoveryLog:@"Importing recovery theme..."];
        // Extraction runs off the UI thread. Validation/drawing and activation run on main.
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0),^{
            NSError *error=nil;NSURL *candidate=[NXTWRPThemeStore prepareArchive:url error:&error];
            dispatch_async(dispatch_get_main_queue(),^{
                NSError *failure=error;
                BOOL imported=candidate && [NXTWRPThemeStore activatePreparedTheme:candidate name:url.lastPathComponent error:&failure];
                if(imported)[self recoveryLog:@"Theme imported. Return to Settings to view it."];
                else [self recoveryLogError:failure.localizedDescription?:@"Theme could not be imported."];
                [self finishConsoleWithSelectAction:^(NXRecoveryViewController *c){[c exitConsole];}];
            });
        });
    }];
}
- (void)restoreRecoverySettings {
    if(self.consoleActive)return;
    for(NSString *name in @[@"tw_military_time",@"tw_button_vibrate",@"tw_keyboard_vibrate",@"tw_brightness_pct",@"timezone",@"language"])
        [NSUserDefaults.standardUserDefaults removeObjectForKey:[@"nyxian.recovery." stringByAppendingString:name]];
    [NSUserDefaults.standardUserDefaults setInteger:50 forKey:@"nyxian.recovery.tw_brightness_pct"];
    UIScreen.mainScreen.brightness=0.5;
    [self reloadRecoveryTheme];
}
- (void)reloadRecoveryTheme {
    if(self.consoleActive)return;
    [NSNotificationCenter.defaultCenter postNotificationName:NXTWRPThemeDidChangeNotification object:nil];
    [self renderPage];
}
- (void)useStockRecoveryTheme {
    if(self.consoleActive)return;[NXTWRPThemeStore useStockTheme];[self recoveryLog:@"Stock recovery theme selected."];[self renderPage];
}
- (void)setOperationProgress:(double)fraction status:(NSString *)status {[self createRecoveryView];[self.surface setOperationProgress:fraction status:status];}
- (void)clearOperationProgress {[self.surface clearOperationProgress];}
- (void)enterConsole {
    [self createRecoveryView]; if(self.consoleActive) return;
    self.consoleActive=YES; self.consoleSelectAction=nil; self.savedLogMax=self.recoveryLogMax; _recoveryLogMax=1024;
    [self.surface setConsole:YES completionEnabled:NO]; [self paintRecoveryLog];
}
- (void)finishConsoleWithSelectAction:(NXRecoveryAction)action {
    [self finishConsoleWithSelectAction:action title:@"Continue" status:@"Complete"];
}
- (void)finishConsoleWithSelectAction:(NXRecoveryAction)action title:(NSString *)title status:(NSString *)status {
    if(!self.consoleActive) return; self.consoleSelectAction=action;
    [self.surface setConsoleCompletionTitle:title status:status]; [self.surface setConsole:YES completionEnabled:action!=nil];
}
- (void)finishOperation {
    if(!self.consoleActive || !self.consoleSelectAction) return;
    NXRecoveryAction action=self.consoleSelectAction; self.consoleSelectAction=nil;
    [self.surface setConsole:YES completionEnabled:NO]; action(self);
}
- (void)exitConsole {
    if(!self.consoleActive) return; self.consoleActive=NO; self.consoleSelectAction=nil; _recoveryLogMax=self.savedLogMax;
    [self.surface setConsole:NO completionEnabled:NO]; [self renderPage]; [self paintRecoveryLog];
}
- (NSFileManager *)fm
{
    return [NSFileManager defaultManager];
}

- (NSString *)fmJoin:(NSString *)dir
                name:(NSString *)name
{
    return [dir isEqualToString:@"/"] ? [@"/" stringByAppendingString:name] : [NSString stringWithFormat:@"%@/%@", dir, name];
}

- (NSString *)fmParentOfPath:(NSString *)p
{
    if([p isEqualToString:@"/"])
    {
        return @"/";
    }
    
    NSString *q = p;
    while(q.length > 1 && [q hasSuffix:@"/"])
    {
        q = [q substringToIndex:q.length - 1];
    }

    NSRange slash = [q rangeOfString:@"/" options:NSBackwardsSearch];
    if(slash.location == NSNotFound || slash.location == 0)
    {
        return @"/";
    }
    return [q substringToIndex:slash.location];
}

- (NXRecoveryEntry*)entryForName:(NSString*)name
                     inDirectory:(NSString*)dir
{
    NXRecoveryEntry *e = [NXRecoveryEntry new];
    e.name = name;
    e.path = [self fmJoin:dir name:name];
    
    NSDictionary *attrs = [self.fm attributesOfItemAtPath:e.path error:NULL];
    NSString *type = attrs[NSFileType];
    
    if([type isEqualToString:NSFileTypeSymbolicLink])
    {
        e.isSymlink = YES;
        e.linkDestination = [self.fm destinationOfSymbolicLinkAtPath:e.path error:NULL];
        BOOL targetIsDir = NO;
        BOOL targetExists = [self.fm fileExistsAtPath:e.path isDirectory:&targetIsDir];
        
        e.isBroken = !targetExists;
        e.isDirectory = targetExists && targetIsDir;
    }
    else
    {
        e.isDirectory = [type isEqualToString:NSFileTypeDirectory];
    }
    
    return e;
}

- (void)browsePath:(NSString *)path
{
    [self browsePath:path root:self.browserRoot header:self.browserHeader onBack:self.browserOnBack onFile:self.browserOnFile];
}

- (void)browsePath:(NSString *)path
              root:(NSString *)root
            header:(NSString *)header
            onBack:(NXRecoveryAction)onBack
            onFile:(NXRecoveryFileHandler)onFile
{
    NSArray<NSString *> *names = [self.fm contentsOfDirectoryAtPath:path error:NULL];
    if(names == nil)
    {
        [self recoveryLogError:[@"open failed: " stringByAppendingString:path]];
        names = @[];
    }
    names = [names sortedArrayUsingSelector:@selector(localizedCompare:)];
    
    NSMutableArray<NXRecoveryEntry*> *dirs = [NSMutableArray array];
    NSMutableArray<NXRecoveryEntry*> *files = [NSMutableArray array];
    for(NSString *name in names)
    {
        NXRecoveryEntry *e = [self entryForName:name inDirectory:path];
        [(e.isDirectory ? dirs : files) addObject:e];
    }
    
    self.browserRoot = root ?: @"/";
    self.browserHeader = header;
    self.browserPath = path;
    self.browserOnBack = onBack;
    self.browserOnFile = onFile;
    
    NSMutableArray<NXRecoveryItem *> *items = [NSMutableArray array];
    for(NXRecoveryEntry *e in dirs)
    {
        NSString *full=e.path;
        NXRecoveryItem *item=[NXRecoveryItem itemWithTitle:e.displayTitle action:^(NXRecoveryViewController *c){[c browsePath:full];}];
        item.filePath=full;[items addObject:item];
    }
    for(NXRecoveryEntry *e in files)
    {
        NSString *full=e.path, *name=e.name;BOOL broken=e.isBroken;
        NXRecoveryItem *item=[NXRecoveryItem itemWithTitle:e.displayTitle action:^(NXRecoveryViewController *c){
            if(broken){[c recoveryLogError:[@"dangling symlink: " stringByAppendingString:name]];return;}
            if(c.fmActive){if(!c.fmPickingDestination)[c fmShowOptionsForPath:full folder:NO];return;}
            if(c.browserOnFile)c.browserOnFile(full,name,c);
        }];
        item.filePath=full;[items addObject:item];
    }
    /* TWRP's select-folder button: Choose Action on the folder shown, or the destination of a copy/move */
    if(self.fmActive)
    {
        [items addObject:[NXRecoveryItem itemWithTitle:@"Select Folder" action:^(NXRecoveryViewController *c){
            NSString *folder=c.browserPath;if(!folder)return;
            if(c.fmPickingDestination)[c fmConfirmDestination:folder];
            else [c fmShowOptionsForPath:folder folder:YES];
        }]];
    }
    self.fmInputPage = NO;
    [self setRecoveryHeader:[NSString stringWithFormat:@"%@\n%@", (header ?: @"Files"), path]];
    [self setRecoveryItems:items];
    if(items.count)self.recoveryIndex=[self.surface browserIndexAfterMoving:0 current:-1];
}

- (void)enterFileBrowserAtPath:(NSString *)path
                          root:(NSString *)root
                        header:(NSString *)header
                        onBack:(NXRecoveryAction)onBack
                        onFile:(NXRecoveryFileHandler)onFile
{
    [self enterRecoveryWithHeader:(header ?: @"Files") instructions:nil footer:nil items:@[] onSelect:nil onMove:nil];
    [self browsePath:path root:root header:header onBack:onBack onFile:onFile];
}



/* ----------------------------------------------------------------------
 *  TWRP file manager: filemanagerlist, filemanageroptions,
 *  choosedestinationfolder, filemanagerrenamefile/folder, filemanagerchmod,
 *  filemanagerconfirm and filemanageraction
 * -------------------------------------------------------------------- */

static NSString *const NXRecoveryFMDestinationHeader = @"Select Destination Folder";

- (void)enterFileManagerAtPath:(NSString *)path
                          root:(NSString *)root
                        onBack:(NXRecoveryAction)onBack
{
    [self enterRecoveryWithHeader:@"File Manager" instructions:nil footer:nil items:@[] onSelect:nil onMove:nil];
    self.fmActive = YES;
    self.fmRoot = root ?: @"/";
    self.fmOnBack = onBack;
    self.fmListPath = path;
    [self browsePath:path root:self.fmRoot header:@"File Manager" onBack:onBack onFile:nil];
}

- (BOOL)fmPickingDestination
{
    return self.fmActive && self.browserPath != nil && [self.browserHeader isEqualToString:NXRecoveryFMDestinationHeader];
}

/* the folder the list was showing; what it showed may be gone after a move, rename or delete */
- (void)fmShowList
{
    NSString *path = self.fmListPath ?: self.fmRoot;
    while(![self.fm fileExistsAtPath:path] && ![path isEqualToString:self.fmRoot] && path.length > 1)
    {
        path = [self fmParentOfPath:path];
    }
    self.fmActive = YES;
    [self browsePath:path root:self.fmRoot header:@"File Manager" onBack:self.fmOnBack onFile:nil];
}

- (void)fmShowPage:(NSString *)header instructions:(NSString *)instructions items:(NSArray<NXRecoveryItem *> *)items input:(BOOL)input
{
    self.browserPath = nil;
    self.fmInputPage = input;
    self.headerText = header;
    self.instructionsText = instructions ?: @"";
    [self.mutableItems setArray:items];
    self.onSelect = nil;
    self.onMove = nil;
    _recoveryIndex = 0;
    for(NSUInteger i = 0; i < items.count; i++)
    {
        if(items[i].enabled) { _recoveryIndex = i; break; }
    }
    [self renderPage];
}

- (NXRecoveryItem *)fmItem:(NSString *)title enabled:(BOOL)enabled action:(NXRecoveryAction)action
{
    NXRecoveryItem *item = [NXRecoveryItem itemWithTitle:title action:action];
    item.enabled = enabled;
    return item;
}

- (void)fmShowOptionsForPath:(NSString *)path folder:(BOOL)folder
{
    if(self.browserPath)
    {
        self.fmListPath = self.browserPath;
    }
    self.fmTarget = path;
    self.fmTargetIsFolder = folder;
    [self fmShowOptions];
}

/* filemanageroptions */
- (void)fmShowOptions
{
    NSString *path = self.fmTarget;
    BOOL folder = self.fmTargetIsFolder;
    BOOL visible = [NXRecoveryTerminal.shared shellPathForPath:path] != nil;
    NSArray<NXRecoveryItem *> *items = @[
        folder ?
            [self fmItem:@"Open Terminal Here" enabled:visible action:^(NXRecoveryViewController *c){ [NXRecoveryTerminal.shared openTerminalAt:path inRecovery:c]; }] :
            [self fmItem:@"Edit File" enabled:visible action:^(NXRecoveryViewController *c){ [NXRecoveryTerminal.shared editFile:path inRecovery:c]; }],
        [self fmItem:folder ? @"Copy Folder" : @"Copy File" enabled:YES action:^(NXRecoveryViewController *c){ [c fmChooseDestination:NXRecoveryFileCopy]; }],
        [self fmItem:@"Move" enabled:YES action:^(NXRecoveryViewController *c){ [c fmChooseDestination:NXRecoveryFileMove]; }],
        [self fmItem:@"chmod 755" enabled:YES action:^(NXRecoveryViewController *c){ [c fmConfirm:NXRecoveryFileChmod argument:@"755"]; }],
        [self fmItem:@"chmod" enabled:YES action:^(NXRecoveryViewController *c){ [c fmAskPermissions]; }],
        [self fmItem:@"Delete" enabled:YES action:^(NXRecoveryViewController *c){ [c fmConfirm:NXRecoveryFileDelete argument:nil]; }],
        [self fmItem:folder ? @"Rename Folder" : @"Rename File" enabled:YES action:^(NXRecoveryViewController *c){ [c fmAskName]; }],
    ];
    [self fmShowPage:@"File Manager\nChoose Action" instructions:path items:items input:NO];
}

/* choosedestinationfolder: the list, folders only; its select-folder button picks the one shown */
- (void)fmChooseDestination:(NXRecoveryFileOperation)operation
{
    self.fmPending = operation;
    NSString *start = self.fmListPath ?: self.fmRoot;
    [self browsePath:start root:self.fmRoot header:NXRecoveryFMDestinationHeader onBack:^(NXRecoveryViewController *c){ [c fmShowOptions]; } onFile:nil];
}

- (void)fmConfirmDestination:(NSString *)folder
{
    [self fmConfirm:(NXRecoveryFileOperation)self.fmPending argument:folder];
}

- (void)enterBootArgumentsInput:(NSString *)text help:(NSString *)help onSave:(void (^)(NXRecoveryViewController *controller, NSString *text))onSave
{
    [self createRecoveryView];
    if(self.terminalActive) [self exitTerminal];
    [self.pages addObject:[self snapshot]];
    [self.surface prepareTextInput:text ?: @""];
    void (^back)(NXRecoveryViewController *) = ^(NXRecoveryViewController *c){
        NXRecoveryPage *page = c.pages.lastObject;
        if(page == nil) return;
        [c.pages removeLastObject];
        [c restorePage:page];
    };
    void (^save)(NXRecoveryViewController *, NSString *) = [onSave copy];
    NSArray<NXRecoveryItem *> *items = @[
        [self fmItem:@"Cancel" enabled:YES action:back],
        [self fmItem:@"Save" enabled:YES action:^(NXRecoveryViewController *c){
            NSString *value = [c.surface textInputValue] ?: @"";
            back(c);
            if(save) save(c, value);
        }],
    ];
    /* "Settings\nBoot Arguments" is what NXTWRPIsBootArgumentsInput keys the page on */
    [self fmShowPage:@"Settings\nBoot Arguments" instructions:help items:items input:YES];
}

/* filemanagerrenamefile / filemanagerrenamefolder */
- (void)fmAskName
{
    [self.surface prepareTextInput:self.fmTarget.lastPathComponent];
    NSArray<NXRecoveryItem *> *items = @[
        [self fmItem:@"Cancel" enabled:YES action:^(NXRecoveryViewController *c){ [c fmShowOptions]; }],
        [self fmItem:@"Rename" enabled:YES action:^(NXRecoveryViewController *c){
            NSString *name = [c.surface textInputValue];
            if(name.length == 0 || name.length > 128 || [name containsString:@"/"] || [name isEqualToString:@"."] || [name isEqualToString:@".."])
            {
                [c recoveryLogError:[@"invalid name: " stringByAppendingString:name]];
                return;
            }
            [c fmConfirm:NXRecoveryFileRename argument:name];
        }],
    ];
    [self fmShowPage:self.fmTargetIsFolder ? @"File Manager\nRename Folder" : @"File Manager\nRename File" instructions:self.fmTarget items:items input:YES];
}

/* filemanagerchmod */
- (void)fmAskPermissions
{
    struct stat st;
    NSString *mode = lstat(self.fmTarget.fileSystemRepresentation, &st) == 0 ? [NSString stringWithFormat:@"%04o", st.st_mode & 07777] : @"0000";
    [self.surface prepareTextInput:mode];
    NSArray<NXRecoveryItem *> *items = @[
        [self fmItem:@"Cancel" enabled:YES action:^(NXRecoveryViewController *c){ [c fmShowOptions]; }],
        [self fmItem:@"Set Permissions" enabled:YES action:^(NXRecoveryViewController *c){
            NSString *value = [c.surface textInputValue];
            NSCharacterSet *octal = [NSCharacterSet characterSetWithCharactersInString:@"01234567"];
            if(value.length < 3 || value.length > 4 || [value rangeOfCharacterFromSet:octal.invertedSet].location != NSNotFound)
            {
                [c recoveryLogError:[@"invalid permissions: " stringByAppendingString:value]];
                return;
            }
            [c fmConfirm:NXRecoveryFileChmod argument:value];
        }],
    ];
    [self fmShowPage:@"File Manager\nSet Permissions" instructions:self.fmTarget items:items input:YES];
}

- (NSString *)fmTypeName
{
    return self.fmTargetIsFolder ? @"Folder" : @"File";
}

/* filemanagerconfirm: tw_fm_text1, tw_filename1, tw_fm_text2, tw_fm_text3 (and tw_fm_type) */
- (void)fmConfirm:(NXRecoveryFileOperation)operation argument:(NSString *)argument
{
    NSString *target = self.fmTarget;
    NSString *text1 = @"", *text2 = @"", *text3 = @"";
    switch(operation)
    {
        case NXRecoveryFileCopy:   text1 = @"Copying"; text2 = @"to"; text3 = argument; break;
        case NXRecoveryFileMove:   text1 = @"Moving"; text2 = @"to"; text3 = argument; break;
        case NXRecoveryFileChmod:  text1 = [@"chmod " stringByAppendingString:argument]; break;
        case NXRecoveryFileDelete: text1 = @"Deleting"; break;
        case NXRecoveryFileRename: text1 = @"Renaming"; text2 = @"to"; text3 = [[target stringByDeletingLastPathComponent] stringByAppendingPathComponent:argument]; break;
    }
    NSString *details = [@[text1, target, text2, text3, self.fmTypeName] componentsJoinedByString:@"\n"];
    NSArray<NXRecoveryItem *> *items = @[
        [self fmItem:@"Cancel" enabled:YES action:^(NXRecoveryViewController *c){ [c fmShowOptions]; }],
        [self fmItem:@"Confirm" enabled:YES action:^(NXRecoveryViewController *c){ [c fmRun:operation argument:argument]; }],
    ];
    [self fmShowPage:@"File Manager\nConfirm Action" instructions:details items:items input:NO];
}

/* filemanageraction: runs it, then back to the list (errors stay on screen until Continue) */
- (void)fmRun:(NXRecoveryFileOperation)operation argument:(NSString *)argument
{
    NSString *target = self.fmTarget;
    BOOL targetIsFolder = self.fmTargetIsFolder;
    NSString *destination = nil;
    NSString *status = nil;
    switch(operation)
    {
        case NXRecoveryFileCopy:
        case NXRecoveryFileMove:
            destination = [argument stringByAppendingPathComponent:target.lastPathComponent];
            status = [NSString stringWithFormat:@"%@ %@ to %@", operation == NXRecoveryFileCopy ? @"Copying" : @"Moving", target, argument];
            break;
        case NXRecoveryFileRename:
            destination = [target.stringByDeletingLastPathComponent stringByAppendingPathComponent:argument];
            status = [NSString stringWithFormat:@"Renaming %@ to %@", target, destination];
            break;
        case NXRecoveryFileChmod:
            status = [NSString stringWithFormat:@"chmod %@ %@", argument, target];
            break;
        case NXRecoveryFileDelete:
            status = [@"Deleting " stringByAppendingString:target];
            break;
    }

    [self enterConsole];
    [self recoveryLog:status];
    __weak NXRecoveryViewController *weakSelf = self;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSFileManager *fm = [NSFileManager new];
        NSError *error = nil;
        BOOL ok = YES;
        switch(operation)
        {
            case NXRecoveryFileCopy:
            case NXRecoveryFileMove:
            case NXRecoveryFileRename:
            {
                BOOL folder = NO;
                if([destination isEqualToString:target] ||
                   (targetIsFolder && [destination hasPrefix:[target stringByAppendingString:@"/"]]))
                {
                    error = [NSError errorWithDomain:NSPOSIXErrorDomain code:EINVAL userInfo:@{NSLocalizedDescriptionKey: @"the destination is the source itself"}];
                    ok = NO;
                    break;
                }
                /* like cp/mv, a file replaces a file of the same name; folders never replace anything */
                if([fm fileExistsAtPath:destination isDirectory:&folder])
                {
                    if(folder || targetIsFolder)
                    {
                        error = [NSError errorWithDomain:NSPOSIXErrorDomain code:EEXIST userInfo:@{NSLocalizedDescriptionKey: [destination stringByAppendingString:@" already exists"]}];
                        ok = NO;
                        break;
                    }
                    ok = [fm removeItemAtPath:destination error:&error];
                }
                if(ok)
                {
                    ok = operation == NXRecoveryFileCopy ? [fm copyItemAtPath:target toPath:destination error:&error]
                                                         : [fm moveItemAtPath:target toPath:destination error:&error];
                }
                break;
            }
            case NXRecoveryFileChmod:
                if(chmod(target.fileSystemRepresentation, (mode_t)strtol(argument.UTF8String, NULL, 8)) != 0)
                {
                    error = [NSError errorWithDomain:NSPOSIXErrorDomain code:errno userInfo:@{NSLocalizedDescriptionKey: @(strerror(errno))}];
                    ok = NO;
                }
                break;
            case NXRecoveryFileDelete:
                ok = [fm removeItemAtPath:target error:&error];
                break;
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            NXRecoveryViewController *c = weakSelf;
            if(c == nil)
            {
                return;
            }
            if(ok)
            {
                [c recoveryLog:@"Done."];
                [c exitConsole];
                [c fmShowList];
                return;
            }
            [c recoveryLogError:[@"ERROR: " stringByAppendingString:error.localizedDescription ?: @"the operation failed"]];
            [c finishConsoleWithSelectAction:^(NXRecoveryViewController *done) { [done exitConsole]; [done fmShowList]; }];
        });
    });
}

@end
