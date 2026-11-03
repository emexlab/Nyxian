/* SPDX-License-Identifier: GPL-3.0-or-later
 * iOS view and input surface for the vendored TeamWin renderer.
 */
#import "NXRecoverySurface.h"
#include "TWRP/NXTWRPEngine.hpp"
#include "TWRP/NXTWRPTerminal.hpp"
#import "TWRP/NXTWRPThemeStore.h"
#include <exception>
#include <cmath>
#include <algorithm>

@interface NXRecoveryAccessibleControl : UIAccessibilityElement
@property (nonatomic, copy) BOOL (^activate)(void);
@property (nonatomic, copy) void (^adjust)(NSInteger);
@end
@implementation NXRecoveryAccessibleControl
- (BOOL)accessibilityActivate { return self.activate?self.activate():NO; }
- (void)accessibilityIncrement {if(self.adjust)self.adjust(1);}
- (void)accessibilityDecrement {if(self.adjust)self.adjust(-1);}
@end

@interface NXRecoverySurface () {
    NXTWRPEngine *_engine;
    NXTWRPModel _model;
    std::string _pendingInput;
    BOOL _tracking;
    CGRect _lastCanvas;
}
@property (nonatomic, strong) NSTimer *keyHoldTimer;
@property (nonatomic) CGPoint keyTouchPoint;
@property (nonatomic, strong) NSTimer *refreshTimer;
@property (nonatomic, copy) NSString *renderError;
@property (nonatomic) NSUInteger modelGeneration;
- (BOOL)textInputActive;
@end

@implementation NXRecoverySurface
- (instancetype)initWithFrame:(CGRect)frame {
    if((self=[super initWithFrame:frame])) {
        self.backgroundColor=[UIColor colorWithRed:0 green:144/255.0 blue:202/255.0 alpha:1];
        self.multipleTouchEnabled=NO;
        self.contentMode=UIViewContentModeRedraw;
        self.accessibilityIdentifier=@"recovery.twrp.canvas";
        [NSNotificationCenter.defaultCenter addObserver:self selector:@selector(themeChanged:) name:NXTWRPThemeDidChangeNotification object:nil];
        [NSNotificationCenter.defaultCenter addObserver:self selector:@selector(resumePresentation:) name:UIApplicationDidBecomeActiveNotification object:nil];
        try {_engine=NXTWRPCreate();}catch(const std::exception& e){self.renderError=@(e.what());}
    }
    return self;
}
- (void)themeChanged:(NSNotification *)notification {[self cancelTouch];if(_engine)NXTWRPReloadTheme(_engine);self.renderError=nil;self.modelGeneration++;[self setNeedsDisplay];}
- (void)dealloc { [NSNotificationCenter.defaultCenter removeObserver:self]; [self cancelTouch]; [self.refreshTimer invalidate]; if(_engine)NXTWRPDestroy(_engine); }
- (CGRect)canvas {
    UIEdgeInsets insets=self.safeAreaInsets;
    CGFloat height=MAX(1,self.bounds.size.height-insets.top-(_model.console?0:insets.bottom));
    CGFloat availableWidth=MAX(1,self.bounds.size.width-insets.left-insets.right);
    return CGRectMake(insets.left,insets.top,availableWidth,height);
}
- (void)resumePresentation:(NSNotification *)notification {if(_engine && self.window && !self.hidden)NXTWRPResumePresentation(_engine,self);}
- (void)setHidden:(BOOL)hidden {[super setHidden:hidden];if(!hidden)[self resumePresentation:nil];}
- (void)didMoveToWindow {
    [super didMoveToWindow];[self.refreshTimer invalidate];self.refreshTimer=nil;
    if(self.window) {__weak __typeof__(self) weakSelf=self;
        dispatch_async(dispatch_get_main_queue(),^{[weakSelf resumePresentation:nil];});
        self.refreshTimer=[NSTimer timerWithTimeInterval:1.0/30 repeats:YES block:^(NSTimer *t){if(!weakSelf.hidden)[weakSelf setNeedsDisplay];}];
        [NSRunLoop.mainRunLoop addTimer:self.refreshTimer forMode:NSRunLoopCommonModes];
    }
}
- (void)layoutSubviews {
    [super layoutSubviews];
    if(!CGRectEqualToRect(_lastCanvas,self.canvas)) {[self cancelTouch];_lastCanvas=self.canvas;[self setNeedsDisplay];}
}
- (void)updateModel {
    self.modelGeneration++;[self cancelTouch];
    if(_engine)NXTWRPSetModel(_engine,_model);
    
    [self setNeedsDisplay];
}
- (void)showHeader:(NSString *)header instructions:(NSString *)instructions titles:(NSArray<NSString *> *)titles
          enabled:(NSArray<NSNumber *> *)enabled checks:(NSArray<NSNumber *> *)checks browserPath:(NSString *)browserPath filePaths:(NSArray<NSString *> *)filePaths selected:(NSInteger)selected home:(BOOL)home confirmation:(BOOL)confirmation canGoBack:(BOOL)back {
    bool enteringFormat = [header isEqual:@"Wipe\nFormat Data"] && _model.header != "Wipe\nFormat Data";
    if (enteringFormat) { _model.password.clear(); _model.keyboardHidden=false; }
    std::string headerText=header.UTF8String?:"";
    NXTWRPModel entering;entering.header=headerText;entering.titles.resize(titles.count);
    if ((NXTWRPIsFileManagerInput(entering) || NXTWRPIsBootArgumentsInput(entering)) && _model.header != headerText) { _model.password=_pendingInput; _model.keyboardHidden=false; }
    _model.certificate=false;_model.navigationFocus=false;
    _model.header=header.UTF8String?:"";_model.instructions=instructions.UTF8String?:"";
    _model.titles.clear();_model.enabled.clear();
    for(NSUInteger i=0;i<titles.count;i++) {_model.titles.emplace_back(titles[i].UTF8String?:"");_model.enabled.push_back(i<enabled.count?enabled[i].boolValue:true);}
    _model.checks.clear();for(NSNumber *value in checks)_model.checks.push_back(value.intValue);
    _model.browserPath=browserPath.UTF8String?:"";_model.filePaths.clear();for(NSString *path in filePaths)_model.filePaths.emplace_back(path.UTF8String?:"");
    _model.selected=(int)selected;_model.home=home;_model.confirmation=confirmation;_model.back=back;_model.showLog=false;
    [self updateModel];
}
- (void)showCertificatePassword:(NSString *)password {
    _model.certificate=true;_model.keyboardHidden=true;_model.password=password.UTF8String?:"";
    [self updateModel];
}
- (BOOL)textInputActive { return _model.certificate || _model.header=="Wipe\nFormat Data" || NXTWRPIsFileManagerInput(_model) || NXTWRPIsBootArgumentsInput(_model); }
- (void)prepareTextInput:(NSString *)text { _pendingInput=text.UTF8String?:""; }
- (NSString *)textInputValue { return @(_model.password.c_str()); }
- (BOOL)formatDataConfirmed { return _model.header=="Wipe\nFormat Data" && _model.password=="yes"; }
- (void)focusCertificatePassword {if([self textInputActive] && _model.keyboardHidden){_model.keyboardHidden=false;[self updateModel];}}
- (NSInteger)browserIndexAfterMoving:(NSInteger)delta current:(NSInteger)current {return _engine?NXTWRPBrowserIndexAfterMoving(_engine,(int)delta,(int)current):current;}
- (BOOL)settingsDetailActive {return _engine && NXTWRPSettingsDetailActive(_engine);}
- (void)setSelectedIndex:(NSInteger)index {_model.selected=(int)index;_model.navigationFocus=true;[self updateModel];}
- (void)setLog:(NSAttributedString *)log {
    _model.log.clear();_model.logColors.clear();
    [log.string enumerateSubstringsInRange:NSMakeRange(0,log.length) options:NSStringEnumerationByLines usingBlock:^(NSString *line,NSRange range,NSRange enclosing,BOOL *stop){
        self->_model.log.emplace_back(line.UTF8String?:"");
        UIColor *color=range.location<log.length?[log attribute:NSForegroundColorAttributeName atIndex:range.location effectiveRange:NULL]:nil;
        CGFloat r=1,g=1,b=1,a=1;[color getRed:&r green:&g blue:&b alpha:&a];
        self->_model.logColors.push_back(r>0.9 && g<0.5?"#FF4040":"normal");
    }];
    if(_engine)NXTWRPSetModel(_engine,_model);[self setNeedsDisplay];
}
- (void)setOperationProgress:(double)fraction status:(NSString *)status {
    int progress=(int)lround((std::isfinite(fraction)?std::clamp(fraction,0.0,1.0):0.0)*100);
    std::string text=status.UTF8String?:"";if(_model.progress==progress && _model.progressStatus==text)return;
    _model.progress=progress;_model.progressStatus=text;[self updateModel];
}
- (void)clearOperationProgress {
    if(_model.progress<0)return;_model.progress=-1;_model.progressStatus.clear();[self updateModel];
}
- (void)setConsole:(BOOL)console completionEnabled:(BOOL)enabled {
    if(!console){_model.progress=-1;_model.progressStatus.clear();}
    _model.console=console;_model.complete=enabled;[self updateModel];
}
- (void)setConsoleCompletionTitle:(NSString *)title status:(NSString *)status {
    _model.completeTitle=title.UTF8String?:"Continue";_model.completeStatus=status.UTF8String?:"Complete";[self updateModel];
}
- (void)setTerminal:(BOOL)terminal {
    if(_model.terminal==(bool)terminal)return;
    _model.terminal=terminal;[self updateModel];
    if(terminal)[self becomeFirstResponder];else [self resignFirstResponder];
}
/* hardware keyboards type into the terminal */
- (BOOL)canBecomeFirstResponder {return _model.terminal;}
- (void)pressesBegan:(NSSet<UIPress *> *)presses withEvent:(UIPressesEvent *)event {
    if(!_model.terminal || _model.console){[super pressesBegan:presses withEvent:event];return;}
    BOOL handled=NO;
    for(UIPress *press in presses) {
        UIKey *key=press.key;if(!key)continue;
        int special=0;
        switch(key.keyCode) {
            case UIKeyboardHIDUsageKeyboardUpArrow:special=NXTWRPTerminalKeyUp;break;
            case UIKeyboardHIDUsageKeyboardDownArrow:special=NXTWRPTerminalKeyDown;break;
            case UIKeyboardHIDUsageKeyboardLeftArrow:special=NXTWRPTerminalKeyLeft;break;
            case UIKeyboardHIDUsageKeyboardRightArrow:special=NXTWRPTerminalKeyRight;break;
            case UIKeyboardHIDUsageKeyboardHome:special=NXTWRPTerminalKeyHome;break;
            case UIKeyboardHIDUsageKeyboardEnd:special=NXTWRPTerminalKeyEnd;break;
            case UIKeyboardHIDUsageKeyboardPageUp:special=NXTWRPTerminalKeyPageUp;break;
            case UIKeyboardHIDUsageKeyboardPageDown:special=NXTWRPTerminalKeyPageDown;break;
            case UIKeyboardHIDUsageKeyboardDeleteForward:special=NXTWRPTerminalKeyDelete;break;
            case UIKeyboardHIDUsageKeyboardEscape:special=NXTWRPTerminalKeyEscape;break;
            case UIKeyboardHIDUsageKeyboardTab:special=NXTWRPTerminalKeyTab;break;
            case UIKeyboardHIDUsageKeyboardDeleteOrBackspace:special=NXTWRPTerminalKeyBackspace;break;
            case UIKeyboardHIDUsageKeyboardReturnOrEnter:case UIKeyboardHIDUsageKeypadEnter:special=NXTWRPTerminalKeyReturn;break;
            default:break;
        }
        if(special){NXTWRPTerminalSendKey(special);handled=YES;continue;}
        NSString *characters=(key.modifierFlags & UIKeyModifierControl)?key.charactersIgnoringModifiers:key.characters;
        if(!characters.length)continue;
        if(key.modifierFlags & UIKeyModifierControl) {
            unichar c=[characters.lowercaseString characterAtIndex:0];
            if(c>='a' && c<='z'){char ctrl=(char)(c-'a'+1);NXTWRPTerminalSendText(&ctrl,1);handled=YES;}
            else if(c=='['||c=='\\'||c==']'||c=='^'||c=='_'){char ctrl=(char)(c & 0x1f);NXTWRPTerminalSendText(&ctrl,1);handled=YES;}
            continue;
        }
        const char *utf8=characters.UTF8String;
        if(key.modifierFlags & UIKeyModifierAlternate){char esc=0x1b;NXTWRPTerminalSendText(&esc,1);}
        NXTWRPTerminalSendText(utf8,strlen(utf8));handled=YES;
    }
    if(handled)[self setNeedsDisplay];else [super pressesBegan:presses withEvent:event];
}
- (void)drawRect:(CGRect)rect {
    if(self.renderError || !_engine) {
        [([@"Recovery UI could not load.\n" stringByAppendingString:self.renderError?:@"TWRP engine unavailable"]) drawInRect:CGRectInset(self.bounds,20,100)
             withAttributes:@{NSFontAttributeName:[UIFont systemFontOfSize:18],NSForegroundColorAttributeName:UIColor.whiteColor}];
        return;
    }
    CGRect canvas=self.canvas;if(canvas.size.width<1 || canvas.size.height<1)return;
    CGContextRef c=UIGraphicsGetCurrentContext();
    CGContextSetFillColorWithColor(c,UIColor.blackColor.CGColor);CGContextFillRect(c,self.bounds);
    CGContextSaveGState(c);
    CGContextTranslateCTM(c,canvas.origin.x,canvas.origin.y);CGContextScaleCTM(c,canvas.size.width/1080.0,canvas.size.width/1080.0);
    try {
        NXTWRPRender(_engine,c,1080,lround(canvas.size.height*1080/canvas.size.width));
    }catch(const std::exception& e){self.renderError=@(e.what());NSLog(@"TWRP renderer: %@",self.renderError);}
    CGContextRestoreGState(c);
    if(_engine && !self.renderError) {
        CGContextSetFillColorWithColor(c,NXTWRPAccentColor(_engine).CGColor);
        CGContextFillRect(c,CGRectMake(canvas.origin.x,0,canvas.size.width,canvas.origin.y));
        // The stock status strip is a #00000030 overlay on the accent color.
        // Continue it above the safe-area content origin to the physical top edge.
        CGContextSetFillColorWithColor(c,[UIColor colorWithWhite:0 alpha:48/255.0].CGColor);
        CGContextFillRect(c,CGRectMake(canvas.origin.x,0,canvas.size.width,canvas.origin.y));
        // Extend the navigation bar background through the iOS home gesture area.
        CGContextSetFillColorWithColor(c,UIColor.blackColor.CGColor);
        CGContextFillRect(c,CGRectMake(0,CGRectGetMaxY(canvas),self.bounds.size.width,MAX(0,self.bounds.size.height-CGRectGetMaxY(canvas))));
    }
}
/* The same adapter entry point is exercised by physical touches and Simulator tests.
 * 0=start, 1=drag, 2=release, 3=cancel, 4=hold, 5=repeat. Coordinates are view points, not XML pixels. */
- (void)routeTWRPTouch:(NSInteger)state atPoint:(CGPoint)point {
    if(!_engine || self.renderError)return;
    if(state==0 && !CGRectContainsPoint(self.canvas,point))return;
    if(state==0) {
        NXTWRPPrepareFeedback(_engine);
        _tracking=YES;_model.navigationFocus=false;NXTWRPSetNavigationFocus(_engine,false);
    }
    self.keyTouchPoint=point;
    if(state==2){[self.keyHoldTimer invalidate];self.keyHoldTimer=nil;}
    if(!_tracking)return;
    if(state==3) {[self cancelTouch];return;}
    CGRect canvas=self.canvas;float scale=1080.0/MAX(1,canvas.size.width);
    int x=lround((point.x-canvas.origin.x)*scale),y=lround((point.y-canvas.origin.y)*scale);
    if(state==2)_tracking=NO;
    std::vector<NXTWRPEvent> events;
    try {events=NXTWRPTouch(_engine,(int)(state>=4?state-1:state),x,y);}catch(const std::exception& e){self.renderError=@(e.what());return;}
    if(_model.terminal && !_model.console && state==0)for(auto key:NXTWRPKeyboardKeys(_engine))if(CGRectContainsPoint(key.bounds,CGPointMake(x,y))) {
        __weak NXRecoverySurface *weakSelf=self;
        self.keyHoldTimer=[NSTimer timerWithTimeInterval:0.5 repeats:NO block:^(NSTimer *timer){
            NXRecoverySurface *s=weakSelf;if(!s || !s->_tracking)return;
            [s routeTWRPTouch:4 atPoint:s.keyTouchPoint];
            if(s->_tracking) {
                s.keyHoldTimer=[NSTimer timerWithTimeInterval:0.08 repeats:YES block:^(NSTimer *repeat){
                    NXRecoverySurface *current=weakSelf;if(current && current->_tracking)[current routeTWRPTouch:5 atPoint:current.keyTouchPoint];else [repeat invalidate];
                }];
                [NSRunLoop.mainRunLoop addTimer:s.keyHoldTimer forMode:NSRunLoopCommonModes];
            }
        }];
        [NSRunLoop.mainRunLoop addTimer:self.keyHoldTimer forMode:NSRunLoopCommonModes];break;
    }
    if([self textInputActive]) {
        BOOL hidden=NXTWRPKeyboardHidden(_engine);
        if(_model.keyboardHidden!=hidden){_model.keyboardHidden=hidden;self.modelGeneration++;}
        auto password=NXTWRPCertificatePassword(_engine);
        if(password!=_model.password){_model.password=password;if(self.onPasswordChanged)self.onPasswordChanged(@(password.c_str()));}
        if(state==2)self.modelGeneration++;
        if(state==0)for(auto key:NXTWRPKeyboardKeys(_engine))if(CGRectContainsPoint(key.bounds,CGPointMake(x,y))) {
            __weak NXRecoverySurface *weakSelf=self;
            self.keyHoldTimer=[NSTimer timerWithTimeInterval:0.5 repeats:NO block:^(NSTimer *timer){
                NXRecoverySurface *s=weakSelf;if(!s || !s->_tracking)return;
                [s routeTWRPTouch:4 atPoint:s.keyTouchPoint];
                if(s->_tracking) {
                    s.keyHoldTimer=[NSTimer timerWithTimeInterval:0.08 repeats:YES block:^(NSTimer *repeat){
                        NXRecoverySurface *current=weakSelf;if(current && current->_tracking)[current routeTWRPTouch:5 atPoint:current.keyTouchPoint];else [repeat invalidate];
                    }];
                    [NSRunLoop.mainRunLoop addTimer:s.keyHoldTimer forMode:NSRunLoopCommonModes];
                }
            }];
            [NSRunLoop.mainRunLoop addTimer:self.keyHoldTimer forMode:NSRunLoopCommonModes];break;
        }
    }
    if(state==2)self.modelGeneration++;
    [self setNeedsDisplay];
    for(const auto& e:events) switch(e.kind) {
        case NXTWRPEvent::Select: if(self.onSelect)self.onSelect(e.index);break;
        case NXTWRPEvent::Back: if([self textInputActive] && !_model.keyboardHidden){_model.keyboardHidden=true;[self updateModel];}else if(_model.showLog){_model.showLog=false;[self updateModel];}else if(self.onBack)self.onBack();break;
        case NXTWRPEvent::Home: if(self.onHome)self.onHome();break;
        case NXTWRPEvent::Log: _model.showLog=!_model.showLog;[self updateModel];break;
        case NXTWRPEvent::Complete: if(self.onComplete)self.onComplete();break;
        case NXTWRPEvent::Sort:NXTWRPSortFiles(_engine,e.index);self.modelGeneration++;break;
        case NXTWRPEvent::Settings:break;
    }
}
// Accessibility mirrors the hit regions exported by the actual upstream objects.
- (NSArray *)accessibilityElements {
    if(!_engine || self.renderError)return @[];
    NSMutableArray *out=[NSMutableArray array];__weak NXRecoverySurface *weakSelf=self;
    NSUInteger generation=self.modelGeneration;
    CGRect canvas=self.canvas;CGFloat scale=canvas.size.width/1080;
    for(const auto& bound:NXTWRPBindings(_engine)) {
        NXTWRPEvent event=bound.first;CGRect rect=bound.second;
        rect=CGRectMake(rect.origin.x*scale+canvas.origin.x,rect.origin.y*scale+canvas.origin.y,rect.size.width*scale,rect.size.height*scale);
        rect=CGRectIntersection(rect,canvas);if(CGRectIsNull(rect) || CGRectIsEmpty(rect))continue;
        BOOL enabled=YES,checked=NO;NSString *label=nil;
        switch(event.kind) {
            case NXTWRPEvent::Select: {
                int i=event.index;if(i<0 || i>=(int)_model.titles.size())continue;
                label=@(_model.titles[i].c_str());enabled=i<(int)_model.enabled.size() && _model.enabled[i];
                checked=i<(int)_model.checks.size() && _model.checks[i]>=0 && (_model.checks[i]&1);break;
            }
            case NXTWRPEvent::Back:label=@"Back";enabled=(_model.back || _model.showLog || ([self textInputActive] && !_model.keyboardHidden)) && !_model.console;break;
            case NXTWRPEvent::Home:label=@"Home";enabled=_model.back && !_model.console;break;
            case NXTWRPEvent::Log:label=@"Recovery log";enabled=!_model.console;break;
            case NXTWRPEvent::Complete:label=@(_model.completeTitle.c_str());enabled=_model.complete && _model.console;break;
            case NXTWRPEvent::Sort:label=abs(event.index)==1?@"Name":abs(event.index)==2?@"Date":@"Size";break;
            case NXTWRPEvent::Settings:label=@(NXTWRPSettingsLabel(_engine,event.index).c_str());checked=NXTWRPSettingsValue(_engine,event.index)=="Selected";break;
        }
        NXRecoveryAccessibleControl *element=[[NXRecoveryAccessibleControl alloc] initWithAccessibilityContainer:self];
        element.accessibilityLabel=label;element.accessibilityFrameInContainerSpace=rect;
        element.accessibilityTraits=UIAccessibilityTraitButton|(enabled?0:UIAccessibilityTraitNotEnabled)|(checked?UIAccessibilityTraitSelected:0);
        if(event.kind==NXTWRPEvent::Select && event.index<(int)_model.checks.size() && _model.checks[event.index]>=0)element.accessibilityValue=checked?@"On":@"Off";
        if(event.kind==NXTWRPEvent::Settings) {
            element.accessibilityValue=@(NXTWRPSettingsValue(_engine,event.index).c_str());
            if(event.index>=10000) {
                element.accessibilityTraits=UIAccessibilityTraitAdjustable;
                __weak NXRecoveryAccessibleControl *weakElement=element;
                element.adjust=^(NSInteger delta){NXRecoverySurface *s=weakSelf;if(!s || s.modelGeneration!=generation)return;NXTWRPAdjustSetting(s->_engine,event.index,(int)delta);weakElement.accessibilityValue=@(NXTWRPSettingsValue(s->_engine,event.index).c_str());[s setNeedsDisplay];};
            }
        }
        if(enabled)element.activate=^BOOL{
            NXRecoverySurface *s=weakSelf;if(!s || s.modelGeneration!=generation)return NO;
            switch(event.kind) {
                case NXTWRPEvent::Select:if(s.onSelect)s.onSelect(event.index);break;
                case NXTWRPEvent::Back:if([s textInputActive] && !s->_model.keyboardHidden){s->_model.keyboardHidden=true;[s updateModel];}else if(s->_model.showLog){s->_model.showLog=false;[s updateModel];}else if(s.onBack)s.onBack();break;
                case NXTWRPEvent::Home:if(s.onHome)s.onHome();break;
                case NXTWRPEvent::Log:s->_model.showLog=!s->_model.showLog;[s updateModel];break;
                case NXTWRPEvent::Complete:if(s.onComplete)s.onComplete();break;
                case NXTWRPEvent::Sort:NXTWRPSortFiles(s->_engine,event.index);s.modelGeneration++;[s setNeedsDisplay];break;
                case NXTWRPEvent::Settings:if(event.index>=10000)return NO;NXTWRPActivateSettings(s->_engine,event.index);s.modelGeneration++;[s setNeedsDisplay];break;
            }return YES;
        };[out addObject:element];
    }
    for(auto key:NXTWRPKeyboardKeys(_engine)) {
        CGRect rect=CGRectMake(key.bounds.origin.x*scale+canvas.origin.x,key.bounds.origin.y*scale+canvas.origin.y,key.bounds.size.width*scale,key.bounds.size.height*scale);
        rect=CGRectIntersection(rect,canvas);if(CGRectIsNull(rect) || CGRectIsEmpty(rect))continue;
        BOOL enabled=_model.enabled.size()>1 && _model.enabled[1];
        NXRecoveryAccessibleControl *element=[[NXRecoveryAccessibleControl alloc] initWithAccessibilityContainer:self];
        element.accessibilityLabel=@(key.label.c_str());element.accessibilityFrameInContainerSpace=rect;
        element.accessibilityTraits=UIAccessibilityTraitKeyboardKey|(enabled?0:UIAccessibilityTraitNotEnabled);
        if(enabled)element.activate=^BOOL{
            NXRecoverySurface *s=weakSelf;if(!s || s.modelGeneration!=generation)return NO;
            CGPoint point=CGPointMake(CGRectGetMidX(rect),CGRectGetMidY(rect));
            [s routeTWRPTouch:0 atPoint:point];[s routeTWRPTouch:2 atPoint:point];return YES;
        };[out addObject:element];
    }
    if(_model.progress>=0) {
        UIAccessibilityElement *progress=[[UIAccessibilityElement alloc] initWithAccessibilityContainer:self];
        progress.accessibilityLabel=@(_model.progressStatus.c_str());progress.accessibilityValue=[NSString stringWithFormat:@"%d%%",_model.progress];
        progress.accessibilityTraits=UIAccessibilityTraitStaticText|UIAccessibilityTraitUpdatesFrequently;progress.accessibilityFrameInContainerSpace=self.canvas;[out addObject:progress];
    }
    if(_model.console || _model.showLog) {
        UIAccessibilityElement *log=[[UIAccessibilityElement alloc] initWithAccessibilityContainer:self];
        NSMutableArray *lines=[NSMutableArray array];for(size_t i=_model.log.size()>50?_model.log.size()-50:0;i<_model.log.size();i++)[lines addObject:@(_model.log[i].c_str())];
        log.accessibilityLabel=[lines componentsJoinedByString:@"\n"];log.accessibilityTraits=UIAccessibilityTraitStaticText;log.accessibilityFrameInContainerSpace=self.canvas;[out addObject:log];
    }
    return out;
}
- (BOOL)accessibilityScroll:(UIAccessibilityScrollDirection)direction {
    if(!_engine || _model.home || _model.confirmation || _model.console || _model.showLog)return NO;
    if(direction!=UIAccessibilityScrollDirectionUp && direction!=UIAccessibilityScrollDirectionDown)return NO;
    auto rows=NXTWRPScrollBounds(_engine);if(rows.empty())return NO;
    CGRect c=self.canvas;CGFloat scale=c.size.width/1080;
    CGFloat top=rows.front().origin.y*scale+c.origin.y+20;
    CGFloat bottom=CGRectGetMaxY(rows.back())*scale+c.origin.y-20;
    bottom=MIN(bottom,CGRectGetMaxY(c)-80);if(bottom<=top)return NO;
    CGPoint start=CGPointMake(CGRectGetMidX(c),direction==UIAccessibilityScrollDirectionDown?bottom:top);
    CGPoint end=CGPointMake(start.x,direction==UIAccessibilityScrollDirectionDown?top:bottom);
    [self routeTWRPTouch:0 atPoint:start];[self routeTWRPTouch:1 atPoint:end];
    [self routeTWRPTouch:1 atPoint:end];[self routeTWRPTouch:2 atPoint:end];
    UIAccessibilityPostNotification(UIAccessibilityPageScrolledNotification,nil);return YES;
}
- (void)cancelTouch {
    [self.keyHoldTimer invalidate];self.keyHoldTimer=nil;
    if(!_tracking || !_engine)return;_tracking=NO;
    /* Move outside the upstream slider before releasing: cancellation must never confirm. */
    NXTWRPTouch(_engine,1,-10000,-10000);NXTWRPTouch(_engine,2,-10000,-10000);
}
- (void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {[self routeTWRPTouch:0 atPoint:[touches.anyObject locationInView:self]];}
- (void)touchesMoved:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {[self routeTWRPTouch:1 atPoint:[touches.anyObject locationInView:self]];}
- (void)touchesEnded:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {[self routeTWRPTouch:2 atPoint:[touches.anyObject locationInView:self]];}
- (void)touchesCancelled:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {[self cancelTouch];}
- (NSArray<NSValue *> *)twrpControlBounds:(BOOL)sliders {
    NSMutableArray *out=[NSMutableArray array];if(!_engine)return out;
    for(CGRect r:NXTWRPControlBounds(_engine,sliders)) {CGRect c=self.canvas;CGFloat s=c.size.width/1080;r=CGRectMake(r.origin.x*s+c.origin.x,r.origin.y*s+c.origin.y,r.size.width*s,r.size.height*s);[out addObject:[NSValue valueWithCGRect:r]];}
    return out;
}
@end
