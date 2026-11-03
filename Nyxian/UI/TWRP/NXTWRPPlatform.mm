/* SPDX-License-Identifier: GPL-3.0-or-later
 * iOS platform adapter for TeamWin's GUI widgets. No Android recovery operations.
 */
#import <UIKit/UIKit.h>
#import <CoreText/CoreText.h>
#import <ImageIO/ImageIO.h>
#import "NXTWRPThemeStore.h"
#import "NXTWRPSplash.h"
#include "NXTWRPEngine.hpp"
#include "NXTWRPTerminal.hpp"
#include "Upstream/gui/objects.hpp"
#include "Upstream/NXTWRPBridge.hpp"
#include <memory>
#include <map>
#include <algorithm>
#include <cmath>
#include <stdexcept>
#include <set>
#include <optional>

namespace rapidxml { void parse_error_handler(const char *what,void *) {throw std::runtime_error(what);} }

static CGContextRef context;
static UIColor *ink;
static bool clipped;
static int framebufferWidth=1080,framebufferHeight=1920;
static float scaleW=1,scaleH=1;
static NXTWRPEngine *active;
static NSString *themeAssets;
static size_t loadedImagePixels;
// TW_MAIN_VERSION_STR from variables.h at the pinned TeamWin commit in UPSTREAM.json.
static constexpr const char *upstreamTWRPVersion="3.7.1_12";
static const std::vector<std::string> settingsPages={"settings","settings_timezone","settings_screen","settings_vibration","settings_language"};
static const std::vector<std::string> settingsNames={"General","Time Zone","Screen","Vibration","Language"};
static const std::vector<std::string> settingsVariables={"tw_brightness_pct","tw_button_vibrate","tw_keyboard_vibrate"};
static bool IsSettings(const NXTWRPModel& m) {return m.header=="Settings" && !m.console && !m.showLog && !m.confirmation && m.browserPath.empty() && std::any_of(m.checks.begin(),m.checks.end(),[](int v){return v>=0;});}
static bool IsWipeHome(const NXTWRPModel& m) {return m.header=="Wipe" && m.titles.size()==3;}
static bool IsAdvancedWipe(const NXTWRPModel& m) {return m.header=="Wipe\nAdvanced Wipe" && m.titles.size()==5;}
static bool IsFormatData(const NXTWRPModel& m) {return m.header=="Wipe\nFormat Data" && m.titles.size()==3;}
static bool HasTextInput(const NXTWRPModel& m) {return m.certificate || IsFormatData(m) || NXTWRPIsFileManagerInput(m) || NXTWRPIsBootArgumentsInput(m);}
static bool IsFileManagerPage(const NXTWRPModel& m) {return NXTWRPIsFileManagerOptions(m) || NXTWRPIsFileManagerConfirm(m) || NXTWRPIsFileManagerInput(m);}
// "{@fm_copy_file_btn=Copy File}" -> "Copy File": the English default of a TWRP string resource
static std::string DefaultText(std::string t) {
    for(size_t b;(b=t.find("{@"))!=std::string::npos;) {
        size_t e=t.find('}',b);if(e==std::string::npos)break;
        size_t eq=t.find('=',b);std::string value=eq!=std::string::npos && eq<e?t.substr(eq+1,e-eq-1):"";
        t=t.substr(0,b)+value+t.substr(e+1);
    }return t;
}
static int WipeSliderIndex(const NXTWRPModel& m) {return IsWipeHome(m)?2:IsAdvancedWipe(m)?3:-1;}
static NSString *PreferenceKey(const std::string& variable) {return [@"nyxian.recovery." stringByAppendingString:@(variable.c_str())];}
static void RegisterSettings() {
    [NSUserDefaults.standardUserDefaults registerDefaults:@{@"nyxian.recovery.tw_military_time":@YES,@"nyxian.recovery.tw_button_vibrate":@80,@"nyxian.recovery.tw_keyboard_vibrate":@40}];
}
static int ConfiguredBrightness() {
    NSNumber *saved=[NSUserDefaults.standardUserDefaults objectForKey:@"nyxian.recovery.tw_brightness_pct"];
    return std::clamp(saved?saved.intValue:(int)lround(UIScreen.mainScreen.brightness*100),10,100);
}
static std::string RecoveryTime() {
    NSDateFormatter *formatter=[NSDateFormatter new];formatter.locale=[NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
    formatter.dateFormat=[NSUserDefaults.standardUserDefaults boolForKey:@"nyxian.recovery.tw_military_time"]?@"HH:mm":@"h:mm a";
    NSString *zone=[NSUserDefaults.standardUserDefaults stringForKey:@"nyxian.recovery.timezone"];
    formatter.timeZone=(zone.length?[NSTimeZone timeZoneWithName:zone]:nil)?:NSTimeZone.localTimeZone;
    return [formatter stringFromDate:NSDate.date].UTF8String;
}
static const std::vector<std::pair<std::string,std::string>>& TimeZones() {
    static std::vector<std::pair<std::string,std::string>> zones;
    if(zones.empty()) {
        zones.push_back({"Use Device Time Zone",""});
        for(NSString *name in [NSTimeZone.knownTimeZoneNames sortedArrayUsingSelector:@selector(compare:)]) {
            NSInteger offset=[[NSTimeZone timeZoneWithName:name] secondsFromGMTForDate:NSDate.date]/60;
            NSString *label=[NSString stringWithFormat:@"(UTC %@%02ld:%02ld) %@",offset<0?@"−":@"+",labs(offset)/60,labs(offset)%60,name];
            zones.push_back({label.UTF8String,name.UTF8String});
        }
    }return zones;
}
static NSString *Asset(const char *file) {
    NSString *relative=@(file);
    if(themeAssets && !relative.isAbsolutePath && ![relative.pathComponents containsObject:@".."] && ![relative containsString:@"\\"]) {
        NSArray *candidates=@[relative,[@"images" stringByAppendingPathComponent:relative],[@"fonts" stringByAppendingPathComponent:relative]];
        for(NSString *__strong candidate in candidates) {
            if(!candidate.pathExtension.length)candidate=[candidate stringByAppendingPathExtension:@"png"];
            NSString *path=[themeAssets stringByAppendingPathComponent:candidate];
            if([NSFileManager.defaultManager fileExistsAtPath:path])return path;
        }
    }
    NSString *name=relative.lastPathComponent;
    if(!name.pathExtension.length) name=[name stringByAppendingPathExtension:@"png"];
    return [NSBundle.mainBundle pathForResource:[@"Shared/TWRP/" stringByAppendingString:name.stringByDeletingPathExtension] ofType:name.pathExtension];
}
extern "C" {
void set_scale_values(float w,float h) { scaleW=w;scaleH=h; }
int scale_theme_x(int n) { return lround(n*scaleW); }
int scale_theme_y(int n) { return lround(n*scaleH); }
int scale_theme_min(int n) { return lround(n*std::min(scaleW,scaleH)); }
float get_scale_w() { return scaleW; }
float get_scale_h() { return scaleH; }
int gr_fb_width() { return framebufferWidth; }
int gr_fb_height() { return framebufferHeight; }
void gr_color(unsigned char r,unsigned char g,unsigned char b,unsigned char a) { ink=[UIColor colorWithRed:r/255.0 green:g/255.0 blue:b/255.0 alpha:a/255.0]; }
void gr_noclip() { if(context && clipped) CGContextRestoreGState(context); clipped=false; }
void gr_clip(int x,int y,int w,int h) { gr_noclip(); if(!context)return; CGContextSaveGState(context);clipped=true;CGContextClipToRect(context,CGRectMake(x,y,w,h)); }
void gr_fill(int x,int y,int w,int h) {
    if(!context)return;
    // minui fills are pixel-aligned. Antialiasing adjacent scaled rectangles
    // blends their shared edge with the background, leaving a false dark seam.
    CGContextSaveGState(context);CGContextSetShouldAntialias(context,false);
    CGContextSetFillColorWithColor(context,ink.CGColor);CGContextFillRect(context,CGRectMake(x,y,w,h));
    CGContextRestoreGState(context);
}
void gr_line(int x,int y,int x2,int y2,int width) { if(!context)return;CGContextSetStrokeColorWithColor(context,ink.CGColor);CGContextSetLineWidth(context,width);CGContextMoveToPoint(context,x,y);CGContextAddLineToPoint(context,x2,y2);CGContextStrokePath(context); }
unsigned int gr_get_width(gr_surface p) { return p?lround(((__bridge UIImage*)p).size.width):0; }
unsigned int gr_get_height(gr_surface p) { return p?lround(((__bridge UIImage*)p).size.height):0; }
void res_free_surface(gr_surface p) { if(p) CFRelease(p); }
int res_create_surface(const char *name,gr_surface *out) { NSString *path=Asset(name);UIImage *image=nil;
    if(path) {CGImageSourceRef source=CGImageSourceCreateWithURL((__bridge CFURLRef)[NSURL fileURLWithPath:path],nullptr);
        NSDictionary *properties=source?CFBridgingRelease(CGImageSourceCopyPropertiesAtIndex(source,0,nullptr)):nil;
        NSUInteger w=[properties[(__bridge NSString*)kCGImagePropertyPixelWidth] unsignedIntegerValue],h=[properties[(__bridge NSString*)kCGImagePropertyPixelHeight] unsignedIntegerValue];
        if(source)CFRelease(source);
        if(themeAssets && [path hasPrefix:[themeAssets stringByAppendingString:@"/"]] && (!w || !h || w>4096 || h>4096))throw std::runtime_error("Invalid or oversized theme image");
        if(w && h && w<=4096 && h<=4096) {loadedImagePixels+=w*h;if(loadedImagePixels>32*1024*1024)throw std::runtime_error("Theme image memory limit exceeded");image=[UIImage imageWithContentsOfFile:path];}
    } *out=image?(void*)CFBridgingRetain(image):nullptr;return *out?0:-1; }
int res_scale_surface(gr_surface source,gr_surface *out,float w,float h) {
    UIImage *image=(__bridge UIImage*)source;if(!image || w<=0 || h<=0)return -1;
    UIGraphicsImageRendererFormat *f=[UIGraphicsImageRendererFormat defaultFormat];f.scale=1;
    CGSize size=CGSizeMake(MAX(1,lround(image.size.width*w)),MAX(1,lround(image.size.height*h)));
    if(size.width>8192 || size.height>8192 || size.width*size.height>16*1024*1024)throw std::runtime_error("Scaled theme image is too large");
    UIImage *scaled=[[[UIGraphicsImageRenderer alloc] initWithSize:size format:f] imageWithActions:^(UIGraphicsImageRendererContext *c){[image drawInRect:(CGRect){CGPointZero,size}];}];
    *out=(void*)CFBridgingRetain(scaled);res_free_surface(source);return 0;
}
void gr_blit(gr_surface p,int sx,int sy,int w,int h,int dx,int dy) {
    if(!p || !context || w<=0 || h<=0)return;
    CGImageRef crop=CGImageCreateWithImageInRect(((__bridge UIImage*)p).CGImage,CGRectMake(sx,sy,w,h));
    if(crop) { [[UIImage imageWithCGImage:crop] drawInRect:CGRectMake(dx,dy,w,h)];CGImageRelease(crop); }
}
int gr_textEx_scaleW(int x,int y,const char *s,void *font,int maxWidth,int placement,int scale) {
    if(!font || !context)return 0;
    UIFont *f=(__bridge UIFont*)font;NSString *text=@(s?:"");
    CGSize size=[text sizeWithAttributes:@{NSFontAttributeName:f}];
    if(scale && maxWidth>0 && size.width>maxWidth) {f=[f fontWithSize:f.pointSize*maxWidth/size.width];size=[text sizeWithAttributes:@{NSFontAttributeName:f}];}
    CGFloat px=x,py=y;
    if(placement==CENTER || placement==CENTER_X_ONLY)px-=size.width/2;
    if(placement==TOP_RIGHT || placement==BOTTOM_RIGHT)px-=size.width;
    if(placement==CENTER || placement==TEXT_ONLY_RIGHT)py-=size.height/2;
    if(placement==BOTTOM_LEFT || placement==BOTTOM_RIGHT)py-=size.height;
    CGContextSaveGState(context);
    if(maxWidth>0)CGContextClipToRect(context,CGRectMake(px,py,maxWidth,size.height+2));
    [text drawAtPoint:CGPointMake(px,py) withAttributes:@{NSFontAttributeName:f,NSForegroundColorAttributeName:ink?:UIColor.whiteColor}];
    CGContextRestoreGState(context);return (int)text.length;
}
}
void *twrpTruetype::gr_ttf_loadFont(const char *file,int size,int dpi) {
    NSString *path=Asset(file); NSURL *url=path?[NSURL fileURLWithPath:path]:nil;
    if(!url || size<=0 || size>256)return nullptr;
    static NSMutableSet<NSString *> *registered; if(!registered)registered=[NSMutableSet set];
    if(![registered containsObject:path]) {CTFontManagerRegisterFontsForURL((__bridge CFURLRef)url,kCTFontManagerScopeProcess,NULL);[registered addObject:path];}
    CGDataProviderRef data=CGDataProviderCreateWithURL((__bridge CFURLRef)url);CGFontRef cg=data?CGFontCreateWithDataProvider(data):nullptr;
    NSString *name=cg?CFBridgingRelease(CGFontCopyPostScriptName(cg)):nil;
    UIFont *font=name?[UIFont fontWithName:name size:size]:nil;
    if(cg)CGFontRelease(cg);if(data)CGDataProviderRelease(data);
    return font?(void*)CFBridgingRetain(font):nullptr;
}
void *twrpTruetype::gr_ttf_scaleFont(void *font,int maxWidth,int measured) {return (void*)CFBridgingRetain([(__bridge UIFont*)font fontWithSize:((__bridge UIFont*)font).pointSize*maxWidth/MAX(1,measured)]);}
void twrpTruetype::gr_ttf_freeFont(void *p) {if(p)CFRelease(p);}
int twrpTruetype::gr_ttf_getMaxFontHeight(void *p) {return p?ceil(((__bridge UIFont*)p).lineHeight):0;}
int twrpTruetype::gr_ttf_measureEx(const char *s,void *p) {return p?ceil([@(s) sizeWithAttributes:@{NSFontAttributeName:(__bridge UIFont*)p}].width):0;}
int twrpTruetype::gr_ttf_maxExW(const char *s,void *p,int width) {
    NSString *text=@(s);NSUInteger best=0;
    while(best<text.length) {NSRange range=[text rangeOfComposedCharacterSequenceAtIndex:best];NSUInteger next=NSMaxRange(range);
        if(best && [[text substringToIndex:next] sizeWithAttributes:@{NSFontAttributeName:(__bridge UIFont*)p}].width>width)break;best=next;}
    return (int)[[text substringToIndex:best] lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
}
extern "C" int gr_getMaxFontHeight(void *p) {return twrpTruetype::gr_ttf_getMaxFontHeight(p);}

class NXPage : public Page {
public: NXPage(xml_node<>* n,std::vector<xml_node<>*>* t):Page(n,t){}
    std::vector<GUIObject*>& objects() {return mObjects;}
    std::vector<CGRect> controls(bool sliders) {std::vector<CGRect> out;
        for(auto o:mObjects) if(sliders?dynamic_cast<GUISlider*>(o)!=nullptr:dynamic_cast<GUIButton*>(o)!=nullptr) {
            auto r=dynamic_cast<RenderObject*>(o);int x,y,w,h;r->GetRenderPos(x,y,w,h);out.push_back(CGRectMake(x,y,w,h));}
        return out;
    }
};
struct NXThemeXML {xml_document<> doc;std::vector<char> buffer;};
class NXTWRPEngine {
public:
    NXTWRPModel model;
    std::map<std::string,std::string> values;
    std::unique_ptr<ResourceManager> resources;
    std::unique_ptr<NXPage> page;
    xml_document<> layout,portrait,dynamic;
    std::vector<char> layoutBuffer,portraitBuffer,dynamicBuffer;
    std::vector<xml_node<>*> templates;
    std::vector<NXTWRPEvent> events;
    int width=1080,height=1920,settingsTab=0,settingsScroll=0;
    std::string pendingTimeZone;
    bool reloadTheme=false,dirty=true,validating=false,input=false,checkboxInput=false,sliderInput=false,pendingSort=false,terminalPage=false;
    NSString *themePath=nil;
    __weak UIView *presentationView=nil;
    UIImpactFeedbackGenerator *feedback=nil;
    int themeWidth=1080,themeHeight=1920;
    std::vector<std::unique_ptr<NXThemeXML>> themeDocs;
    std::vector<xml_node<>*> styles;
    void loadThemeFile(const std::string&,std::set<std::string>&);
    void validatePage(xml_node<>*,int depth=0);
    xml_node<>* homeNode();
    void parseDesignXML(const std::string&);
    NSTimeInterval lastStatus=0;
    void activate() {active=this;framebufferWidth=width;framebufferHeight=height;themeAssets=themePath;set_scale_values((float)width/themeWidth,(float)height/themeHeight);}
    void load();void build();
};
static std::string Escape(std::string s) {
    std::string out; for(char c:s) switch(c) {case '&':out+="&amp;";break;case '<':out+="&lt;";break;case '>':out+="&gt;";break;case '"':out+="&quot;";break;default:out+=c;}return out;
}
static bool ReadXML(const char *name,xml_document<>&doc,std::vector<char>&buffer) {
    NSString *file=@(name);NSString *path=[NSBundle.mainBundle pathForResource:[@"Shared/TWRP/" stringByAppendingString:file.stringByDeletingPathExtension] ofType:file.pathExtension];
    NSData *d=[NSData dataWithContentsOfFile:path];if(!d)return false;
    buffer.assign((const char*)d.bytes,(const char*)d.bytes+d.length);buffer.push_back(0);doc.parse<0>(buffer.data());return true;
}
int DataManager::GetValue(const std::string& name,std::string& out) {
    if(!active)return -1;std::string key=name;if(key.size()>2 && key.front()=='%' && key.back()=='%')key=key.substr(1,key.size()-2);
    auto i=active->values.find(key);if(i==active->values.end())return -1;out=i->second;return 0;
}
int DataManager::GetValue(const std::string& n,int& out) {std::string s;int r=GetValue(n,s);out=atoi(s.c_str());return r;}
std::string DataManager::GetStrValue(const std::string& n) {std::string s;GetValue(n,s);return s;}
int DataManager::GetIntValue(const std::string& n) {int n2;GetValue(n,n2);return n2;}
int DataManager::SetValue(const std::string& n,const std::string& v,int) {
    if(!active)return -1;active->values[n]=v;
    if(active->input && IsSettings(active->model))for(size_t i=0;i<settingsVariables.size();i++)if(n==settingsVariables[i]) {
        int value=std::clamp(atoi(v.c_str()),i==0?10:0,i==0?100:300);
        active->values[n]=std::to_string(value);
        [NSUserDefaults.standardUserDefaults setInteger:value forKey:PreferenceKey(n)];
        if(i==0)(active->presentationView.window.screen?:UIScreen.mainScreen).brightness=value/100.0;
        if(active->page)active->page->NotifyVarChange(n,std::to_string(value));
    }
    if(active->input && n=="tw_gui_sort_order")active->pendingSort=true;
    if(active->input && !active->model.console && !active->model.browserPath.empty() && !v.empty() && (n=="nx_browser_path" || n=="nx_browser_result")) {
        auto& paths=active->model.filePaths;auto found=std::find(paths.begin(),paths.end(),v);
        if(found!=paths.end())active->events.push_back({NXTWRPEvent::Select,(int)(found-paths.begin())});
    }
    if(active->input && HasTextInput(active->model) && n=="nx_certificate_password")active->model.password=v;
    if(active->input && active->checkboxInput && !active->model.console && n.rfind("nx_check_",0)==0) {
        int index=atoi(n.c_str()+9);auto& m=active->model;
        if(index>=0 && index<(int)m.checks.size() && m.checks[index]>=0 && index<(int)m.enabled.size() && m.enabled[index])active->events.push_back({NXTWRPEvent::Select,index});
    }return 0;
}
int DataManager::SetValue(const std::string& n,int v,int p) {return SetValue(n,std::to_string(v),p);}
const ResourceManager *PageManager::GetResources() {return active?active->resources.get():nullptr;}
xml_node<> *PageManager::FindStyle(std::string name) {
    if(!active)return nullptr;
    for(auto styles:active->styles)for(auto s=styles?styles->first_node("style"):nullptr;s;s=s->next_sibling("style"))if(name==LoadAttrString(s,"name"))return s;
    return nullptr;
}
void PageManager::AddStringResource(std::string source,std::string name,std::string value) {if(active)active->resources->AddStringResource(source,name,value);}

int DataManager::Vibrate(const std::string& variable) {
    NSInteger amount=[NSUserDefaults.standardUserDefaults integerForKey:PreferenceKey(variable)];
    if(amount<=0 || !active || active->validating || !active->presentationView.window || !active->feedback)return 0;
    [active->feedback impactOccurredWithIntensity:0.25+0.75*std::clamp(amount/300.0,0.0,1.0)];
    [active->feedback prepare];return 0;
}
class NXSettingsList : public GUIScrollList {
    int kind,gap=-1;
    size_t generalCount() const {size_t count=kind==3?std::min<size_t>(3,active->model.titles.size()):active->model.titles.size();return count && active->model.titles.back()=="Restore Defaults"?count-1:count;}
    int nativeIndex(int row) const {if(kind!=0 || gap<0)return row;return row==gap?-1:row-(row>gap?1:0);}
    ImageResource *checked,*unchecked,*actionIcon;
public:
    NXSettingsList(xml_node<>* n):GUIScrollList(n),kind(LoadAttrInt(n,"kind",0)) {
        checked=LoadAttrImage(FindNode(n,"icon"),"selected");unchecked=LoadAttrImage(FindNode(n,"icon"),"unselected");
        actionIcon=active->resources->FindImage("handle");
        if(kind==0)for(size_t i=0;i<generalCount();i++)if(i>=active->model.checks.size() || active->model.checks[i]<0){if(i>0)gap=(int)i;break;}
        SetMaxIconSize(std::max(checked?checked->GetWidth():0,unchecked?unchecked->GetWidth():0),std::max(checked?checked->GetHeight():0,unchecked?unchecked->GetHeight():0));
        if(kind==0 || kind==3) {
            int row=active->model.selected;if(gap>=0 && row>=gap)row++;
            SetVisibleListLocation(active->model.navigationFocus?row:active->settingsScroll);
        }
    }
    int NotifyTouch(TOUCH_STATE state,int x,int y) override {
        int result=GUIScrollList::NotifyTouch(state,x,y);
        if(state==TOUCH_START && nativeIndex((int)selectedItem)<0)selectedItem=NO_ITEM;
        return result;
    }
    std::vector<std::pair<NXTWRPEvent,CGRect>> bindings() {
        std::vector<std::pair<NXTWRPEvent,CGRect>> out;
        for(int i=firstDisplayedItem,y=mRenderY+mHeaderH+y_offset;i<(int)GetItemCount() && y<mRenderY+mRenderH;i++,y+=actualItemHeight) {
            CGRect r=CGRectIntersection(CGRectMake(mRenderX,y,mRenderW,actualItemHeight),CGRectMake(mRenderX,mRenderY+mHeaderH,mRenderW,mRenderH-mHeaderH));
            int index=nativeIndex(i);
            if(i>=0 && index>=0 && !CGRectIsEmpty(r))out.push_back({{(kind==0 || kind==3)?NXTWRPEvent::Select:NXTWRPEvent::Settings,(kind==0 || kind==3)?index:100+i},r});
        }return out;
    }
protected:
    size_t GetItemCount() override {
        if(kind==1)return TimeZones().size();if(kind==2)return 1;
        return generalCount()+(gap>=0?1:0);
    }
    void RenderItem(size_t i,int y,bool pressed) override {
        int index=nativeIndex((int)i);if(index<0)return;i=(size_t)index;
        bool selected=false;std::string label;ImageResource *icon=nullptr;
        if(kind==0 || kind==3) {
            label=active->model.titles[i];int check=i<active->model.checks.size()?active->model.checks[i]:-1;
            icon=check>=0?((check&1)?checked:unchecked):actionIcon;
        } else {selected=kind==2 || TimeZones()[i].second==active->pendingTimeZone;label=kind==2?"English":TimeZones()[i].first;icon=selected?checked:unchecked;}
        COLOR saved=mFontColor;if((kind==0 || kind==3) && (i>=active->model.enabled.size() || !active->model.enabled[i]))mFontColor=COLOR(100,100,100);
        RenderStdItem(y,pressed || (active->model.navigationFocus && (kind==0 || kind==3) && (int)i==active->model.selected),icon,label.c_str());mFontColor=saved;
    }
    void NotifySelect(size_t i) override {
        if(kind==0 || kind==3){int index=nativeIndex((int)i);if(index<0)return;active->settingsScroll=firstDisplayedItem;nx_twrp_action("nyxian",std::to_string(index));}
        else if(kind==1)active->pendingTimeZone=TimeZones()[i].second;
    }
};
GUIObject *nx_twrp_settingslist(xml_node<>* n){return new NXSettingsList(n);}
class NXValueSlider : public GUISliderValue {
    int initial=0;
public:
    int setting=-1;
    NXValueSlider(xml_node<>* n):GUISliderValue(n){for(size_t i=0;i<settingsVariables.size();i++)if(mVariable==settingsVariables[i])setting=(int)i;}
    int NotifyTouch(TOUCH_STATE state,int x,int y) override {
        if(state==TOUCH_START)initial=DataManager::GetIntValue(mVariable);
        if((state==TOUCH_DRAG || state==TOUCH_RELEASE) && x==-10000 && y==-10000) {
            if(mDragging && mChangeOnDrag)DataManager::SetValue(mVariable,initial);
            mDragging=false;mRendered=false;return 0;
        }
        bool preview=state==TOUCH_RELEASE && mDragging && setting>0;
        int result=GUISliderValue::NotifyTouch(state,x,y);
        if(preview)DataManager::Vibrate(mVariable);
        return result;
    }
};
GUIObject *nx_twrp_slidervalue(xml_node<>* n){return new NXValueSlider(n);}
class NXMenu : public GUIScrollList {
    int start;
    ImageResource *selectedIcon=nullptr,*unselectedIcon=nullptr;
public: NXMenu(xml_node<>* n):GUIScrollList(n),start(std::max(0,LoadAttrInt(n,"start",0))){
        // Match GUIListBox: honor the theme's selected/unselected row icons.
        if(auto icon=FindNode(n,"icon")) {
            selectedIcon=LoadAttrImage(icon,"selected");unselectedIcon=LoadAttrImage(icon,"unselected");
            SetMaxIconSize(std::max(selectedIcon?selectedIcon->GetWidth():0,unselectedIcon?unselectedIcon->GetWidth():0),
                           std::max(selectedIcon?selectedIcon->GetHeight():0,unselectedIcon?unselectedIcon->GetHeight():0));
        }
        SetVisibleListLocation(MAX(0,active->model.selected-start));
    }
    std::vector<std::pair<int,CGRect>> itemBounds() {
        std::vector<std::pair<int,CGRect>> out;
        for(int i=firstDisplayedItem,y=mRenderY+mHeaderH+y_offset;i<(int)GetItemCount() && y<mRenderY+mRenderH;i++,y+=actualItemHeight)
            if(i>=0)out.push_back({i+start,CGRectMake(mRenderX,y,mRenderW,actualItemHeight)});
        return out;
    }
protected:
    size_t GetItemCount() override {return active->model.titles.size()>start?active->model.titles.size()-start:0;}
    void RenderItem(size_t i,int y,bool selected) override {
        i+=start;
        COLOR saved=mFontColor;if(i<active->model.enabled.size() && !active->model.enabled[i])mFontColor=COLOR(100,100,100);
        bool focused=selected || (active->model.navigationFocus && (int)i==active->model.selected);
        RenderStdItem(y,focused,focused?selectedIcon:unselectedIcon,active->model.titles[i].c_str());mFontColor=saved;
    }
    void NotifySelect(size_t i) override {nx_twrp_action("nyxian",std::to_string(i+start));}
};
GUIObject *nx_twrp_menu(xml_node<>* n) {return new NXMenu(n);}
// Upstream enumeration, sorting, drawing and selection; this subclass only maps
// visible file paths to Nyxian callbacks and exports focus/accessibility geometry.
class NXFileSelector : public GUIFileSelector {
public:
    NXFileSelector(xml_node<>* node):GUIFileSelector(node) {focusNative(active->model.selected);}
    int nativeIndex(size_t row) {
        size_t folders=mShowFolders?mFolderList.size():0;
        if(row>=GetItemCount())return -1;
        const auto& entry=row<folders?mFolderList[row]:mFileList[row-folders];
        std::string folder=DataManager::GetStrValue(mPathVar);std::string path=folder+(folder=="/"?"":"/")+entry.fileName;
        auto& paths=active->model.filePaths;auto found=std::find(paths.begin(),paths.end(),path);
        return found==paths.end()?-1:(int)(found-paths.begin());
    }
    void focusNative(int index) {
        for(size_t row=0;row<GetItemCount();row++)if(nativeIndex(row)==index){SetVisibleListLocation(row);break;}
    }
    std::vector<int> order() {Update();std::vector<int> result;for(size_t row=0;row<GetItemCount();row++){int i=nativeIndex(row);if(i>=0)result.push_back(i);}return result;}
    std::vector<std::pair<int,CGRect>> itemBounds() {
        Update();std::vector<std::pair<int,CGRect>> out;
        for(int row=firstDisplayedItem,y=mRenderY+mHeaderH+y_offset;row<(int)GetItemCount() && y<mRenderY+mRenderH;row++,y+=actualItemHeight) {
            if(row<0)continue;int index=nativeIndex(row);if(index<0)continue;
            CGRect rect=CGRectIntersection(CGRectMake(mRenderX,y,mRenderW,actualItemHeight),CGRectMake(mRenderX,mRenderY+mHeaderH,mRenderW,mRenderH-mHeaderH));
            if(!CGRectIsEmpty(rect))out.push_back({index,rect});
        }return out;
    }
    void RenderItem(size_t row,int y,bool selected) override {
        GUIFileSelector::RenderItem(row,y,selected || (active->model.navigationFocus && nativeIndex(row)==active->model.selected));
    }
    int NotifyTouch(TOUCH_STATE state,int x,int y) override {
        // The UIView uses this sentinel to cancel an interrupted touch stream.
        if((state==TOUCH_DRAG || state==TOUCH_RELEASE) && x==-10000 && y==-10000) {
            selectedItem=NO_ITEM;scrollingSpeed=0;fastScroll=0;lastY=last2Y=0;mUpdate=1;return 0;
        }
        return GUIFileSelector::NotifyTouch(state,x,y);
    }
protected:
    int GetFileList(const std::string folder) override {
        DataManager::GetValue(mSortVariable,mSortOrder);return GUIFileSelector::GetFileList(folder);
    }
};
GUIObject *nx_twrp_fileselector(xml_node<>* node) {return new NXFileSelector(node);}
static std::optional<NXTWRPEvent> ActionBinding(xml_node<>* node) {
    auto group=FindNode(node,"actions");auto action=group?group->first_node("action"):FindNode(node,"action");
    for(auto a=action;a;a=a->next_sibling("action")) {
        std::string function=LoadAttrString(a,"function"),arg=gui_parse_text(a->value());
        if(function=="key" && arg=="back")return NXTWRPEvent{NXTWRPEvent::Back};
        if((function=="key" && arg=="home") || function=="home")return NXTWRPEvent{NXTWRPEvent::Home};
        if(function=="overlay" || function=="nyxianlog")return NXTWRPEvent{NXTWRPEvent::Log};
        if(function=="nyxiancomplete")return NXTWRPEvent{NXTWRPEvent::Complete};
        if(function=="set" && arg.rfind("tw_gui_sort_order=",0)==0)return NXTWRPEvent{NXTWRPEvent::Sort,atoi(arg.c_str()+18)};
        if(function=="nyxian")return NXTWRPEvent{NXTWRPEvent::Select,atoi(arg.c_str())};
        if(IsSettings(active->model)) {
            auto tab=std::find(settingsPages.begin(),settingsPages.end(),arg);
            if(function=="page" && tab!=settingsPages.end())return NXTWRPEvent{NXTWRPEvent::Settings,(int)(tab-settingsPages.begin())};
            if(function=="nyxiansettingsapply")return NXTWRPEvent{NXTWRPEvent::Settings,10};
        }
        if(function=="page" && active->model.home) {std::vector<std::string> names={"install","wipe","backup","restore","mount","settings","advanced","reboot"};
            auto i=std::find(names.begin(),names.end(),arg);if(i!=names.end())return NXTWRPEvent{NXTWRPEvent::Select,(int)(i-names.begin())};}
    }return {};
}
class NXButton : public GUIButton {
public:
    std::optional<NXTWRPEvent> binding;
    NXButton(xml_node<>* n):GUIButton(n),binding(ActionBinding(n)){}
    int NotifyTouch(TOUCH_STATE state,int x,int y) override {
        if(binding && binding->kind==NXTWRPEvent::Select) {int i=binding->index;if(i<0 || i>=(int)active->model.enabled.size() || !active->model.enabled[i])return -1;}
        return GUIButton::NotifyTouch(state,x,y);
    }
};
class NXCheckbox : public GUICheckbox {
    bool started=false;
public:
    int index=-1;
    NXCheckbox(xml_node<>* n):GUICheckbox(n) {if(mVarName.rfind("nx_check_",0)==0)index=atoi(mVarName.c_str()+9);}
    int NotifyTouch(TOUCH_STATE state,int x,int y) override {
        if(index>=0 && (index>=(int)active->model.enabled.size() || !active->model.enabled[index]))return -1;
        if(state==TOUCH_START)started=IsInRegion(x,y);
        if(state==TOUCH_RELEASE){bool valid=started && IsInRegion(x,y);started=false;if(!valid)return 0;}
        active->checkboxInput=true;int result=GUICheckbox::NotifyTouch(state,x,y);active->checkboxInput=false;return result;
    }
};
class NXSlider : public GUISlider {
public:
    NXSlider(xml_node<>* n):GUISlider(n) {
        if(sSliderLabel) {
            // The upstream label inherits TOP_LEFT when the style has no placement.
            // Keep it centered in the usable track, to the right of the thumb.
            int thumb=sTouch && sTouch->GetResource()?sTouchW:0;
            int width=std::max(1,mRenderW-thumb-48),w=0,h=0;
            sSliderLabel->GetCurrentBounds(w,h);
            sSliderLabel->SetPlacement(CENTER_X_ONLY);
            sSliderLabel->SetRenderPos(mRenderX+thumb+24+width/2,mRenderY+(mRenderH-h)/2);
            sSliderLabel->SetMaxWidth(width);
        }
    }
    int NotifyTouch(TOUCH_STATE state,int x,int y) override {
        if(active->model.certificate && (active->model.enabled.size()<3 || !active->model.enabled[2]))return -1;
        active->sliderInput=true;int result=GUISlider::NotifyTouch(state,x,y);active->sliderInput=false;return result;
    }
};
class NXInput : public GUIInput {
public:
    NXInput(xml_node<>* n):GUIInput(n){}
    int NotifyTouch(TOUCH_STATE state,int x,int y) override {
        if(!HasTextInput(active->model) || active->model.enabled.size()<2 || !active->model.enabled[1])return -1;
        // GUIInput owns cursor/focus now; no native keyboard callback or page rebuild.
        int result=GUIInput::NotifyTouch(state,x,y);
        if(state==TOUCH_RELEASE && active->model.keyboardHidden && IsInRegion(x,y)) {
            active->model.keyboardHidden=false;active->dirty=true;
        }
        return result;
    }
};
class NXKeyboard : public GUIKeyboard {
public:
    NXKeyboard(xml_node<>* n):GUIKeyboard(n){}
    int NotifyTouch(TOUCH_STATE state,int x,int y) override {
        if(x==-10000 && y==-10000){currentKey=nullptr;highlightRenderCount=0;mRendered=false;return 0;}
        if(!active->model.terminal && (!HasTextInput(active->model) || active->model.enabled.size()<2 || !active->model.enabled[1]))return -1;
        return GUIKeyboard::NotifyTouch(state,x,y);
    }
    std::vector<NXTWRPKeyboardKey> keys() {
        std::vector<NXTWRPKeyboardKey> result;if(!isConditionTrue())return result;
        auto& layout=layouts[currentLayout-1];int y=0;
        for(int row=0;row<MAX_KEYBOARD_ROWS;row++) {
            int bottom=layout.row_end_y[row];if(bottom<=y)break;int x=0;
            for(int col=0;col<MAX_KEYBOARD_KEYS;col++) {
                const auto& key=layout.keys[row][col];if(key.end_x<=x)break;
                std::string label;
                if(key.key>32 && key.key<127)label=std::string(1,(char)key.key);
                else if(key.key==KEYBOARD_BACKSPACE)label="Backspace";
                else if(key.key==KEYBOARD_ACTION)label="Enter";
                else if(key.key==' ')label="Space";
                else for(auto& value:mKeyLabels)if((!value.layout_from || value.layout_from==currentLayout) && value.key==key.key && value.layout_to==key.layout){label=value.text;break;}
                if(!label.empty())result.push_back({label,CGRectMake(mRenderX+x,mRenderY+y,key.end_x-x,bottom-y)});
                x=key.end_x;
            }y=bottom;
        }return result;
    }
};
GUIObject *nx_twrp_keyboard(xml_node<>* n) {return new NXKeyboard(n);}
int PageManager::NotifyKey(int key,bool down) {return active && active->page?active->page->NotifyKey(key,down):1;}
GUIObject *nx_twrp_input(xml_node<>* n) {return new NXInput(n);}
int PageManager::SetKeyBoardFocus(int focus) {return active && active->page?active->page->SetKeyBoardFocus(focus):1;}
int PageManager::NotifyCharInput(int ch) {return active && active->page?active->page->NotifyCharInput(ch):1;}
GUIObject *nx_twrp_slider(xml_node<>* n) {return new NXSlider(n);}
GUIObject *nx_twrp_button(xml_node<>* n) {return new NXButton(n);}
GUIObject *nx_twrp_checkbox(xml_node<>* n) {return new NXCheckbox(n);}
void nx_twrp_action(const std::string& function,const std::string& arg) {
    if(!active)return;auto& m=active->model;
    if(IsSettings(m)) {
        auto tab=std::find(settingsPages.begin(),settingsPages.end(),arg);
        if(function=="page" && tab!=settingsPages.end()){active->settingsTab=(int)(tab-settingsPages.begin());active->dirty=true;return;}
        if(function=="nyxiansettingsapply") {
            if(active->settingsTab==1)[NSUserDefaults.standardUserDefaults setObject:@(active->pendingTimeZone.c_str()) forKey:@"nyxian.recovery.timezone"];
            if(active->settingsTab==4)[NSUserDefaults.standardUserDefaults setObject:@"en" forKey:@"nyxian.recovery.language"];
            active->lastStatus=0;return;
        }
    }
    if(function=="set") {if(arg.rfind("nx_",0)==0)return;auto p=arg.find('=');if(p!=std::string::npos){DataManager::SetValue(arg.substr(0,p),arg.substr(p+1));if(m.terminal && active->page)active->page->NotifyVarChange(arg.substr(0,p),arg.substr(p+1));if(arg.substr(0,p)=="tw_gui_sort_order")active->events.push_back({NXTWRPEvent::Sort,atoi(arg.c_str()+p+1)});}return;}
    if(HasTextInput(m) && !m.keyboardHidden && ((function=="key" && arg=="back") || function=="nyxiankeyboardhide")) {active->events.push_back({NXTWRPEvent::Back});return;}
    if(function=="key" && arg=="back") {if(!m.console && (m.back || m.showLog))active->events.push_back({NXTWRPEvent::Back});return;}
    if((function=="key" && arg=="home") || function=="home") {if(!m.console && m.back)active->events.push_back({NXTWRPEvent::Home});return;}
    if(function=="overlay" || function=="nyxianlog") {if(!m.console)active->events.push_back({NXTWRPEvent::Log});return;}
    if(function=="nyxiancomplete") {if(m.console && m.complete)active->events.push_back({NXTWRPEvent::Complete});return;}
    int index=-1;
    if(function=="nyxian") {try {size_t used;index=std::stoi(arg,&used);if(used!=arg.size())return;} catch(...) {return;}}
    if(function=="page" && m.home) {std::vector<std::string> names={"install","wipe","backup","restore","mount","settings","advanced","reboot"};auto i=std::find(names.begin(),names.end(),arg);if(i!=names.end())index=(int)(i-names.begin());}
    if(function=="nyxianinput") {if(!NXTWRPIsFileManagerInput(m) && !NXTWRPIsBootArgumentsInput(m))return;index=1;}
    if(function=="nyxianformat") {if(!IsFormatData(m) || DataManager::GetStrValue("nx_certificate_password")!="yes")return;index=1;}
    if(IsFormatData(m) && index==1 && DataManager::GetStrValue("nx_certificate_password")!="yes")return;
    if(index>=0 && index==WipeSliderIndex(m) && !active->sliderInput)return;
    if(((m.confirmation && index==1) || (m.certificate && index==2)) && !active->sliderInput)return;
    if(!m.console && index>=0 && index<(int)m.titles.size() && index<(int)m.enabled.size() && m.enabled[index]) active->events.push_back({NXTWRPEvent::Select,index});
}
static void CheckXMLNodes(xml_node<>* n,size_t& count,int depth=0) {
    if(depth>64 || ++count>80000)throw std::runtime_error("Theme XML is too complex");
    for(auto child=n->first_node();child;child=child->next_sibling())CheckXMLNodes(child,count,depth+1);
    std::string type=n->name();
    if((type=="template" || type=="variable" || type=="style") && !n->first_attribute("name"))throw std::runtime_error("Theme has a missing name attribute");
}
void NXTWRPEngine::loadThemeFile(const std::string& name,std::set<std::string>& loaded) {
    NSString *relative=@(name.c_str());
    if(relative.isAbsolutePath || [relative.pathComponents containsObject:@".."] || [relative containsString:@"\\"])throw std::runtime_error("Unsafe XML include path");
    if(!loaded.insert(name).second)return;if(loaded.size()>64)throw std::runtime_error("Too many XML includes");
    NSData *data=[NSData dataWithContentsOfFile:[themePath stringByAppendingPathComponent:relative]];
    if(!data || data.length>4*1024*1024)throw std::runtime_error("Missing or oversized theme XML include");
    NSString *text=[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if(!text || [text rangeOfString:@"<!DOCTYPE" options:NSCaseInsensitiveSearch].location!=NSNotFound)throw std::runtime_error("Unsupported theme XML declaration");
    NSXMLParser *parser=[[NSXMLParser alloc] initWithData:data];parser.shouldResolveExternalEntities=NO;
    if(![parser parse])throw std::runtime_error("Malformed theme XML");
    auto document=std::make_unique<NXThemeXML>();document->buffer.assign((const char*)data.bytes,(const char*)data.bytes+data.length);document->buffer.push_back(0);
    document->doc.parse<parse_validate_closing_tags>(document->buffer.data());auto root=document->doc.first_node("recovery");
    if(!root)throw std::runtime_error("Theme XML requires a recovery root");size_t count=0;CheckXMLNodes(root,count);
    if(loaded.size()==1)if(auto details=root->first_node("details")) {
        if(auto version=details->first_node("themeversion")){std::string v=version->value();if(v!="6" && v!="{themeversion}")throw std::runtime_error("Theme must target TWRP theme version 6");}
        if(auto resolution=details->first_node("resolution")){themeWidth=LoadAttrInt(resolution,"width",1080);themeHeight=LoadAttrInt(resolution,"height",1920);
            if(themeWidth<240 || themeWidth>4096 || themeHeight<320 || themeHeight>8192)throw std::runtime_error("Unsupported theme resolution");}
    }
    themeDocs.push_back(std::move(document));
    if(auto include=root->first_node("include"))for(auto f=include->first_node("xmlfile");f;f=f->next_sibling("xmlfile")) {
        auto attr=f->first_attribute("name");if(!attr)throw std::runtime_error("Theme include has no filename");loadThemeFile(attr->value(),loaded);
    }
}
xml_node<>* NXTWRPEngine::homeNode() {
    for(auto& d:themeDocs)if(auto pages=d->doc.first_node("recovery")->first_node("pages"))for(auto n=pages->first_node("page");n;n=n->next_sibling("page"))if(LoadAttrString(n,"name")=="main2")return n;
    auto pages=portrait.first_node("recovery")->first_node("pages");for(auto n=pages->first_node("page");n;n=n->next_sibling("page"))if(LoadAttrString(n,"name")=="main2")return n;
    throw std::runtime_error("TWRP home page missing");
}
void NXTWRPEngine::validatePage(xml_node<>* page,int depth) {
    if(depth>=10)throw std::runtime_error("Recursive theme template");
    static const std::set<std::string> supported={"background","text","image","fill","action","button","checkbox","slider","console","textbox","nyxianmenu","fileselector","input","keyboard","progressbar","slidervalue","nyxiansettingslist","template","terminal"};
    for(auto child=page->first_node();child;child=child->next_sibling()) {
        std::string type=child->name();if(type=="object")type=LoadAttrString(child,"type");
        if(!supported.count(type))throw std::runtime_error("Theme home/header uses a widget unavailable in Nyxian: "+type);
        if(type=="template") {bool found=false;std::string name=LoadAttrString(child,"name");
            for(auto group:templates){for(auto t=group->first_node("template");t;t=t->next_sibling("template"))if(name==LoadAttrString(t,"name")){validatePage(t,depth+1);found=true;break;}if(found)break;}
            if(!found)throw std::runtime_error("Theme references a missing template");}
    }
}
void NXTWRPEngine::parseDesignXML(const std::string& xml) {
    dynamicBuffer.assign(xml.begin(),xml.end());dynamicBuffer.push_back(0);dynamic.parse<0>(dynamicBuffer.data());
    // Nyxian-generated content uses the stock 1080x1920 design coordinate system.
    auto adjust=[&](auto&& self,xml_node<>* node)->void {
        if(std::string(node->name())=="placement")for(auto name:{"x","y","w","h"})if(auto a=node->first_attribute(name)) {
            char *end=nullptr;long value=strtol(a->value(),&end,10);if(end && !*end){float factor=(name[0]=='x' || name[0]=='w')?(float)themeWidth/1080:(float)themeHeight/1920;
                a->value(dynamic.allocate_string(std::to_string(lround(value*factor)).c_str()));}}
        for(auto c=node->first_node();c;c=c->next_sibling())self(self,c);
    };if(auto root=dynamic.first_node())adjust(adjust,root);
}
void NXTWRPEngine::load() {
    NSString *savedZone=[NSUserDefaults.standardUserDefaults stringForKey:@"nyxian.recovery.timezone"];pendingTimeZone=savedZone.UTF8String?:"";
    activate();int previousSort=DataManager::GetIntValue("tw_gui_sort_order");page.reset();loadedImagePixels=0;resources=std::make_unique<ResourceManager>();layout.clear();portrait.clear();templates.clear();styles.clear();themeDocs.clear();values.clear();themeWidth=1080;themeHeight=1920;
    if(!ReadXML("layout.xml",layout,layoutBuffer) || !ReadXML("portrait.xml",portrait,portraitBuffer))throw std::runtime_error("Missing bundled TWRP XML");
    if(themePath){std::set<std::string> loaded;loadThemeFile("ui.xml",loaded);}
    auto root=layout.first_node("recovery");
    auto loadVariables=[&](xml_node<>* r){if(auto vars=r->first_node("variables"))for(auto n=vars->first_node("variable");n;n=n->next_sibling("variable")) {
        std::string name=LoadAttrString(n,"name"),value=gui_parse_text(LoadAttrString(n,"value"));if(name.rfind("nx_",0)==0)continue;
        auto p=value.find('+');if(p!=std::string::npos)value=std::to_string(atoi(value.substr(0,p).c_str())+atoi(value.substr(p+1).c_str()));
        else {p=value.find('-',1);if(p!=std::string::npos && isdigit(value[0]))value=std::to_string(atoi(value.substr(0,p).c_str())-atoi(value.substr(p+1).c_str()));}values[name]=value;
    }};
    loadVariables(root);values["tw_gui_sort_order"]=std::to_string(previousSort && abs(previousSort)<=3?previousSort:1);for(auto& doc:themeDocs)loadVariables(doc->doc.first_node("recovery"));
    values["tw_brightness_pct"]=std::to_string(ConfiguredBrightness());
    for(auto name:{"tw_button_vibrate","tw_keyboard_vibrate"})values[name]=std::to_string([NSUserDefaults.standardUserDefaults integerForKey:PreferenceKey(name)]);
    values["tw_simulate_actions"]="0";values["row1_header_y"]="15";values["tw_no_cpu_temp"]="1";values["tw_cpu_pos_x"]="0";values["tw_clock_12_pos_x"]="0";values["tw_clock_24_pos_x"]="0";values["tw_battery_pos_x"]="0";values["tw_no_battery_percent"]="0";
    activate();for(auto& doc:themeDocs) {auto r=doc->doc.first_node("recovery");resources->LoadResources(r->first_node("resources"),nullptr,"Imported theme");
        if(auto t=r->first_node("templates"))templates.push_back(t);if(auto st=r->first_node("styles"))styles.push_back(st);}
    set_scale_values(1,(float)height/1920);resources->LoadResources(root->first_node("resources"),nullptr,"TWRP");activate();
    if(!resources->FindFont("font_l") || !resources->FindFont("font_m") || !resources->FindFont("fixed") || !resources->FindImage("main_button") || !resources->FindImage("slider_touch"))throw std::runtime_error("Incomplete TWRP theme resources");
    resources->AddStringResource("Nyxian","twrp_header","Nyxian Recovery Project");
    templates.push_back(root->first_node("templates"));styles.push_back(portrait.first_node("recovery")->first_node("styles"));validatePage(homeNode());dirty=true;
}
static std::string HeaderXML() {return "<template name=\"page\"/><text style=\"text_l\"><placement x=\"184\" y=\"90\"/><text>%nx_title%</text></text><text style=\"text_m\"><placement x=\"184\" y=\"168\"/><text>%nx_subtitle%</text></text>";}
void NXTWRPEngine::build() {
    activate();page.reset();dynamic.clear();events.clear();
    bool logs=model.console || model.showLog;
    values["tw_busy"]=model.console?"1":"0";values["nx_title"]=logs?(model.progress>=0?"Download ROM":"Recovery operation"):model.header.substr(0,model.header.find('\n'));
    values["nx_subtitle"]=logs?(model.progress>=0?model.progressStatus:(model.complete?model.completeStatus:"Operation in progress...")):"Nyxian Recovery";
    values["nx_download_progress"]=std::to_string(std::max(0,model.progress));values["nx_download_percent"]=std::to_string(std::max(0,model.progress))+"%";
    values["tw_version"]="Nyxian "+std::string([(NSBundle.mainBundle.infoDictionary[@"CFBundleShortVersionString"]?:@"") UTF8String]);
    values["tw_time"]=RecoveryTime();
    UIDevice.currentDevice.batteryMonitoringEnabled=YES;values["tw_battery"]=std::to_string((int)(UIDevice.currentDevice.batteryLevel*100));
    std::string xml;
    if(!logs && model.terminal) {
        // Upstream terminalcommand page: <terminal>, the terminal key row and the keyboard, kb show/hide in the navbar.
        if(!terminalPage)values["tw_hide_kb"]="0";
        xml_node<> *original=nullptr;
        for(auto& d:themeDocs)if(auto pages=d->doc.first_node("recovery")->first_node("pages"))for(auto n=pages->first_node("page");n && !original;n=n->next_sibling("page"))if(LoadAttrString(n,"name")=="terminalcommand")original=n;
        for(auto n=portrait.first_node("recovery")->first_node("pages")->first_node("page");n && !original;n=n->next_sibling("page"))if(LoadAttrString(n,"name")=="terminalcommand")original=n;
        if(!original)throw std::runtime_error("Bundled TWRP terminal page missing");
        auto cloned=dynamic.clone_node(original);
        // Android hardware-key and screenshot bindings never cross the native boundary.
        for(auto node=cloned->first_node();node;){auto next=node->next_sibling();if(std::string(node->name())=="action")cloned->remove_node(node);node=next;}
        validatePage(cloned);page=std::make_unique<NXPage>(cloned,&templates);
        terminalPage=true;
        page->NotifyVarChange("","");page->SetPageFocus(1);dirty=false;
        return;
    }
    terminalPage=false;
    if(!logs && (IsWipeHome(model) || IsAdvancedWipe(model) || IsFormatData(model))) {
        values["tw_has_data_media"]="1";values["tw_has_android_secure"]="0";values["tw_has_sdext_partition"]="0";
        values["tw_is_encrypted"]="0";values["tw_has_adopted_storage"]="0";
        values["tw_hide_kb"]=model.keyboardHidden?"1":"0";
        values["nx_certificate_password"]=model.password;
        xml_node<> *original=nullptr;
        std::string name=IsWipeHome(model)?"wipe":IsAdvancedWipe(model)?"advancedwipe":"formatdata";
        for(auto node=portrait.first_node("recovery")->first_node("pages")->first_node("page");node;node=node->next_sibling("page"))
            if(LoadAttrString(node,"name")==name){original=node;break;}
        if(!original)throw std::runtime_error("Bundled TWRP wipe page missing");
        auto cloned=dynamic.clone_node(original);
        auto setAction=[&](xml_node<> *node,const std::string& function,const std::string& argument) {
            for(auto action=node->first_node();action;){auto next=action->next_sibling();if(std::string(action->name())=="actions" || std::string(action->name())=="action")node->remove_node(action);action=next;}
            auto action=dynamic.allocate_node(node_element,"action",dynamic.allocate_string(argument.c_str()));
            action->append_attribute(dynamic.allocate_attribute("function",dynamic.allocate_string(function.c_str())));node->append_node(action);
        };
        for(auto node=cloned->first_node();node;){auto next=node->next_sibling();std::string type=node->name();
            if(type=="action")cloned->remove_node(node); // Android page lifecycle/action commands never cross the native boundary.
            if(type=="button") {
                auto label=node->first_node("text");std::string text=label?label->value():"";
                if(text.find("advanced_wipe_btn")!=std::string::npos)setAction(node,"nyxian","0");
                else if(text.find("format_data_btn")!=std::string::npos)setAction(node,"nyxian","1");
                else if(text.find("repair_change_btn")!=std::string::npos) {
                    setAction(node,"nyxian","4");
                    auto font=dynamic.allocate_node(node_element,"font");font->append_attribute(dynamic.allocate_attribute("resource","font_m"));font->append_attribute(dynamic.allocate_attribute("color","#999999"));node->append_node(font);
                } else cloned->remove_node(node);
            }
            if(type=="partitionlist") {
                node->name("nyxiansettingslist");
                node->append_attribute(dynamic.allocate_attribute("kind","3"));node->append_attribute(dynamic.allocate_attribute("style","partitionlist"));
            }
            if(type=="slider") {
                int index=WipeSliderIndex(model);setAction(node,"nyxian",std::to_string(index));
                if(index>=0 && index<(int)model.enabled.size() && !model.enabled[index]) {
                    auto font=dynamic.allocate_node(node_element,"font");font->append_attribute(dynamic.allocate_attribute("resource","font_m"));font->append_attribute(dynamic.allocate_attribute("color","#999999"));node->append_node(font);
                }
            }
            if(type=="input") {
                if(auto data=node->first_node("data"))data->first_attribute("name")->value("nx_certificate_password");
                if(auto text=node->first_node("text"))text->value("%nx_certificate_password%");
                setAction(node,"nyxianformat","");
            }
            if(type=="text")if(auto label=node->first_node("text")) {
                std::string text=label->value(),replacement;
                if(text.find("factory_reset1=")!=std::string::npos)replacement="Wipes ROM Data";
                if(text.find("factory_reset5=")!=std::string::npos)replacement="(preserves certificate and Inbox)";
                if(text.find("factory_reset2=")!=std::string::npos)replacement=model.instructions;
                if(text.find("format_data_ptr1=")!=std::string::npos)replacement="Clears ROM data, cache and internal storage.";
                if(text.find("format_data_ptr2=")!=std::string::npos)replacement="Certificate, Inbox and system slots are kept.";
                if(text.find("format_data_ptr3=")!=std::string::npos)replacement="Does not format iOS or remove encryption.";
                if(!replacement.empty())label->value(dynamic.allocate_string(replacement.c_str()));
            }
            node=next;
        }
        validatePage(cloned);page=std::make_unique<NXPage>(cloned,&templates);
    } else if(!logs && IsFileManagerPage(model)) {
        // TWRP's own file manager pages, their buttons bound to the page's items by label (the conditions decided which exist)
        std::string name=NXTWRPIsFileManagerOptions(model)?"filemanageroptions":NXTWRPIsFileManagerConfirm(model)?"filemanagerconfirm":
            model.header=="File Manager\nRename File"?"filemanagerrenamefile":model.header=="File Manager\nRename Folder"?"filemanagerrenamefolder":"filemanagerchmod";
        xml_node<> *original=nullptr;
        for(auto& d:themeDocs)if(auto pages=d->doc.first_node("recovery")->first_node("pages"))for(auto n=pages->first_node("page");n && !original;n=n->next_sibling("page"))if(LoadAttrString(n,"name")==name)original=n;
        for(auto n=portrait.first_node("recovery")->first_node("pages")->first_node("page");n && !original;n=n->next_sibling("page"))if(LoadAttrString(n,"name")==name)original=n;
        if(!original)throw std::runtime_error("Bundled TWRP file manager page missing");
        std::vector<std::string> lines;{std::string text=model.instructions;size_t start=0,end;while((end=text.find('\n',start))!=std::string::npos){lines.push_back(text.substr(start,end-start));start=end+1;}lines.push_back(text.substr(start));}
        auto line=[&](size_t i){return i<lines.size()?lines[i]:std::string();};
        bool folder=std::find(model.titles.begin(),model.titles.end(),"Open Terminal Here")!=model.titles.end() || model.header=="File Manager\nRename Folder";
        values["tw_fm_type"]=NXTWRPIsFileManagerConfirm(model)?line(4):folder?"Folder":"File";
        values["tw_fm_isfolder"]=folder?"1":"0";values["tw_include_nano"]="1";
        // paths as the list header shows them: the bootloader's container is "~"
        auto display=[](const std::string& path)->std::string {
            NSString *p=@(path.c_str()),*home=NSHomeDirectory();
            if([p isEqualToString:home])return "~";
            if([p hasPrefix:[home stringByAppendingString:@"/"]])return std::string("~")+[p substringFromIndex:home.length].UTF8String;
            return path;
        };
        if(NXTWRPIsFileManagerConfirm(model)) {
            values["tw_fm_text1"]=line(0);values["tw_filename1"]=display(line(1));values["tw_fm_text2"]=line(2);values["tw_fm_text3"]=display(line(3));values["tw_include_text3"]=line(3).empty()?"0":"1";
        } else values["tw_filename1"]=display(model.instructions);
        values["tw_hide_kb"]=model.keyboardHidden?"1":"0";values["nx_certificate_password"]=model.password;
        auto cloned=dynamic.clone_node(original);
        auto setAction=[&](xml_node<> *node,const std::string& function,const std::string& argument) {
            for(auto child=node->first_node();child;){auto next=child->next_sibling();std::string type=child->name();if(type=="actions" || type=="action" || type=="condition" || type=="conditions")node->remove_node(child);child=next;}
            auto action=dynamic.allocate_node(node_element,"action",dynamic.allocate_string(argument.c_str()));
            action->append_attribute(dynamic.allocate_attribute("function",dynamic.allocate_string(function.c_str())));node->append_node(action);
        };
        for(auto node=cloned->first_node();node;){auto next=node->next_sibling();std::string type=node->name();
            if(type=="action")cloned->remove_node(node); // hardware keys and page flow stay with the bootloader
            if(type=="button") {
                auto label=node->first_node("text");std::string text=label?DefaultText(label->value()):"";
                auto found=std::find(model.titles.begin(),model.titles.end(),text);
                if(found==model.titles.end() || node->first_node("image"))cloned->remove_node(node);
                else {
                    int index=(int)(found-model.titles.begin());setAction(node,"nyxian",std::to_string(index));
                    if(index>=(int)model.enabled.size() || !model.enabled[index]) {
                        auto font=dynamic.allocate_node(node_element,"font");font->append_attribute(dynamic.allocate_attribute("resource","font_m"));font->append_attribute(dynamic.allocate_attribute("color","#999999"));node->append_node(font);
                    }
                }
            }
            if(type=="slider")setAction(node,"nyxian","1");
            if(type=="input") {
                if(auto data=node->first_node("data"))if(auto a=data->first_attribute("name"))a->value("nx_certificate_password");
                if(auto text=node->first_node("text"))text->value("%nx_certificate_password%");
                setAction(node,"nyxianinput","");
            }
            node=next;
        }
        /*
         * TWRP draws a text on one line and shrinks its font until it fits, fine for
         * /sdcard paths, unreadable for the container's. The path texts wrap at '/'
         * instead (like a textbox), one row (64) per line, and the texts below move down.
         */
        int wrapped=0;
        for(auto node=cloned->first_node("text");node;node=node->next_sibling("text")) {
            auto label=node->first_node("text");auto placement=node->first_node("placement");
            std::string source=label?label->value():"";
            if(!placement || (source!="%tw_filename1%" && source!="%tw_fm_text3%"))continue;
            std::string fontName;
            if(auto font=node->first_node("font"))fontName=LoadAttrString(font,"resource");
            if(fontName.empty())if(auto style=PageManager::FindStyle(LoadAttrString(node,"style")))if(auto font=style->first_node("font"))fontName=LoadAttrString(font,"resource");
            auto fontResource=resources->FindFont(fontName.empty()?"font_m":fontName);
            void *font=fontResource?fontResource->GetResource():nullptr;
            if(!font)continue;
            NSString *rest=@(DataManager::GetStrValue(source.substr(1,source.size()-2)).c_str());
            int maxWidth=std::max(1,1008*width/std::max(1,themeWidth));
            size_t maxLines=NXTWRPIsFileManagerOptions(model)?8:4;
            std::vector<std::string> lines;
            while(rest.length) {
                NSUInteger fit=(NSUInteger)twrpTruetype::gr_ttf_maxExW(rest.UTF8String,font,maxWidth);
                if(fit>=rest.length){lines.push_back(rest.UTF8String);break;}
                fit=MAX(fit,(NSUInteger)1);
                if(lines.size()+1==maxLines) {
                    NSRange keep=[rest rangeOfComposedCharacterSequencesForRange:NSMakeRange(0,fit>1?fit-1:fit)];
                    lines.push_back([[rest substringWithRange:keep] stringByAppendingString:@"\u2026"].UTF8String);break;
                }
                NSRange slash=[rest rangeOfString:@"/" options:NSBackwardsSearch range:NSMakeRange(0,fit)];
                NSUInteger cut=slash.location==NSNotFound || slash.location==0?fit:slash.location+1;
                lines.push_back([rest substringToIndex:cut].UTF8String);rest=[rest substringFromIndex:cut];
            }
            if(lines.size()<2)continue;
            auto yAttr=placement->first_attribute("y");if(!yAttr)continue;
            int y=atoi(gui_parse_text(yAttr->value()).c_str());
            // texts below this one make room
            for(auto below=node->next_sibling("text");below;below=below->next_sibling("text"))
                if(auto p=below->first_node("placement"))if(auto a=p->first_attribute("y")) {
                    int by=atoi(gui_parse_text(a->value()).c_str());
                    if(by>y)a->value(dynamic.allocate_string(std::to_string(by+64*((int)lines.size()-1)).c_str()));
                }
            xml_node<> *after=node;
            for(size_t i=0;i<lines.size();i++) {
                std::string name="nx_fm_wrap_"+std::to_string(wrapped)+"_"+std::to_string(i);
                values[name]=lines[i];
                xml_node<> *target=i==0?node:dynamic.clone_node(node);
                target->first_node("text")->value(dynamic.allocate_string(("%"+name+"%").c_str()));
                if(i>0) {
                    target->first_node("placement")->first_attribute("y")->value(dynamic.allocate_string(std::to_string(y+64*(int)i).c_str()));
                    cloned->insert_node(after->next_sibling(),target);after=target;
                }
            }
            node=after;wrapped++;
        }
        validatePage(cloned);page=std::make_unique<NXPage>(cloned,&templates);
    } else if(model.home && !logs) {
        auto node=homeNode();
        values["nx_twrp_version"]="TWRP "+std::string(upstreamTWRPVersion);
        auto split=model.header.find('\n');values["nx_home_details"]=split==std::string::npos?"":model.header.substr(split+1);
        xml="<text style=\"text_m\"><placement x=\"184\" y=\"168\"/><text>%nx_twrp_version%</text></text><textbox style=\"scrolllist\"><placement x=\"36\" y=\"264\" w=\"1008\" h=\"80\"/><font resource=\"font_s\" color=\"%text_color%\" spacing=\"0\"/><text>%nx_home_details%</text></textbox>";
        parseDesignXML(xml);
        auto cloned=dynamic.clone_node(node);
        cloned->append_node(dynamic.clone_node(dynamic.first_node()));
        if(node->parent()==portrait.first_node("recovery")->first_node("pages"))cloned->append_node(dynamic.clone_node(dynamic.first_node()->next_sibling()));
        int item=0;
        for(auto n=cloned->first_node("button");n;n=n->next_sibling("button"),item++) {
            auto binding=ActionBinding(n);
            if(binding && binding->kind==NXTWRPEvent::Select && binding->index>=0 && binding->index<(int)model.enabled.size() && !model.enabled[binding->index]) {
                auto f=dynamic.allocate_node(node_element,"font");
                f->append_attribute(dynamic.allocate_attribute("resource","font_l"));
                f->append_attribute(dynamic.allocate_attribute("color","#999999"));n->append_node(f);
            }
        }
        page=std::make_unique<NXPage>(cloned,&templates);
    } else {
        xml="<page name=\"nyxian\">"+HeaderXML();
        if(logs) {
            nx_twrp_console_snapshot(model.log,model.logColors);
            xml+="<console style=\"console\"><placement x=\"36\" y=\"288\" w=\"1008\" h=\""+std::string(model.progress>=0?"1160":"1360")+"\"/></console>";
            if(model.progress>=0)xml+="<progressbar><placement x=\"36\" y=\"1500\"/><resource empty=\"progress_empty\" full=\"progress_full\"/><data name=\"nx_download_progress\" max=\"100\"/></progressbar><text style=\"text_m\"><placement x=\"540\" y=\"1570\" placement=\"5\"/><text>%nx_download_percent%</text></text>";
            if(model.console && model.complete)xml+="<button style=\"main_button_half_height_full_width\"><placement x=\"36\" y=\"1664\"/><text>"+Escape(model.completeTitle)+"</text><action function=\"nyxiancomplete\"/></button>";
        } else if(IsSettings(model)) {
            values["nx_subtitle"]=settingsNames[settingsTab];
            xml+="<template name=\"tabs_settings\"/><fill color=\"%text_color%\"><placement x=\""+std::to_string(settingsTab*216)+"\" y=\"%row_tab_y%\" w=\"%tab5_width%\" h=\"%tab_indicator_height%\"/></fill>";
            if(settingsTab==0 || settingsTab==1 || settingsTab==4) {
                int kind=settingsTab==0?0:settingsTab==1?1:2;
                xml+="<nyxiansettingslist kind=\""+std::to_string(kind)+"\" style=\""+std::string(kind==0?"scrolllist":"listbox")+"\"><placement x=\"%indent%\" y=\"%row3a_y%\" w=\"%content_width%\" h=\"%listbox_settings_height%\"/>"+std::string(kind==0?"":kind==1?"<text>Select Time Zone:</text>":"<text>Select Language:</text>")+"<font resource=\"font_m\" spacing=\"%fileselector_spacing%\" color=\"%text_color%\" highlightcolor=\"%accent_color%\"/><icon selected=\""+std::string(kind==0?"checkbox_true":"radio_true")+"\" unselected=\""+std::string(kind==0?"checkbox_false":"radio_false")+"\"/></nyxiansettingslist>";
                if(settingsTab==0 && !model.titles.empty() && model.titles.back()=="Restore Defaults")xml+="<button style=\"main_button_half_height\"><placement x=\"%center_x%\" y=\"%row21a_y%\"/><text>Restore Defaults</text><action function=\"nyxian\">"+std::to_string(model.titles.size()-1)+"</action></button>";
                else if(settingsTab!=0)xml+="<button style=\"main_button_half_height\"><placement x=\"%center_x%\" y=\"%row21a_y%\"/><text>"+std::string(settingsTab==1?"Set Time Zone":"Set Language")+"</text><action function=\"nyxiansettingsapply\"/></button>";
            } else {
                for(int i=settingsTab==2?0:1;i<(settingsTab==2?1:3);i++) {
                    int y=i==2?832:480;
                    xml+="<slidervalue style=\"slidervalue\"><placement x=\"%indent%\" y=\""+std::to_string(y)+"\" w=\"%content_width%\"/><text>"+std::string(i==0?"Brightness:":i==1?"Button Vibration:":"Keyboard Vibration:")+"</text><data variable=\""+settingsVariables[i]+"\" min=\""+std::string(i==0?"10":"0")+"\" max=\""+std::string(i==0?"100":"300")+"\" changeondrag=\""+std::string(i==0?"1":"0")+"\"/></slidervalue>";
                }
            }
        } else if(model.header=="Advanced" && model.titles.size()>=4) {
            // Upstream Advanced uses a two-column main_button layout for its primary actions.
            for(int index=0;index<4;index++) {
                bool enabled=index<(int)model.enabled.size() && model.enabled[index];
                xml+="<button style=\"main_button\"><placement x=\""+std::string(index%2?"%center_x%":"%indent%")+"\" y=\""+std::string(index<2?"%row2a_y%":"%row8_y%")+"\"/><font resource=\"font_l\" color=\""+std::string(enabled?"%text_button_color%":"#999999")+"\"/><text>"+Escape(model.titles[index])+"</text><action function=\"nyxian\">"+std::to_string(index)+"</action></button>";
            }
            if(model.titles.size()>4)xml+="<nyxianmenu start=\"4\" style=\"advanced_listbox\"><placement x=\"%indent%\" y=\"%row13a_y%\" w=\"%content_width%\" h=\"%listbox_advanced_height%\"/></nyxianmenu>";
        } else if(model.header=="Reboot" && model.titles.size()==4 && model.titles[2]=="Slot A" && model.titles[3]=="Slot B") {
            values["nx_current_slot"]=model.instructions;
            for(int index=0;index<4;index++) {
                bool enabled=index<(int)model.enabled.size() && model.enabled[index];
                std::string placement=index<2?"<placement x=\"%indent%\" y=\""+std::string(index==0?"%row3a_y%":"%row7_y%")+"\"/>":"<placement x=\""+std::string(index==2?"%indent%":"%center_x%")+"\" y=\"%row19_y%\"/>";
                xml+="<button style=\""+std::string(index<2?"main_button_half_height_full_width":"main_button")+"\">"+placement+"<font resource=\"font_m\" color=\""+std::string(enabled?"%text_color%":"#999999")+"\"/><text>"+Escape(model.titles[index])+"</text><action function=\"nyxian\">"+std::to_string(index)+"</action></button>";
            }
            // Match the upstream Reboot page's slot status and two-button placement.
            xml+="<text style=\"text_m\"><placement x=\"%center_x%\" y=\"%row17_y%\" placement=\"5\"/><text>%nx_current_slot%</text></text>";
        } else if(NXTWRPIsBootArgumentsInput(model)) {
            // Settings > General > Boot Arguments: the field, Cancel / Save, what the standard arguments do, the keyboard
            values["tw_hide_kb"]=model.keyboardHidden?"1":"0";
            values["nx_certificate_password"]=model.password;
            values["nx_bootargs_help"]=model.instructions;
            xml+="<text style=\"text_m\"><placement x=\"72\" y=\"300\"/><text>Boot Arguments</text></text><input><placement x=\"72\" y=\"364\" w=\"936\" h=\"112\"/><font resource=\"font_m\" color=\"%text_color%\"/><background color=\"#333333\"/><cursor color=\"%accent_color%\" width=\"3\" hasfocus=\"1\"/><data name=\"nx_certificate_password\"/><action function=\"nyxianinput\"/></input>";
            for(int index=0;index<2;index++)xml+="<button style=\"main_button_half_height\"><placement x=\""+std::string(index==0?"%indent%":"%center_x%")+"\" y=\"520\"/><font resource=\"font_m\" color=\"%text_color%\"/><text>"+Escape(model.titles[index])+"</text><action function=\"nyxian\">"+std::to_string(index)+"</action></button>";
            xml+="<textbox style=\"scrolllist\"><placement x=\"36\" y=\"720\" w=\"1008\" h=\""+std::string(model.keyboardHidden?"1000":"400")+"\"/><font resource=\"font_m\" spacing=\"8\" color=\"%text_color%\"/><text>%nx_bootargs_help%</text></textbox>";
            xml+="<template name=\"keyboardtemplate\"/>";
        } else if(model.certificate) {
            values["tw_hide_kb"]=model.keyboardHidden?"1":"0";
            values["nx_certificate_password"]=model.password;
            values["nx_certificate_message"]=model.instructions;
            auto button=[&](int index,int y) {
                bool enabled=index<(int)model.enabled.size() && model.enabled[index];
                return "<button style=\"main_button_half_height_full_width\"><placement x=\"36\" y=\""+std::to_string(y)+"\"/><font resource=\"font_m\" color=\""+std::string(enabled?"%text_color%":"#999999")+"\"/><text>"+Escape(model.titles[index])+"</text><action function=\"nyxian\">"+std::to_string(index)+"</action></button>";
            };
            xml+="<textbox style=\"scrolllist\"><placement x=\"36\" y=\"280\" w=\"1008\" h=\"112\"/><font resource=\"font_m\" spacing=\"8\" color=\"%text_color%\"/><text>Choose your PKCS#12 certificate to continue.</text></textbox>";
            xml+=button(0,416);
            xml+="<text style=\"text_m\"><placement x=\"72\" y=\"600\"/><text>Password</text></text><input><placement x=\"72\" y=\"664\" w=\"936\" h=\"112\"/><font resource=\"font_m\" color=\"%text_color%\"/><background color=\"#333333\"/><cursor color=\"%accent_color%\" width=\"3\" hasfocus=\"1\"/><data name=\"nx_certificate_password\" mask=\"*\"/><action function=\"nyxiankeyboardhide\"/></input>";
            bool canValidate=model.enabled.size()>2 && model.enabled[2];
            xml+="<slider style=\"slider\">"+std::string(model.keyboardHidden?"":"<placement x=\"540\" y=\"920\"/>")+"<font resource=\"font_s\" color=\""+std::string(canValidate?"%text_color%":"#999999")+"\"/><text>Swipe to validate and continue</text><action function=\"nyxian\">2</action></slider>";
            xml+="<textbox style=\"scrolllist\"><placement x=\"36\" y=\""+std::string(model.keyboardHidden?"848":"1024")+"\" w=\"1008\" h=\""+std::string(model.keyboardHidden?"600":"112")+"\"/><font resource=\"font_m\" spacing=\"8\" color=\"#FF8080\"/><text>%nx_certificate_message%</text></textbox>";
            xml+="<template name=\"keyboardtemplate\"/>";
        } else if(!model.browserPath.empty()) {
            values["nx_browser_path"]=model.browserPath;values["nx_browser_result"]="";
            NSString *path=@(model.browserPath.c_str()),*home=NSHomeDirectory();
            NSString *display=[path isEqual:home]?@"~":([path hasPrefix:[home stringByAppendingString:@"/"]]?[@"~" stringByAppendingString:[path substringFromIndex:home.length]]:path);
            values["nx_browser_label"]=display.UTF8String;
            // TWRP's file manager: filemanagerlist, or choosedestinationfolder (folders only)
            bool destination=model.header.rfind("Select Destination Folder\n",0)==0;
            if(destination || model.header.rfind("File Manager\n",0)==0) {
                values["nx_title"]="File Manager";values["nx_subtitle"]=destination?"Select Destination Folder":"Select a File or Folder";
            }
            xml+="<template name=\"sort_options\"/><fileselector><placement x=\"%indent%\" y=\"%row3_y%\" w=\"%content_width%\" h=\"%fileselector_filemanager_height%\"/><text>%nx_browser_label%</text><filter folders=\"1\" files=\""+std::string(destination?"0":"1")+"\" nav=\"0\"/><path name=\"nx_browser_path\"/><data name=\"nx_browser_result\"/></fileselector>";
            // the select-folder action button, the last item (it has no file)
            if(!model.titles.empty() && model.titles.back()=="Select Folder" && model.filePaths.size()==model.titles.size() && model.filePaths.back().empty())
                xml+="<button style=\"fab\"><image resource=\"fab_selectfolder\"/><action function=\"nyxian\">"+std::to_string(model.titles.size()-1)+"</action></button>";
        } else {
            std::string details;auto split=model.header.find('\n');if(split!=std::string::npos)details=model.header.substr(split+1);if(!model.instructions.empty())details+="\n"+model.instructions;
            values["nx_details"]=details;
            int top=288;
            if(!details.empty()) {
                UIFont *font=(__bridge UIFont*)resources->FindFont("font_m")->GetResource();
                CGRect measured=[@(details.c_str()) boundingRectWithSize:CGSizeMake(1008,CGFLOAT_MAX)
                    options:NSStringDrawingUsesLineFragmentOrigin|NSStringDrawingUsesFontLeading
                    attributes:@{NSFontAttributeName:font} context:nil];
                // Leave a spare row for differences between UIKit and TWRP word wrapping.
                int rows=std::max(1,(int)ceil(measured.size.height/font.lineHeight)+1);
                int height=std::clamp(rows*((int)ceil(font.lineHeight)+8),180,600);
                xml+="<textbox style=\"scrolllist\"><placement x=\"36\" y=\"280\" w=\"1008\" h=\""+std::to_string(height)+"\"/><font resource=\"font_m\" spacing=\"8\" color=\"%text_color%\"/><text>%nx_details%</text></textbox>";
                top=280+height+24;
            }
            if(model.confirmation && model.titles.size()==2) {
                xml+="<button style=\"main_button_half_height_full_width\"><placement x=\"36\" y=\""+std::to_string(top)+"\"/><text>Cancel</text><action function=\"nyxian\">0</action></button>";
                xml+="<slider style=\"slider\"><text>Swipe to "+Escape(model.titles[1])+"</text><action function=\"nyxian\">1</action></slider>";
            } else if(std::any_of(model.checks.begin(),model.checks.end(),[](int c){return c>=0;})) {
                for(size_t i=0;i<model.titles.size();i++) {
                    // checks 2/3: one choice of a radio group (TWRP's radio_false/radio_true), packed closer like TWRP's lists
                    bool radio=std::all_of(model.checks.begin(),model.checks.end(),[](int c){return c>=2;});
                    int y=top+(int)i*(radio?120:160);std::string index=std::to_string(i);
                    bool disabled=i>=model.enabled.size() || !model.enabled[i];
                    std::string focus=(disabled)?("<font resource=\"font_m\" color=\""+std::string(disabled?"#999999":"%accent_color%")+"\"/>"):"";
                    if(i<model.checks.size() && model.checks[i]>=0) {
                        values["nx_check_"+index]=std::to_string(model.checks[i]&1);
                        std::string image=model.checks[i]>=2?"<image checked=\"radio_true\" unchecked=\"radio_false\"/>":"";
                        xml+="<checkbox style=\"checkbox\"><placement x=\"72\" y=\""+std::to_string(y)+"\"/>"+focus+image+"<text>"+Escape(model.titles[i])+"</text><data variable=\"nx_check_"+index+"\"/></checkbox>";
                    } else xml+="<button style=\"main_button_half_height_full_width\"><placement x=\"36\" y=\""+std::to_string(y)+"\"/>"+focus+"<text>"+Escape(model.titles[i])+"</text><action function=\"nyxian\">"+index+"</action></button>";
                }
            } else xml+="<nyxianmenu style=\"scrolllist\"><placement x=\"36\" y=\""+std::to_string(top)+"\" w=\"1008\" h=\""+std::to_string(1760-top)+"\"/><font resource=\"font_m\" spacing=\"40\" color=\"#EEEEEE\" highlightcolor=\"%accent_color%\"/><separator color=\"#555555\" height=\"2\"/></nyxianmenu>";
        }
        xml+="</page>";parseDesignXML(xml);validatePage(dynamic.first_node());page=std::make_unique<NXPage>(dynamic.first_node(),&templates);
    }
    page->NotifyVarChange("","");page->SetPageFocus(1);dirty=false;
}
NXTWRPEngine *NXTWRPCreate() {RegisterSettings();auto e=new NXTWRPEngine;try{e->themePath=[NXTWRPThemeStore activeDirectory];try{e->load();}catch(...){if(!e->themePath)throw;[NXTWRPThemeStore useStockTheme];e->themePath=nil;e->load();}}catch(...){delete e;throw;}return e;}
void NXTWRPDestroy(NXTWRPEngine *e) {e->activate();if(e->page){e->page->NotifyTouch(TOUCH_DRAG,-10000,-10000);e->page->NotifyTouch(TOUCH_RELEASE,-10000,-10000);}if(active==e){active=nullptr;themeAssets=nil;}delete e;}
void NXTWRPSetModel(NXTWRPEngine *e,const NXTWRPModel& m) {
    const auto& old=e->model;
    bool same=(old.progress>=0)==(m.progress>=0) && old.certificate==m.certificate && old.keyboardHidden==m.keyboardHidden && old.navigationFocus==m.navigationFocus && old.password==m.password && old.header==m.header && old.instructions==m.instructions && old.titles==m.titles && old.enabled==m.enabled && old.checks==m.checks && old.browserPath==m.browserPath && old.filePaths==m.filePaths && old.selected==m.selected && old.home==m.home && old.confirmation==m.confirmation && old.back==m.back && old.console==m.console && old.complete==m.complete && old.completeTitle==m.completeTitle && old.completeStatus==m.completeStatus && old.showLog==m.showLog && old.terminal==m.terminal;
    bool append=old.log.size()<=m.log.size() && std::equal(old.log.begin(),old.log.end(),m.log.begin()) && old.logColors.size()<=m.logColors.size() && std::equal(old.logColors.begin(),old.logColors.end(),m.logColors.begin());
    bool browserFocusOnly=!m.certificate && !m.browserPath.empty() && !e->dirty && old.header==m.header && old.instructions==m.instructions && old.browserPath==m.browserPath && old.filePaths==m.filePaths && old.titles==m.titles && old.enabled==m.enabled && old.checks==m.checks && old.home==m.home && old.confirmation==m.confirmation && old.back==m.back && old.console==m.console && old.complete==m.complete && old.showLog==m.showLog && old.log==m.log && old.logColors==m.logColors;
    if(!IsSettings(m)){e->settingsTab=0;e->settingsScroll=0;}
    if(IsSettings(m) && !IsSettings(old)) {NSString *zone=[NSUserDefaults.standardUserDefaults stringForKey:@"nyxian.recovery.timezone"];e->pendingTimeZone=zone.UTF8String?:"";}
    e->model=m;
    if(browserFocusOnly){e->activate();for(auto o:e->page->objects())if(auto files=dynamic_cast<NXFileSelector*>(o))files->focusNative(m.selected);return;}
    if(same && append && !e->dirty && (m.console || m.showLog)) {
        e->activate();
        if(m.progress>=0) {
            e->values["nx_subtitle"]=m.progressStatus;e->values["nx_download_progress"]=std::to_string(m.progress);e->values["nx_download_percent"]=std::to_string(m.progress)+"%";
            e->page->NotifyVarChange("nx_subtitle",m.progressStatus);e->page->NotifyVarChange("nx_download_progress",std::to_string(m.progress));e->page->NotifyVarChange("nx_download_percent",e->values["nx_download_percent"]);
        }
        nx_twrp_console_snapshot(m.log,m.logColors);return;
    }
    e->dirty=true;
}
// Invalidate the resource cache even when the selected theme path is unchanged.
void NXTWRPReloadTheme(NXTWRPEngine *e) {if(e){e->reloadTheme=true;e->dirty=true;}}
// Touch switches off key focus without rebuilding or resetting a scrolled list.
void NXTWRPResumePresentation(NXTWRPEngine *e,UIView *view) {
    if(!e || e->validating || !view.window || UIApplication.sharedApplication.applicationState!=UIApplicationStateActive)return;
    if(e->presentationView!=view || !e->feedback) {
        e->presentationView=view;
        if(@available(iOS 17.5,*))e->feedback=[UIImpactFeedbackGenerator feedbackGeneratorWithStyle:UIImpactFeedbackStyleMedium forView:view];
        else e->feedback=[[UIImpactFeedbackGenerator alloc] initWithStyle:UIImpactFeedbackStyleMedium];
    }
    [e->feedback prepare];
    if([NSUserDefaults.standardUserDefaults objectForKey:@"nyxian.recovery.tw_brightness_pct"])
        view.window.screen.brightness=ConfiguredBrightness()/100.0;
}
void NXTWRPPrepareFeedback(NXTWRPEngine *e){if(e)[e->feedback prepare];}
void NXTWRPSetNavigationFocus(NXTWRPEngine *e,bool focused) {if(e)e->model.navigationFocus=focused;}
bool NXTWRPKeyboardHidden(NXTWRPEngine *e) {return !e || e->model.keyboardHidden;}
void NXTWRPRender(NXTWRPEngine *e,CGContextRef c,int width,int height) {
    NSString *requested=e->validating?e->themePath:[NXTWRPThemeStore activeDirectory];
    bool changed=![requested?:@"" isEqual:e->themePath?:@""];
    if(e->width!=width || e->height!=height || changed || e->reloadTheme){e->reloadTheme=false;e->width=width;e->height=height;e->themePath=requested;
        try{e->load();}catch(...){if(e->validating || !e->themePath)throw;[NXTWRPThemeStore useStockTheme];e->themePath=nil;e->load();}}
    e->activate();context=c;ink=UIColor.whiteColor;clipped=false;
    try {if(e->dirty)e->build();
        NSTimeInterval now=NSDate.timeIntervalSinceReferenceDate;
        if(now-e->lastStatus>=1) {
            e->lastStatus=now;e->values["tw_time"]=RecoveryTime();
            e->values["tw_battery"]=std::to_string((int)(UIDevice.currentDevice.batteryLevel*100));
            e->page->NotifyVarChange("tw_time",e->values["tw_time"]);e->page->NotifyVarChange("tw_battery",e->values["tw_battery"]);
        }
        if(e->model.console || e->model.showLog)nx_twrp_console_snapshot(e->model.log,e->model.logColors);e->page->Update();e->page->Render();}
    catch(...) {gr_noclip();context=nullptr;throw;}gr_noclip();context=nullptr;
}
std::vector<NXTWRPEvent> NXTWRPTouch(NXTWRPEngine *e,int state,int x,int y) {e->activate();if(e->dirty)e->build();e->events.clear();e->input=true;try{e->page->NotifyTouch((TOUCH_STATE)state,x,y);}catch(...){e->input=false;e->checkboxInput=false;e->sliderInput=false;throw;}e->input=false;if(e->pendingSort){e->pendingSort=false;e->page->NotifyVarChange("tw_gui_sort_order",e->values["tw_gui_sort_order"]);}auto out=std::move(e->events);e->events.clear();if(out.size()>1)out.resize(1);return out;}
std::vector<CGRect> NXTWRPControlBounds(NXTWRPEngine *e,bool sliders) {e->activate();if(e->dirty)e->build();return e->page->controls(sliders);}

std::vector<std::pair<int,CGRect>> NXTWRPMenuBounds(NXTWRPEngine *e) {
    e->activate();if(e->dirty)e->build();
    for(auto o:e->page->objects()) {if(auto files=dynamic_cast<NXFileSelector*>(o))return files->itemBounds();if(auto list=dynamic_cast<NXMenu*>(o))return list->itemBounds();}return {};
}

std::vector<std::pair<NXTWRPEvent,CGRect>> NXTWRPBindings(NXTWRPEngine *e) {
    e->activate();if(e->dirty)e->build();std::vector<std::pair<NXTWRPEvent,CGRect>> out;
    std::map<NXTWRPEvent::Kind,CGRect> nav;
    for(auto object:e->page->objects()) {
        if(!object->isConditionTrue())continue;
        auto r=dynamic_cast<RenderObject*>(object);if(!r)continue;int x,y,w,h;r->GetRenderPos(x,y,w,h);CGRect rect=CGRectMake(x,y,w,h);
        std::optional<NXTWRPEvent> binding;
        if(auto button=dynamic_cast<NXButton*>(object))binding=button->binding;
        if(dynamic_cast<GUIInput*>(object) && HasTextInput(e->model) && !NXTWRPIsFileManagerInput(e->model) && !NXTWRPIsBootArgumentsInput(e->model))binding=NXTWRPEvent{NXTWRPEvent::Select,IsFormatData(e->model)?2:1};
        if(auto checkbox=dynamic_cast<NXCheckbox*>(object))if(checkbox->index>=0)binding=NXTWRPEvent{NXTWRPEvent::Select,checkbox->index};
        if(dynamic_cast<GUISlider*>(object)) {
            if(WipeSliderIndex(e->model)>=0)binding=NXTWRPEvent{NXTWRPEvent::Select,WipeSliderIndex(e->model)};
            else if(e->model.confirmation)binding=NXTWRPEvent{NXTWRPEvent::Select,1};
            else if(e->model.certificate)binding=NXTWRPEvent{NXTWRPEvent::Select,2};
        }
        if(auto value=dynamic_cast<NXValueSlider*>(object))if(value->setting>=0)binding=NXTWRPEvent{NXTWRPEvent::Settings,10000+value->setting};
        if(!binding)continue;
        if(WipeSliderIndex(e->model)>=0 && binding->kind==NXTWRPEvent::Select && binding->index==WipeSliderIndex(e->model) && !dynamic_cast<GUISlider*>(object))continue;
        if(e->model.confirmation && binding->kind==NXTWRPEvent::Select && binding->index==1 && !dynamic_cast<GUISlider*>(object))continue;
        if(binding->kind==NXTWRPEvent::Select || binding->kind==NXTWRPEvent::Complete || binding->kind==NXTWRPEvent::Sort || binding->kind==NXTWRPEvent::Settings)out.push_back({*binding,rect});else nav[binding->kind]=rect;
    }
    std::vector<std::pair<NXTWRPEvent,CGRect>> result;
    for(auto kind:{NXTWRPEvent::Back,NXTWRPEvent::Home,NXTWRPEvent::Log})if(nav.count(kind))result.push_back({{kind},nav[kind]});
    result.insert(result.end(),out.begin(),out.end());
    for(auto row:NXTWRPMenuBounds(e))result.push_back({{NXTWRPEvent::Select,row.first},row.second});
    for(auto object:e->page->objects())if(auto list=dynamic_cast<NXSettingsList*>(object)){auto rows=list->bindings();result.insert(result.end(),rows.begin(),rows.end());}
    return result;
}
bool NXTWRPSettingsDetailActive(NXTWRPEngine *e){return e && IsSettings(e->model) && e->settingsTab!=0;}
std::vector<CGRect> NXTWRPScrollBounds(NXTWRPEngine *e) {
    e->activate();if(e->dirty)e->build();std::vector<CGRect> result;
    for(auto object:e->page->objects())if(auto list=dynamic_cast<NXSettingsList*>(object)) {for(auto row:list->bindings())result.push_back(row.second);return result;}
    for(auto row:NXTWRPMenuBounds(e))result.push_back(row.second);return result;
}
std::string NXTWRPSettingsLabel(NXTWRPEngine *e,int index) {
    if(index>=10000 && index<10003)return std::vector<std::string>{"Brightness","Button Vibration","Keyboard Vibration"}[index-10000];
    if(index>=100)return e->settingsTab==4?"English":TimeZones().at(index-100).first;
    if(index==10)return e->settingsTab==4?"Set Language":"Set Time Zone";
    return settingsNames.at(index);
}
std::string NXTWRPSettingsValue(NXTWRPEngine *e,int index) {
    if(index>=10000){e->activate();return DataManager::GetStrValue(settingsVariables.at(index-10000));}
    if(index>=100)return e->settingsTab==4 || TimeZones().at(index-100).second==e->pendingTimeZone?"Selected":"";
    return index==e->settingsTab?"Selected":"";
}
void NXTWRPActivateSettings(NXTWRPEngine *e,int index) {
    e->activate();if(index<5)nx_twrp_action("page",settingsPages.at(index));
    else if(index==10)nx_twrp_action("nyxiansettingsapply","");
    else if(index>=100 && index<10000 && e->settingsTab==1)e->pendingTimeZone=TimeZones().at(index-100).second;
}
void NXTWRPAdjustSetting(NXTWRPEngine *e,int index,int delta) {
    if(index<10000 || index>=10003)return;e->activate();std::string variable=settingsVariables[index-10000];
    int value=DataManager::GetIntValue(variable)+delta*(index==10000?5:10);
    e->input=true;DataManager::SetValue(variable,std::clamp(value,index==10000?10:0,index==10000?100:300));e->input=false;
}
bool NXTWRPValidateTheme(NSString *directory,NSError **error) {
    NXTWRPEngine *previous=active;std::unique_ptr<NXTWRPEngine> e=std::make_unique<NXTWRPEngine>();e->validating=true;e->themePath=directory;
    bool valid=false;auto engine=e.get();
    try {
        e->load();e->model.home=true;e->model.titles={"Install","Wipe","Backup","Restore","Mount","Settings","Advanced","Reboot"};e->model.enabled=std::vector<bool>(8,true);
        UIGraphicsImageRendererFormat *format=[UIGraphicsImageRendererFormat defaultFormat];format.scale=1;
        UIGraphicsImageRenderer *renderer=[[UIGraphicsImageRenderer alloc] initWithSize:CGSizeMake(1080,1920) format:format];
        [renderer imageWithActions:^(UIGraphicsImageRendererContext *ctx){NXTWRPRender(engine,ctx.CGContext,1080,1920);}];
        std::set<int> actions;for(auto b:NXTWRPBindings(e.get()))if(b.first.kind==NXTWRPEvent::Select && !CGRectIsEmpty(CGRectIntersection(b.second,CGRectMake(0,0,1080,1920))))actions.insert(b.first.index);
        for(int required:{0,1,5,6,7})if(!actions.count(required))throw std::runtime_error("Theme home page must expose Install, Wipe, Settings, Advanced and Reboot");
        e->model.home=false;e->model.header="Settings";e->model.titles={"Option","Action"};e->model.enabled={true,true};e->model.checks={1,-1};e->dirty=true;
        [renderer imageWithActions:^(UIGraphicsImageRendererContext *ctx){NXTWRPRender(engine,ctx.CGContext,1080,1920);}];
        bool back=false;for(auto b:NXTWRPBindings(e.get()))if(b.first.kind==NXTWRPEvent::Back)back=true;if(!back)throw std::runtime_error("Theme header must expose a Back control");
        e->model.checks={};e->model.confirmation=true;e->model.titles={"Cancel","Confirm"};e->dirty=true;
        [renderer imageWithActions:^(UIGraphicsImageRendererContext *ctx){NXTWRPRender(engine,ctx.CGContext,1080,1920);}];
        e->model.console=true;e->model.complete=true;e->dirty=true;
        [renderer imageWithActions:^(UIGraphicsImageRendererContext *ctx){NXTWRPRender(engine,ctx.CGContext,1080,1920);}];
        e->model.console=false;e->model.complete=false;e->model.confirmation=false;e->model.browserPath=NSHomeDirectory().UTF8String;e->model.filePaths.clear();e->dirty=true;
        [renderer imageWithActions:^(UIGraphicsImageRendererContext *ctx){NXTWRPRender(engine,ctx.CGContext,1080,1920);}];valid=true;
    }catch(const std::exception& ex){if(error)*error=[NSError errorWithDomain:@"NXTWRPTheme" code:2 userInfo:@{NSLocalizedDescriptionKey:@(ex.what())}];}
    e.reset();context=nullptr;if(previous)previous->activate();else{active=nullptr;themeAssets=nil;}return valid;
}

UIColor *NXTWRPAccentColor(NXTWRPEngine *e) {
    e->activate();COLOR color(0,144,202);std::string value=e->values["accent_color"];
    ConvertStrToColor(value,&color);return [UIColor colorWithRed:color.red/255.0 green:color.green/255.0 blue:color.blue/255.0 alpha:1];
}

int NXTWRPBrowserIndexAfterMoving(NXTWRPEngine *e,int delta,int current) {
    e->activate();if(e->dirty)e->build();
    for(auto object:e->page->objects())if(auto files=dynamic_cast<NXFileSelector*>(object)) {
        auto order=files->order();if(order.empty())return 0;
        auto found=std::find(order.begin(),order.end(),current);if(found==order.end())return order.front();
        int row=(int)(found-order.begin());return order[(row+delta%(int)order.size()+(int)order.size())%order.size()];
    }return current;
}
void NXTWRPSortFiles(NXTWRPEngine *e,int order) {
    if(!order || abs(order)>3)return;e->activate();if(e->dirty)e->build();
    e->values["tw_gui_sort_order"]=std::to_string(order);e->page->NotifyVarChange("tw_gui_sort_order",e->values["tw_gui_sort_order"]);
    for(auto object:e->page->objects())if(auto files=dynamic_cast<NXFileSelector*>(object)){files->Update();files->focusNative(e->model.selected);}
}

UIImage *NXTWRPBootSplashImage(CGSize size) {
    if(size.width<=0 || size.height<=0)return nil;
    NSCAssert(NSThread.isMainThread,@"TWRP splash rendering belongs on the main thread");
    NXTWRPEngine *previous=active;
    CGContextRef previousContext=context;UIColor *previousInk=ink;bool previousClip=clipped;
    UIImage *result=nil;
    auto owned=std::make_unique<NXTWRPEngine>();auto engine=owned.get();
    context=nullptr;
    try {
        engine->width=1080;engine->height=(int)lround(size.height*1080/size.width);
        engine->load(); // Use the bundled stock resources, independent of imported recovery themes.
        xml_document<> splash;std::vector<char> buffer;
        if(!ReadXML("splash.xml",splash,buffer))throw std::runtime_error("Missing TWRP splash page");
        auto root=splash.first_node("recovery");
        for(auto v=root->first_node("variables")->first_node("variable");v;v=v->next_sibling("variable"))
            engine->values[LoadAttrString(v,"name")]=LoadAttrString(v,"value");
        engine->resources->LoadResources(root->first_node("resources"),nullptr,"TWRP splash");
        for(const char *name:{"splashlogo","splashteamwin"}) {
            auto image=engine->resources->FindImage(name);
            if(!image || !image->GetResource())throw std::runtime_error("Missing TWRP splash image");
        }
        engine->values["tw_version"]=std::string([(NSBundle.mainBundle.infoDictionary[@"CFBundleShortVersionString"]?:@"") UTF8String]);
        engine->page=std::make_unique<NXPage>(root->first_node("pages")->first_node("page"),&engine->templates);
        engine->page->NotifyVarChange("","");engine->page->SetPageFocus(1);
        UIGraphicsImageRendererFormat *format=[UIGraphicsImageRendererFormat defaultFormat];format.opaque=YES;
        UIGraphicsImageRenderer *renderer=[[UIGraphicsImageRenderer alloc] initWithSize:size format:format];
        result=[renderer imageWithActions:^(UIGraphicsImageRendererContext *ctx){
            context=ctx.CGContext;ink=UIColor.whiteColor;clipped=false;engine->activate();
            CGContextScaleCTM(context,size.width/1080.0,size.width/1080.0);
            engine->page->Update();engine->page->Render();
        }];
    } catch(const std::exception& error) {NSLog(@"TWRP splash: %s",error.what());}
    owned.reset();context=previousContext;ink=previousInk;clipped=previousClip;
    if(previous)previous->activate();else {active=nullptr;themeAssets=nil;}
    return result;
}

std::vector<NXTWRPKeyboardKey> NXTWRPKeyboardKeys(NXTWRPEngine *e) {
    e->activate();if(e->dirty)e->build();
    // The terminal page stacks two keyboards (its key row and the letters), every visible key counts.
    std::vector<NXTWRPKeyboardKey> keys;
    for(auto object:e->page->objects())if(auto keyboard=dynamic_cast<NXKeyboard*>(object)){auto more=keyboard->keys();keys.insert(keys.end(),more.begin(),more.end());}
    return keys;
}
std::string NXTWRPCertificatePassword(NXTWRPEngine *e) {return e->model.password;}
