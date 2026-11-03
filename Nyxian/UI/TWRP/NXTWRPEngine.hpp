/* SPDX-License-Identifier: GPL-3.0-or-later */

#pragma once
#include <string>
#include <vector>
#include <CoreGraphics/CoreGraphics.h>

struct NXTWRPModel {
    std::string header,instructions,browserPath,password,progressStatus;
    int progress=-1;
    bool certificate=false,keyboardHidden=true,navigationFocus=false;
    std::vector<std::string> filePaths;
    std::vector<std::string> titles,log,logColors;
    std::vector<bool> enabled;
    std::vector<int> checks; // -1=action, 0/1=checkbox
    int selected=0;
    bool home=false,confirmation=false,back=false,console=false,complete=false,showLog=false,terminal=false;
    /* a finished console: its button ("Continue", "Reboot") and subtitle ("Complete", "Boot failed") */
    std::string completeTitle="Continue",completeStatus="Complete";
};

/* TWRP's file manager pages (filemanageroptions, filemanagerconfirm and the name/permissions inputs), keyed by their header */
inline bool NXTWRPIsFileManagerOptions(const NXTWRPModel& m) {return m.header=="File Manager\nChoose Action";}
inline bool NXTWRPIsFileManagerConfirm(const NXTWRPModel& m) {return m.header=="File Manager\nConfirm Action" && m.titles.size()==2;}
inline bool NXTWRPIsFileManagerInput(const NXTWRPModel& m) {return (m.header=="File Manager\nRename File" || m.header=="File Manager\nRename Folder" || m.header=="File Manager\nSet Permissions") && m.titles.size()==2;}

/* Settings > General > Boot Arguments: Cancel / Save around a text input (NXRecoveryViewController enterBootArgumentsInput) */
inline bool NXTWRPIsBootArgumentsInput(const NXTWRPModel& m) {return m.header=="Settings\nBoot Arguments" && m.titles.size()==2;}
struct NXTWRPEvent { enum Kind { Select,Back,Home,Log,Complete,Sort,Settings } kind; int index=0; };
class NXTWRPEngine;
NXTWRPEngine *NXTWRPCreate();
void NXTWRPDestroy(NXTWRPEngine*);
void NXTWRPReloadTheme(NXTWRPEngine*);
void NXTWRPSetNavigationFocus(NXTWRPEngine*,bool);
std::string NXTWRPSettingsLabel(NXTWRPEngine*,int);
std::string NXTWRPSettingsValue(NXTWRPEngine*,int);
void NXTWRPActivateSettings(NXTWRPEngine*,int);
void NXTWRPAdjustSetting(NXTWRPEngine*,int,int);
bool NXTWRPSettingsDetailActive(NXTWRPEngine*);
std::vector<CGRect> NXTWRPScrollBounds(NXTWRPEngine*);
void NXTWRPSetModel(NXTWRPEngine*,const NXTWRPModel&);
bool NXTWRPKeyboardHidden(NXTWRPEngine*);
void NXTWRPRender(NXTWRPEngine*,CGContextRef,int width,int height);
std::vector<NXTWRPEvent> NXTWRPTouch(NXTWRPEngine*,int state,int x,int y);
/* Test/accessibility geometry comes from actual upstream RenderObject instances. */
std::vector<CGRect> NXTWRPControlBounds(NXTWRPEngine*,bool sliders);

std::vector<std::pair<int,CGRect>> NXTWRPMenuBounds(NXTWRPEngine*);

std::vector<std::pair<NXTWRPEvent,CGRect>> NXTWRPBindings(NXTWRPEngine*);
#ifdef __OBJC__
@class NSString, NSError, UIColor, UIView;
void NXTWRPResumePresentation(NXTWRPEngine*,UIView*);
void NXTWRPPrepareFeedback(NXTWRPEngine*);
UIColor *NXTWRPAccentColor(NXTWRPEngine*);
bool NXTWRPValidateTheme(NSString *directory,NSError **error);
#endif

int NXTWRPBrowserIndexAfterMoving(NXTWRPEngine*,int delta,int current);
void NXTWRPSortFiles(NXTWRPEngine*,int order);

struct NXTWRPKeyboardKey {std::string label;CGRect bounds;};
std::vector<NXTWRPKeyboardKey> NXTWRPKeyboardKeys(NXTWRPEngine*);
std::string NXTWRPCertificatePassword(NXTWRPEngine*);
