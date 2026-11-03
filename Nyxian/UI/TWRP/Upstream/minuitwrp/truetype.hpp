#pragma once
#include "minui.h"
class twrpTruetype { public:
static void* gr_ttf_loadFont(const char*,int,int);
static void* gr_ttf_scaleFont(void*,int,int);
static void gr_ttf_freeFont(void*);
static int gr_ttf_measureEx(const char*,void*);
static int gr_ttf_maxExW(const char*,void*,int);
static int gr_ttf_getMaxFontHeight(void*);
};
