#pragma once
#include <string>
using std::string;
class DataManager { public:
static int GetValue(const std::string&,std::string&);
static int GetValue(const std::string&,int&);
static std::string GetStrValue(const std::string&);
static int GetIntValue(const std::string&);
static int SetValue(const std::string&,const std::string&,int=0);
static int SetValue(const std::string&,int,int=0);
static int Vibrate(const std::string&);
};
