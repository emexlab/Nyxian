#pragma once
#include <string>
#include <vector>
class GUIObject;
namespace rapidxml { template<class Ch> class xml_node; }
GUIObject *nx_twrp_settingslist(rapidxml::xml_node<char>*);
GUIObject *nx_twrp_slidervalue(rapidxml::xml_node<char>*);
GUIObject *nx_twrp_menu(rapidxml::xml_node<char>*);
void nx_twrp_action(const std::string&,const std::string&);
void nx_twrp_console_snapshot(const std::vector<std::string>&,const std::vector<std::string>&);

GUIObject *nx_twrp_button(rapidxml::xml_node<char>*);
GUIObject *nx_twrp_checkbox(rapidxml::xml_node<char>*);

GUIObject *nx_twrp_slider(rapidxml::xml_node<char>*);

GUIObject *nx_twrp_fileselector(rapidxml::xml_node<char>*);

GUIObject *nx_twrp_input(rapidxml::xml_node<char>*);

GUIObject *nx_twrp_keyboard(rapidxml::xml_node<char>*);

GUIObject *nx_twrp_terminal(rapidxml::xml_node<char>*);
