#ifndef __DIALOG_H__
#define __DIALOG_H__

void ok_dialog(const char *str, bool sound=false);
bool yes_no_dialog(const char *str, bool sound, bool defaultYes);
void message_dialog(const char *str, bool (* check_finish)(void));

#endif /* __DIALOG_H__ */

