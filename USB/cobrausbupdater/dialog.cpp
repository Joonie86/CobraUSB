#include <sysutil/sysutil_msgdialog.h>
#include "common.h"
#include "dialog.h"
#include "graphics.h"

static int dialog_result;

static void yes_no_dialog_callback(int buttonType, void *)
{
	dialog_result = (buttonType == CELL_MSGDIALOG_BUTTON_YES) ? 1 : 0;
}

static void ok_dialog_callback(int , void *)
{
	dialog_result = 0;
}

static void dummy_callback(int, void *)
{
}

bool yes_no_dialog(const char *str, bool sound, bool defaultYes)
{
	unsigned int flags;
	
	flags = CELL_MSGDIALOG_TYPE_SE_TYPE_NORMAL | CELL_MSGDIALOG_TYPE_BUTTON_TYPE_YESNO | CELL_MSGDIALOG_TYPE_DISABLE_CANCEL_ON;
	
	if (sound)
		flags |= CELL_MSGDIALOG_TYPE_SE_MUTE_ON;
	
	if (!defaultYes)
		flags |= CELL_MSGDIALOG_TYPE_DEFAULT_CURSOR_NO;
	else
		flags |= CELL_MSGDIALOG_TYPE_DEFAULT_CURSOR_YES;
	
	dialog_result = -1;
	
	int ret;
	
	for (int i = 0; i < 20; i++)
	{
		ret = cellMsgDialogOpen2(flags, str, yes_no_dialog_callback, NULL, NULL);
		if (ret != (int)CELL_SYSUTIL_ERROR_BUSY)
			break;
		
		sys_timer_usleep(50000);
	}
	if (ret != 0)
		return false;
	
	while (dialog_result < 0)
	{
		cellSysutilCheckCallback();
		flip();
	}
	
	cellMsgDialogAbort();
	setRenderColor();
	
	return (dialog_result == 1);
}


void ok_dialog(const char *str, bool sound)
{
	unsigned int flags;
	
	flags = CELL_MSGDIALOG_TYPE_SE_TYPE_NORMAL | CELL_MSGDIALOG_TYPE_BUTTON_TYPE_OK | CELL_MSGDIALOG_TYPE_DEFAULT_CURSOR_OK | CELL_MSGDIALOG_TYPE_DISABLE_CANCEL_ON;
	
	if (sound)
		flags |= CELL_MSGDIALOG_TYPE_SE_MUTE_ON;
	
	dialog_result = -1;
	
	int ret;
	
	for (int i = 0; i < 20; i++)
	{
		ret = cellMsgDialogOpen2(flags, str, ok_dialog_callback, NULL, NULL);
		if (ret != (int)CELL_SYSUTIL_ERROR_BUSY)
			break;
		
		sys_timer_usleep(50000);
	}
	if (ret != 0)
		return;
	
	while (dialog_result < 0)
	{
		cellSysutilCheckCallback();
		flip();
	}
	
	cellMsgDialogAbort();
	setRenderColor();
}


void message_dialog(const char *str, bool (* check_finish)(void))
{
	unsigned int flags;
	int ret;
	
	flags = CELL_MSGDIALOG_TYPE_SE_TYPE_NORMAL | CELL_MSGDIALOG_TYPE_DISABLE_CANCEL_ON;
	
	for (int i = 0; i < 20; i++)
	{
		ret = cellMsgDialogOpen2(flags, str, dummy_callback, NULL, NULL);
		if (ret != (int)CELL_SYSUTIL_ERROR_BUSY)
			break;
		
		sys_timer_usleep(50000);
	}
	
	if (ret != 0)
		return;
	
	while (!check_finish())
	{
		cellSysutilCheckCallback();
		flip();
	}
	
	cellMsgDialogAbort();
	setRenderColor();
}