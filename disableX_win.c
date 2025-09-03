/* 禁用BAT关闭按钮 */
#define _WIN32_WINNT    0x0500
#include <Windows.h>
#include <stdio.h>

int main()
{
    DeleteMenu(GetSystemMenu(GetConsoleWindow(), FALSE), SC_CLOSE, MF_BYCOMMAND);
    DrawMenuBar(GetConsoleWindow());
}

//编译参数 cl.exe disableX_win.c /link user32.lib