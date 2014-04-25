#include <stdio.h>
#include <windows.h>

#ifdef BUILD_DLL
    #define DLL_EXPORT __declspec(dllexport)
#else
    #define DLL_EXPORT __declspec(dllimport)
#endif

void DLL_EXPORT messageBox(const LPCSTR msg){
    MessageBoxA(NULL, msg, "DLL Message", MB_OK | MB_ICONINFORMATION);
}
extern "C" DLL_EXPORT BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved){
    CHAR Buff[128];
    switch (fdwReason){
        case DLL_PROCESS_ATTACH:
            _snprintf(Buff, sizeof(Buff)-1, "DLL injected, PID : %u\n", GetCurrentProcessId());
            messageBox(Buff);
            break;
        case DLL_PROCESS_DETACH:
            messageBox("DLL motherfucker");
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}
