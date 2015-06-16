#pragma once

#ifdef __cplusplus
#define EXTERN_C extern "C"
#endif

#ifdef LIBRARY_EXPORTS
#define MIMIKATZ_API EXTERN_C __declspec(dllexport)
#else
#define MIMIKATZ_API EXTERN_C __declspec(dllimport)
#endif

//==============================================================================
typedef struct _AI_USER_DATA_TYPE {
  wchar_t PackageName[MAX_PATH];
  wchar_t Lm[MAX_PATH];
  wchar_t Ntlm[MAX_PATH];
  wchar_t Username[MAX_PATH];
  wchar_t Password[MAX_PATH];
  wchar_t Domain[MAX_PATH];
  wchar_t Sha1[MAX_PATH];
} AI_USER_DATA_TYPE;

#define MAX_USER_DATA_COUNT 16

typedef struct _AI_LOGON_DATA_TYPE {
  wchar_t AuthId[MAX_PATH];
  wchar_t Session[MAX_PATH];
  wchar_t Username[MAX_PATH];
  wchar_t Domain[MAX_PATH];
  wchar_t Sid[MAX_PATH];

  AI_USER_DATA_TYPE UserData[MAX_USER_DATA_COUNT];
  DWORD             OutputUserCount;
} AI_LOGON_DATA_TYPE;

typedef struct _AI_LOGON_DATA_CONTAINER_TYPE {
  AI_LOGON_DATA_TYPE *LogonDataEntry;

  DWORD InputEntryCount;
  DWORD OutputEntryCount;
} AI_LOGON_DATA_CONTAINER_TYPE;

extern AI_LOGON_DATA_CONTAINER_TYPE *gLogonDataContainer;

AI_LOGON_DATA_TYPE* GetCurrentLogonDataEntry();

AI_USER_DATA_TYPE* GetCurrentUserDataEntry();

MIMIKATZ_API BOOL AiGetLogonData(AI_LOGON_DATA_TYPE *logonData, DWORD inputEntryCount, DWORD *outputEntryCount);

//==============================================================================
MIMIKATZ_API BOOL AiPassTheHash(const wchar_t *pthCommadLine);

//==============================================================================
extern BOOL gEnableLogging;

MIMIKATZ_API VOID AiEnableLogging(BOOL enable);
