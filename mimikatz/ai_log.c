#include "windows.h"
#include "strsafe.h"
#include "ai_log.h"
#include "ai_interface.h"

char* vsntprintf(const char *formatSpecifier, va_list varArgs) {
  size_t bufferSize = 4 * KILO;
  char   *buffer    = (char *)malloc(bufferSize);
  while (bufferSize < 128 * KILO) {
    if (!buffer)
      break;

    if (SUCCEEDED(StringCchVPrintfA(buffer, bufferSize, formatSpecifier, varArgs)))
      return buffer;

    bufferSize *= 2;
    free(buffer);
    buffer = (char *)malloc(bufferSize);
  }

  return 0;
}

BOOL DebugPrint(const char *formatSpecifier, ...) {
  va_list varArgs;
  char    *str = 0;
  va_start(varArgs, formatSpecifier);

  if (!gEnableLogging)
    return TRUE;

  str = vsntprintf(formatSpecifier, varArgs);
  va_end(varArgs);
  if (str) {
    OutputDebugStringA(str);
    printf_s(str);
    fflush(stdout);
    return TRUE;
  }
  else {
    OutputDebugStringA("Out of memory\n");
    printf_s("Out of memory\n");
    fflush(stdout);
    return TRUE;
  }
}

wchar_t* vsntprintfW(const wchar_t *formatSpecifier, va_list varArgs) {
  size_t  bufferSize = 4 * KILO;
  wchar_t *buffer    = (wchar_t *)malloc(bufferSize);
  while (bufferSize < 128 * KILO) {
    if (!buffer)
      break;

    if (SUCCEEDED(StringCchVPrintfW(buffer, bufferSize, formatSpecifier, varArgs)))
      return buffer;

    bufferSize *= 2;
    free(buffer);
    buffer = (wchar_t *)malloc(bufferSize);
  }

  return 0;
}

BOOL DebugPrintW(const wchar_t *formatSpecifier, ...) {
  va_list varArgs;
  wchar_t *str = 0;
  va_start(varArgs, formatSpecifier);

  if (!gEnableLogging)
    return TRUE;

  str = vsntprintfW(formatSpecifier, varArgs);
  va_end(varArgs);
  if (str) {
    OutputDebugStringW(str);
    wprintf_s(str);
    fflush(stdout);
    return TRUE;
  }
  else {
    OutputDebugStringW(L"Out of memory\n");
    wprintf_s(L"Out of memory\n");
    fflush(stdout);
    return TRUE;
  }
}

