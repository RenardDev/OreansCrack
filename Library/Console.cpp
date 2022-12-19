#include "Console.h"

// Framework
#include "framework.h"

static HANDLE g_hPipe = nullptr;
static bool g_bReadyPipe = false;

typedef struct _CONSOLE_MESSAGE {
	char m_pMessage[1024];
	COLOR_PAIR m_ColorPair;
} CONSOLE_MESSAGE, *PCONSOLE_MESSAGE;

bool ConnectToConsole() {
	g_hPipe = CreateNamedPipe(_T("\\\\.\\pipe\\OreansCrack"), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, sizeof(CONSOLE_MESSAGE), sizeof(CONSOLE_MESSAGE), NMPWAIT_USE_DEFAULT_WAIT, NULL);
	if (!g_hPipe || (g_hPipe == INVALID_HANDLE_VALUE)) {
		return false;
	}

	if (!ConnectNamedPipe(g_hPipe, nullptr)) {
		return false;
	}

	g_bReadyPipe = true;

	return true;
}

int clrvprintf(COLOR_PAIR ColorPair, char const* const _Format, va_list vargs) {
	if (!g_bReadyPipe || !g_hPipe || (g_hPipe == INVALID_HANDLE_VALUE)) {
		return -1;
	}

	PCONSOLE_MESSAGE pMessage = new CONSOLE_MESSAGE;
	if (!pMessage) {
		return -1;
	}

	memset(pMessage, 0, sizeof(CONSOLE_MESSAGE));

	pMessage->m_ColorPair = ColorPair;

	int nLength = vsprintf_s(pMessage->m_pMessage, sizeof(CONSOLE_MESSAGE::m_pMessage), _Format, vargs);
	if (nLength == -1) {
		delete pMessage;
		return -1;
	}

	pMessage->m_pMessage[sizeof(CONSOLE_MESSAGE::m_pMessage) - 1] = 0;

	DWORD unNumberOfBytesWritten = 0;
	if (!WriteFile(g_hPipe, pMessage, sizeof(CONSOLE_MESSAGE), &unNumberOfBytesWritten, nullptr)) {
		delete pMessage;
		return -1;
	}

	delete pMessage;
	return nLength;
}

int clrvprintf(COLOR unForegroundColor, char const* const _Format, va_list vargs) {
	return clrvprintf(COLOR_PAIR(unForegroundColor), _Format, vargs);
}

int clrprintf(COLOR_PAIR ColorPair, char const* const _Format, ...) {
	va_list vargs;
	va_start(vargs, _Format);
	int nLength = clrvprintf(ColorPair, _Format, vargs);
	va_end(vargs);
	return nLength;
}

int clrprintf(COLOR unForegroundColor, char const* const _Format, ...) {
	va_list vargs;
	va_start(vargs, _Format);
	int nLength = clrvprintf(unForegroundColor, _Format, vargs);
	va_end(vargs);
	return nLength;
}
