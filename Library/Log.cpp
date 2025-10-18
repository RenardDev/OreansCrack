#include "Log.h"

// C++
#include <ctime>

Log::Log() {
}

Log::~Log() {
	m_Client.Close();
}

void Log::vlogf(LOG_TYPE unLogType, char const* const szFileName, int nCodeLine, char const* const _Format, const va_list& vargs) {
	time_t unCurrentTime = 0;
	time(&unCurrentTime);
	tm TimeInfo;
	memset(&TimeInfo, 0, sizeof(TimeInfo));

	if (localtime_s(&TimeInfo, &unCurrentTime) != 0) {
		if (unLogType != LOG_TYPE::TYPE_RAW) {
			m_Client.printf(Terminal::COLOR::COLOR_WHITE, "[ <UNKNOWN> - %s:%i ] ", szFileName, nCodeLine);
		}

		switch (unLogType) {
			case LOG_TYPE::TYPE_DEFAULT:
				m_Client.vprintf(Terminal::COLOR::COLOR_WHITE, _Format, vargs);
				break;
			case LOG_TYPE::TYPE_DEBUG:
				m_Client.printf(Terminal::COLOR::COLOR_WHITE, "[ ");
				m_Client.printf(Terminal::COLOR::COLOR_GREEN, "DEBUG");
				m_Client.printf(Terminal::COLOR::COLOR_WHITE, " ] ");
				m_Client.vprintf(Terminal::COLOR::COLOR_WHITE, _Format, vargs);
				break;
			case LOG_TYPE::TYPE_INFO:
				m_Client.printf(Terminal::COLOR::COLOR_WHITE, "[ ");
				m_Client.printf(Terminal::COLOR::COLOR_CYAN, "INFO");
				m_Client.printf(Terminal::COLOR::COLOR_WHITE, " ] ");
				m_Client.vprintf(Terminal::COLOR::COLOR_WHITE, _Format, vargs);
				break;
			case LOG_TYPE::TYPE_WARNING:
				m_Client.printf(Terminal::COLOR::COLOR_WHITE, "[ ");
				m_Client.printf(Terminal::COLOR::COLOR_YELLOW, "WARNING");
				m_Client.printf(Terminal::COLOR::COLOR_WHITE, " ] ");
				m_Client.vprintf(Terminal::COLOR::COLOR_WHITE, _Format, vargs);
				break;
			case LOG_TYPE::TYPE_ERROR:
				m_Client.printf(Terminal::COLOR::COLOR_WHITE, "[ ");
				m_Client.printf(Terminal::COLOR::COLOR_RED, "ERROR");
				m_Client.printf(Terminal::COLOR::COLOR_WHITE, " ] ");
				m_Client.vprintf(Terminal::COLOR::COLOR_WHITE, _Format, vargs);
				break;
			case LOG_TYPE::TYPE_CRITICAL:
				m_Client.printf(Terminal::COLOR::COLOR_WHITE, "[ ");
				m_Client.printf(Terminal::COLOR::COLOR_DARK_RED, "CRITICAL");
				m_Client.printf(Terminal::COLOR::COLOR_WHITE, " ] ");
				m_Client.vprintf(Terminal::COLOR::COLOR_WHITE, _Format, vargs);
				break;
			default:
				m_Client.vprintf(Terminal::COLOR::COLOR_WHITE, _Format, vargs);
				break;
		}

		return;
	}

	char szFormatTime[20];
	memset(szFormatTime, 0, sizeof(szFormatTime));
	if (strftime(szFormatTime, sizeof(szFormatTime) / sizeof(char), "%Y-%m-%d %H:%M:%S", &TimeInfo) == 0) {
		if (unLogType != LOG_TYPE::TYPE_RAW) {
			m_Client.printf(Terminal::COLOR::COLOR_WHITE, "[ <UNKNOWN> - %s:%i ] ", szFileName, nCodeLine);
		}

		switch (unLogType) {
			case LOG_TYPE::TYPE_DEFAULT:
				m_Client.vprintf(Terminal::COLOR::COLOR_WHITE, _Format, vargs);
				break;
			case LOG_TYPE::TYPE_DEBUG:
				m_Client.printf(Terminal::COLOR::COLOR_WHITE, "[ ");
				m_Client.printf(Terminal::COLOR::COLOR_GREEN, "DEBUG");
				m_Client.printf(Terminal::COLOR::COLOR_WHITE, " ] ");
				m_Client.vprintf(Terminal::COLOR::COLOR_WHITE, _Format, vargs);
				break;
			case LOG_TYPE::TYPE_INFO:
				m_Client.printf(Terminal::COLOR::COLOR_WHITE, "[ ");
				m_Client.printf(Terminal::COLOR::COLOR_CYAN, "INFO");
				m_Client.printf(Terminal::COLOR::COLOR_WHITE, " ] ");
				m_Client.vprintf(Terminal::COLOR::COLOR_WHITE, _Format, vargs);
				break;
			case LOG_TYPE::TYPE_WARNING:
				m_Client.printf(Terminal::COLOR::COLOR_WHITE, "[ ");
				m_Client.printf(Terminal::COLOR::COLOR_YELLOW, "WARNING");
				m_Client.printf(Terminal::COLOR::COLOR_WHITE, " ] ");
				m_Client.vprintf(Terminal::COLOR::COLOR_WHITE, _Format, vargs);
				break;
			case LOG_TYPE::TYPE_ERROR:
				m_Client.printf(Terminal::COLOR::COLOR_WHITE, "[ ");
				m_Client.printf(Terminal::COLOR::COLOR_RED, "ERROR");
				m_Client.printf(Terminal::COLOR::COLOR_WHITE, " ] ");
				m_Client.vprintf(Terminal::COLOR::COLOR_WHITE, _Format, vargs);
				break;
			case LOG_TYPE::TYPE_CRITICAL:
				m_Client.printf(Terminal::COLOR::COLOR_WHITE, "[ ");
				m_Client.printf(Terminal::COLOR::COLOR_DARK_RED, "CRITICAL");
				m_Client.printf(Terminal::COLOR::COLOR_WHITE, " ] ");
				m_Client.vprintf(Terminal::COLOR::COLOR_WHITE, _Format, vargs);
				break;
			default:
				m_Client.vprintf(Terminal::COLOR::COLOR_WHITE, _Format, vargs);
				break;
		}

		return;
	}

	if (unLogType != LOG_TYPE::TYPE_RAW) {
		m_Client.printf(Terminal::COLOR::COLOR_WHITE, "[ %s - %s:%i ] ", szFormatTime, szFileName, nCodeLine);
	}

	switch (unLogType) {
		case LOG_TYPE::TYPE_DEFAULT:
			m_Client.vprintf(Terminal::COLOR::COLOR_WHITE, _Format, vargs);
			break;
		case LOG_TYPE::TYPE_DEBUG:
			m_Client.printf(Terminal::COLOR::COLOR_WHITE, "[ ");
			m_Client.printf(Terminal::COLOR::COLOR_GREEN, "DEBUG");
			m_Client.printf(Terminal::COLOR::COLOR_WHITE, " ] ");
			m_Client.vprintf(Terminal::COLOR::COLOR_WHITE, _Format, vargs);
			break;
		case LOG_TYPE::TYPE_INFO:
			m_Client.printf(Terminal::COLOR::COLOR_WHITE, "[ ");
			m_Client.printf(Terminal::COLOR::COLOR_CYAN, "INFO");
			m_Client.printf(Terminal::COLOR::COLOR_WHITE, " ] ");
			m_Client.vprintf(Terminal::COLOR::COLOR_WHITE, _Format, vargs);
			break;
		case LOG_TYPE::TYPE_WARNING:
			m_Client.printf(Terminal::COLOR::COLOR_WHITE, "[ ");
			m_Client.printf(Terminal::COLOR::COLOR_YELLOW, "WARNING");
			m_Client.printf(Terminal::COLOR::COLOR_WHITE, " ] ");
			m_Client.vprintf(Terminal::COLOR::COLOR_WHITE, _Format, vargs);
			break;
		case LOG_TYPE::TYPE_ERROR:
			m_Client.printf(Terminal::COLOR::COLOR_WHITE, "[ ");
			m_Client.printf(Terminal::COLOR::COLOR_RED, "ERROR");
			m_Client.printf(Terminal::COLOR::COLOR_WHITE, " ] ");
			m_Client.vprintf(Terminal::COLOR::COLOR_WHITE, _Format, vargs);
			break;
		case LOG_TYPE::TYPE_CRITICAL:
			m_Client.printf(Terminal::COLOR::COLOR_WHITE, "[ ");
			m_Client.printf(Terminal::COLOR::COLOR_DARK_RED, "CRITICAL");
			m_Client.printf(Terminal::COLOR::COLOR_WHITE, " ] ");
			m_Client.vprintf(Terminal::COLOR::COLOR_WHITE, _Format, vargs);
			break;
		default:
			m_Client.vprintf(Terminal::COLOR::COLOR_WHITE, _Format, vargs);
			break;
	}
}

void Log::logf(LOG_TYPE unLogType, char const* const szFileName, int nCodeLine, char const* const _Format, ...) {
	va_list vargs;
	va_start(vargs, _Format);
	vlogf(unLogType, szFileName, nCodeLine, _Format, vargs);
	va_end(vargs);
}

void Log::vwlogf(LOG_TYPE unLogType, wchar_t const* const szFileName, int nCodeLine, wchar_t const* const _Format, const va_list& vargs) {
	time_t unCurrentTime = 0;
	time(&unCurrentTime);
	tm TimeInfo;
	memset(&TimeInfo, 0, sizeof(TimeInfo));

	if (localtime_s(&TimeInfo, &unCurrentTime) != 0) {
		if (unLogType != LOG_TYPE::TYPE_RAW) {
			m_Client.wprintf(Terminal::COLOR::COLOR_WHITE, L"[ <UNKNOWN> - %s:%i ] ", szFileName, nCodeLine);
		}

		switch (unLogType) {
			case LOG_TYPE::TYPE_DEFAULT:
				m_Client.vwprintf(Terminal::COLOR::COLOR_WHITE, _Format, vargs);
				break;
			case LOG_TYPE::TYPE_DEBUG:
				m_Client.wprintf(Terminal::COLOR::COLOR_WHITE, L"[ ");
				m_Client.wprintf(Terminal::COLOR::COLOR_GREEN, L"DEBUG");
				m_Client.wprintf(Terminal::COLOR::COLOR_WHITE, L" ] ");
				m_Client.vwprintf(Terminal::COLOR::COLOR_WHITE, _Format, vargs);
				break;
			case LOG_TYPE::TYPE_INFO:
				m_Client.wprintf(Terminal::COLOR::COLOR_WHITE, L"[ ");
				m_Client.wprintf(Terminal::COLOR::COLOR_CYAN, L"INFO");
				m_Client.wprintf(Terminal::COLOR::COLOR_WHITE, L" ] ");
				m_Client.vwprintf(Terminal::COLOR::COLOR_WHITE, _Format, vargs);
				break;
			case LOG_TYPE::TYPE_WARNING:
				m_Client.wprintf(Terminal::COLOR::COLOR_WHITE, L"[ ");
				m_Client.wprintf(Terminal::COLOR::COLOR_YELLOW, L"WARNING");
				m_Client.wprintf(Terminal::COLOR::COLOR_WHITE, L" ] ");
				m_Client.vwprintf(Terminal::COLOR::COLOR_WHITE, _Format, vargs);
				break;
			case LOG_TYPE::TYPE_ERROR:
				m_Client.wprintf(Terminal::COLOR::COLOR_WHITE, L"[ ");
				m_Client.wprintf(Terminal::COLOR::COLOR_RED, L"ERROR");
				m_Client.wprintf(Terminal::COLOR::COLOR_WHITE, L" ] ");
				m_Client.vwprintf(Terminal::COLOR::COLOR_WHITE, _Format, vargs);
				break;
			case LOG_TYPE::TYPE_CRITICAL:
				m_Client.wprintf(Terminal::COLOR::COLOR_WHITE, L"[ ");
				m_Client.wprintf(Terminal::COLOR::COLOR_DARK_RED, L"CRITICAL");
				m_Client.wprintf(Terminal::COLOR::COLOR_WHITE, L" ] ");
				m_Client.vwprintf(Terminal::COLOR::COLOR_WHITE, _Format, vargs);
				break;
			default:
				m_Client.vwprintf(Terminal::COLOR::COLOR_WHITE, _Format, vargs);
				break;
		}

		return;
	}

	wchar_t szFormatTime[20];
	memset(szFormatTime, 0, sizeof(szFormatTime));
	if (wcsftime(szFormatTime, sizeof(szFormatTime) / sizeof(wchar_t), L"%Y-%m-%d %H:%M:%S", &TimeInfo) == 0) {
		if (unLogType != LOG_TYPE::TYPE_RAW) {
			m_Client.wprintf(Terminal::COLOR::COLOR_WHITE, L"[ <UNKNOWN> - %s:%i ] ", szFileName, nCodeLine);
		}

		switch (unLogType) {
			case LOG_TYPE::TYPE_DEFAULT:
				m_Client.vwprintf(Terminal::COLOR::COLOR_WHITE, _Format, vargs);
				break;
			case LOG_TYPE::TYPE_DEBUG:
				m_Client.wprintf(Terminal::COLOR::COLOR_WHITE, L"[ ");
				m_Client.wprintf(Terminal::COLOR::COLOR_GREEN, L"DEBUG");
				m_Client.wprintf(Terminal::COLOR::COLOR_WHITE, L" ] ");
				m_Client.vwprintf(Terminal::COLOR::COLOR_WHITE, _Format, vargs);
				break;
			case LOG_TYPE::TYPE_INFO:
				m_Client.wprintf(Terminal::COLOR::COLOR_WHITE, L"[ ");
				m_Client.wprintf(Terminal::COLOR::COLOR_CYAN, L"INFO");
				m_Client.wprintf(Terminal::COLOR::COLOR_WHITE, L" ] ");
				m_Client.vwprintf(Terminal::COLOR::COLOR_WHITE, _Format, vargs);
				break;
			case LOG_TYPE::TYPE_WARNING:
				m_Client.wprintf(Terminal::COLOR::COLOR_WHITE, L"[ ");
				m_Client.wprintf(Terminal::COLOR::COLOR_YELLOW, L"WARNING");
				m_Client.wprintf(Terminal::COLOR::COLOR_WHITE, L" ] ");
				m_Client.vwprintf(Terminal::COLOR::COLOR_WHITE, _Format, vargs);
				break;
			case LOG_TYPE::TYPE_ERROR:
				m_Client.wprintf(Terminal::COLOR::COLOR_WHITE, L"[ ");
				m_Client.wprintf(Terminal::COLOR::COLOR_RED, L"ERROR");
				m_Client.wprintf(Terminal::COLOR::COLOR_WHITE, L" ] ");
				m_Client.vwprintf(Terminal::COLOR::COLOR_WHITE, _Format, vargs);
				break;
			case LOG_TYPE::TYPE_CRITICAL:
				m_Client.wprintf(Terminal::COLOR::COLOR_WHITE, L"[ ");
				m_Client.wprintf(Terminal::COLOR::COLOR_DARK_RED, L"CRITICAL");
				m_Client.wprintf(Terminal::COLOR::COLOR_WHITE, L" ] ");
				m_Client.vwprintf(Terminal::COLOR::COLOR_WHITE, _Format, vargs);
				break;
			default:
				m_Client.vwprintf(Terminal::COLOR::COLOR_WHITE, _Format, vargs);
				break;
		}

		return;
	}

	if (unLogType != LOG_TYPE::TYPE_RAW) {
		m_Client.wprintf(Terminal::COLOR::COLOR_WHITE, L"[ %s - %s:%i ] ", szFormatTime, szFileName, nCodeLine);
	}

	switch (unLogType) {
		case LOG_TYPE::TYPE_DEFAULT:
			m_Client.vwprintf(Terminal::COLOR::COLOR_WHITE, _Format, vargs);
			break;
		case LOG_TYPE::TYPE_DEBUG:
			m_Client.wprintf(Terminal::COLOR::COLOR_WHITE, L"[ ");
			m_Client.wprintf(Terminal::COLOR::COLOR_GREEN, L"DEBUG");
			m_Client.wprintf(Terminal::COLOR::COLOR_WHITE, L" ] ");
			m_Client.vwprintf(Terminal::COLOR::COLOR_WHITE, _Format, vargs);
			break;
		case LOG_TYPE::TYPE_INFO:
			m_Client.wprintf(Terminal::COLOR::COLOR_WHITE, L"[ ");
			m_Client.wprintf(Terminal::COLOR::COLOR_CYAN, L"INFO");
			m_Client.wprintf(Terminal::COLOR::COLOR_WHITE, L" ] ");
			m_Client.vwprintf(Terminal::COLOR::COLOR_WHITE, _Format, vargs);
			break;
		case LOG_TYPE::TYPE_WARNING:
			m_Client.wprintf(Terminal::COLOR::COLOR_WHITE, L"[ ");
			m_Client.wprintf(Terminal::COLOR::COLOR_YELLOW, L"WARNING");
			m_Client.wprintf(Terminal::COLOR::COLOR_WHITE, L" ] ");
			m_Client.vwprintf(Terminal::COLOR::COLOR_WHITE, _Format, vargs);
			break;
		case LOG_TYPE::TYPE_ERROR:
			m_Client.wprintf(Terminal::COLOR::COLOR_WHITE, L"[ ");
			m_Client.wprintf(Terminal::COLOR::COLOR_RED, L"ERROR");
			m_Client.wprintf(Terminal::COLOR::COLOR_WHITE, L" ] ");
			m_Client.vwprintf(Terminal::COLOR::COLOR_WHITE, _Format, vargs);
			break;
		case LOG_TYPE::TYPE_CRITICAL:
			m_Client.wprintf(Terminal::COLOR::COLOR_WHITE, L"[ ");
			m_Client.wprintf(Terminal::COLOR::COLOR_DARK_RED, L"CRITICAL");
			m_Client.wprintf(Terminal::COLOR::COLOR_WHITE, L" ] ");
			m_Client.vwprintf(Terminal::COLOR::COLOR_WHITE, _Format, vargs);
			break;
		default:
			m_Client.vwprintf(Terminal::COLOR::COLOR_WHITE, _Format, vargs);
			break;
	}
}

void Log::wlogf(LOG_TYPE unLogType, wchar_t const* const szFileName, int nCodeLine, wchar_t const* const _Format, ...) {
	va_list vargs;
	va_start(vargs, _Format);
	vwlogf(unLogType, szFileName, nCodeLine, _Format, vargs);
	va_end(vargs);
}

#ifdef _UNICODE
void Log::tvlogf(LOG_TYPE unLogType, wchar_t const* const szFileName, int nCodeLine, wchar_t const* const _Format, const va_list& vargs) {
	vwlogf(unLogType, szFileName, nCodeLine, _Format, vargs);
}

void Log::tlogf(LOG_TYPE unLogType, wchar_t const* const szFileName, int nCodeLine, wchar_t const* const _Format, ...) {
	va_list vargs;
	va_start(vargs, _Format);
	tvlogf(unLogType, szFileName, nCodeLine, _Format, vargs);
	va_end(vargs);
}
#else
void Log::tvlogf(LOG_TYPE unLogType, char const* const szFileName, int nCodeLine, char const* const _Format, const va_list& vargs) {
	vlogf(unLogType, szFileName, nCodeLine, _Format, vargs);
}

void Log::tlogf(LOG_TYPE unLogType, char const* const szFileName, int nCodeLine, char const* const _Format, ...) {
	va_list vargs;
	va_start(vargs, _Format);
	tvlogf(unLogType, szFileName, nCodeLine, _Format, vargs);
	va_end(vargs);
}
#endif

Terminal::Client& Log::GetClient() {
	return m_Client;
}

Log& GetLog() {
	static Log instance;
	return instance;
}
