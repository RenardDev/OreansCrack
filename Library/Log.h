#pragma once

#ifndef _LOG_H_
#define _LOG_H_

// Default
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <tchar.h>

// Terminal
#include "Terminal/Terminal.h"

// ----------------------------------------------------------------
// General definitions
// ----------------------------------------------------------------

#define __FILENAME__ (strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__)
#define __FILENAMEW__ (wcsrchr(__FILEW__, L'\\') ? wcsrchr(__FILEW__, L'\\') + 1 : __FILEW__)

#ifdef _UNICODE
#define __FILENAMET__ __FILENAMEW__
#else
#define __FILENAMET__ __FILENAME__
#endif

#define LOGA(X, ...) GetLog().logf(LOG_TYPE::TYPE_DEFAULT, __FILENAME__, __LINE__, X __VA_OPT__(,) __VA_ARGS__)
#define LOG_DEBUGA(X, ...) GetLog().logf(LOG_TYPE::TYPE_DEBUG, __FILENAME__, __LINE__, X __VA_OPT__(,) __VA_ARGS__)
#define LOG_INFOA(X, ...) GetLog().logf(LOG_TYPE::TYPE_INFO, __FILENAME__, __LINE__, X __VA_OPT__(,) __VA_ARGS__)
#define LOG_WARNINGA(X, ...) GetLog().logf(LOG_TYPE::TYPE_WARNING, __FILENAME__, __LINE__, X __VA_OPT__(,) __VA_ARGS__)
#define LOG_ERRORA(X, ...) GetLog().logf(LOG_TYPE::TYPE_ERROR, __FILENAME__, __LINE__, X __VA_OPT__(,) __VA_ARGS__)
#define LOG_CRITICALA(X, ...) GetLog().logf(LOG_TYPE::TYPE_CRITICAL, __FILENAME__, __LINE__, X __VA_OPT__(,) __VA_ARGS__)
#define LOG_PAUSEA(X, ...) GetLog().GetScreen().PauseA(X __VA_OPT__(,) __VA_ARGS__);

#define LOGW(X, ...) GetLog().wlogf(LOG_TYPE::TYPE_DEFAULT, __FILENAMEW__, __LINE__, X __VA_OPT__(,) __VA_ARGS__)
#define LOG_DEBUGW(X, ...) GetLog().wlogf(LOG_TYPE::TYPE_DEBUG, __FILENAMEW__, __LINE__, X __VA_OPT__(,) __VA_ARGS__)
#define LOG_INFOW(X, ...) GetLog().wlogf(LOG_TYPE::TYPE_INFO, __FILENAMEW__, __LINE__, X __VA_OPT__(,) __VA_ARGS__)
#define LOG_WARNINGW(X, ...) GetLog().wlogf(LOG_TYPE::TYPE_WARNING, __FILENAMEW__, __LINE__, X __VA_OPT__(,) __VA_ARGS__)
#define LOG_ERRORW(X, ...) GetLog().wlogf(LOG_TYPE::TYPE_ERROR, __FILENAMEW__, __LINE__, X __VA_OPT__(,) __VA_ARGS__)
#define LOG_CRITICALW(X, ...) GetLog().wlogf(LOG_TYPE::TYPE_CRITICAL, __FILENAMEW__, __LINE__, X __VA_OPT__(,) __VA_ARGS__)
#define LOG_PAUSEW(X, ...) GetLog().GetScreen().PauseW(X __VA_OPT__(,) __VA_ARGS__);

#define LOG(X, ...) GetLog().tlogf(LOG_TYPE::TYPE_DEFAULT, __FILENAMET__, __LINE__, X __VA_OPT__(,) __VA_ARGS__)
#define LOG_DEBUG(X, ...) GetLog().tlogf(LOG_TYPE::TYPE_DEBUG, __FILENAMET__, __LINE__, X __VA_OPT__(,) __VA_ARGS__)
#define LOG_INFO(X, ...) GetLog().tlogf(LOG_TYPE::TYPE_INFO, __FILENAMET__, __LINE__, X __VA_OPT__(,) __VA_ARGS__)
#define LOG_WARNING(X, ...) GetLog().tlogf(LOG_TYPE::TYPE_WARNING, __FILENAMET__, __LINE__, X __VA_OPT__(,) __VA_ARGS__)
#define LOG_ERROR(X, ...) GetLog().tlogf(LOG_TYPE::TYPE_ERROR, __FILENAMET__, __LINE__, X __VA_OPT__(,) __VA_ARGS__)
#define LOG_CRITICAL(X, ...) GetLog().tlogf(LOG_TYPE::TYPE_CRITICAL, __FILENAMET__, __LINE__, X __VA_OPT__(,) __VA_ARGS__)
#define LOG_PAUSE(X, ...) GetLog().GetScreen().Pause(X __VA_OPT__(,) __VA_ARGS__);

enum class LOG_TYPE : unsigned char {
	TYPE_RAW = 0,
	TYPE_DEFAULT,
	TYPE_DEBUG,
	TYPE_INFO,
	TYPE_WARNING,
	TYPE_ERROR,
	TYPE_CRITICAL
};

class Log {
public:
	Log();
	~Log();

public:
	void vlogf(LOG_TYPE unLogType, char const* const szFileName, int nCodeLine, char const* const _Format, const va_list& vargs);
	void logf(LOG_TYPE unLogType, char const* const szFileName, int nCodeLine, char const* const _Format, ...);

public:
	void vwlogf(LOG_TYPE unLogType, wchar_t const* const szFileName, int nCodeLine, wchar_t const* const _Format, const va_list& vargs);
	void wlogf(LOG_TYPE unLogType, wchar_t const* const szFileName, int nCodeLine, wchar_t const* const _Format, ...);

public:
#ifdef _UNICODE
	void tvlogf(LOG_TYPE unLogType, wchar_t const* const szFileName, int nCodeLine, wchar_t const* const _Format, const va_list& vargs);
	void tlogf(LOG_TYPE unLogType, wchar_t const* const szFileName, int nCodeLine, wchar_t const* const _Format, ...);
#else
	void tvlogf(LOG_TYPE unLogType, char const* const szFileName, int nCodeLine, char const* const _Format, const va_list& vargs);
	void tlogf(LOG_TYPE unLogType, char const* const szFileName, int nCodeLine, char const* const _Format, ...);
#endif

public:
	Terminal::Client& GetClient();

private:
	Terminal::Client m_Client;
};

Log& GetLog();

#endif // !_LOG_H_
