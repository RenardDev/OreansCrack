#pragma once

#ifndef _CONSOLEUTILS_H_
#define _CONSOLEUTILS_H_

// Default
#include <Windows.h>
#include <tchar.h>

// C
#include <io.h>
#include <fcntl.h>

// C++
#include <clocale>
#include <cstdio>
#include <cmath>

// STL
#include <vector>

// ----------------------------------------------------------------
// ConsoleUtils
// ----------------------------------------------------------------
namespace ConsoleUtils {
	// ----------------------------------------------------------------
	// PipeServer
	// ----------------------------------------------------------------

	class PipeServer {
	public:
		PipeServer(const DWORD unBufferSize);
		~PipeServer();

	public:
		bool Listen();
		bool Read(void* const pBuffer);
		bool Write(void* const pBuffer);

	public:
		bool GetSessionName(TCHAR szSessionName[64]);
		HANDLE GetPipe();

	private:
		const DWORD m_unBufferSize;
		TCHAR m_szSessionName[64];
		HANDLE m_hPipe;
	};

	// ----------------------------------------------------------------
	// PipeClient
	// ----------------------------------------------------------------

	class PipeClient {
	public:
		PipeClient(const DWORD unBufferSize, TCHAR szSessionName[64]);
		~PipeClient();

	public:
		bool Read(void* const pBuffer);
		bool Write(void* const pBuffer);

	public:
		HANDLE GetPipe();

	private:
		const DWORD m_unBufferSize;
		HANDLE m_hPipe;
	};

	// ----------------------------------------------------------------
	// Console
	// ----------------------------------------------------------------

	class Console {
	public:
		Console(bool bAutoClose = false);
		~Console();
	public:
		// Control
		bool Open(bool bUpdateIO = false);
		bool Close();
		bool Show();
		bool Hide();
	public:
		// IO
		bool ReadA(char* const szBuffer, unsigned int unCount);
		bool ReadW(wchar_t* const szBuffer, unsigned int unCount);
#ifdef UNICODE
		bool Read(wchar_t* const szBuffer, unsigned int unCount);
#else
		bool Read(char* const szBuffer, unsigned int unCount);
#endif
		bool WriteA(char const* const szBuffer);
		bool WriteW(wchar_t const* const szBuffer);
#ifdef UNICODE
		bool Write(wchar_t const* const szBuffer);
#else
		bool Write(char const* const szBuffer);
#endif
	public:
		// Properties
		HWND GetWindow();
		HANDLE GetIn();
		HANDLE GetOut();
	private:
		bool m_bAutoClose;
		HWND m_hWindow;
		FILE* m_pIn;
		FILE* m_pOut;
		HANDLE m_hIn;
		HANDLE m_hOut;
		DWORD m_unOriginalMode;
		LONG m_nOriginalStyle;
		LONG m_nOriginalStyleEx;
	};

	// ----------------------------------------------------------------
	// Colors
	// ----------------------------------------------------------------

	typedef enum class _COLOR : unsigned char {
		COLOR_BLACK = 0,
		COLOR_DARK_BLUE = FOREGROUND_BLUE,
		COLOR_DARK_GREEN = FOREGROUND_GREEN,
		COLOR_DARK_CYAN = FOREGROUND_GREEN | FOREGROUND_BLUE,
		COLOR_DARK_RED = FOREGROUND_RED,
		COLOR_DARK_MAGENTA = FOREGROUND_RED | FOREGROUND_BLUE,
		COLOR_DARK_YELLOW = FOREGROUND_RED | FOREGROUND_GREEN,
		COLOR_DARK_GRAY = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE,
		COLOR_GRAY = FOREGROUND_INTENSITY,
		COLOR_BLUE = FOREGROUND_INTENSITY | FOREGROUND_BLUE,
		COLOR_GREEN = FOREGROUND_INTENSITY | FOREGROUND_GREEN,
		COLOR_CYAN = FOREGROUND_INTENSITY | FOREGROUND_GREEN | FOREGROUND_BLUE,
		COLOR_RED = FOREGROUND_INTENSITY | FOREGROUND_RED,
		COLOR_MAGENTA = FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_BLUE,
		COLOR_YELLOW = FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN,
		COLOR_WHITE = FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE,
		COLOR_UNKNOWN = 0xFF
	} COLOR, *PCOLOR;

	typedef struct _COLOR_PAIR {
	public:
		_COLOR_PAIR() {
			m_unColorBackground = COLOR::COLOR_UNKNOWN;
			m_unColorForeground = COLOR::COLOR_UNKNOWN;
		}

		_COLOR_PAIR(COLOR unColorBackground, COLOR unColorForeground) {
			m_unColorBackground = unColorBackground;
			m_unColorForeground = unColorForeground;
		}

		_COLOR_PAIR(COLOR unColorForeground) {
			m_unColorBackground = COLOR::COLOR_UNKNOWN;
			m_unColorForeground = unColorForeground;
		}

	public:
		COLOR m_unColorBackground;
		COLOR m_unColorForeground;
	} COLOR_PAIR, *PCOLOR_PAIR;

	// ----------------------------------------------------------------
	// Terminal
	// ----------------------------------------------------------------

	class Terminal : public Console {
	public:
		Terminal(bool bAutoClose = false, bool bAutoRestoreColors = false);
		~Terminal();
	public:
		// Control
		bool Open(bool bUpdateIO = false);
		bool Close();
	public:
		// Buffer
		bool GetBufferInfo(PCONSOLE_SCREEN_BUFFER_INFOEX pBufferInfoEx);
		bool SetBufferInfo(CONSOLE_SCREEN_BUFFER_INFOEX BufferInfoEx);
		bool GetAttributes(PWORD pAttributes);
		bool SetAttributes(WORD unAttributes);
		bool ChangeColorPalette(COLOR Color, unsigned int unRGB);
		bool ChangeColorPalette(COLOR Color, unsigned char unR, unsigned char unG, unsigned char unB);
		// Screen
		bool Flush(bool bClear = false, bool bUpdateOriginalColorPair = false, bool bResetPreviousColorPair = false);
		bool GetColor(PCOLOR_PAIR pColorPair);
		bool SetColor(COLOR_PAIR ColorPair);
		bool RestoreColor(bool bRestorePrevious = false);
		// Cursor
		bool GetCursorInfo(PCONSOLE_CURSOR_INFO pCursorInfo);
		bool SetCursorInfo(CONSOLE_CURSOR_INFO CursorInfo);
		bool GetCursorPosition(PCOORD pCursorPosition);
		bool SetCursorPosition(COORD CursorPosition);
		bool ShowCursor();
		bool HideCursor();
		bool ToggleCursor();
		bool GetCursorColor(PCOLOR_PAIR pColorPair);
		bool SetCursorColor(COLOR_PAIR ColorPair);
		bool RestoreCursorColor(bool bRestorePrevious = false);
		// Advanced
		bool Erase(COORD CursorPosition, unsigned int unLength);
	private:
		bool m_bAutoRestoreColors;
		COLOR_PAIR m_OriginalColorPair;
		COLOR_PAIR m_OriginalCursorColorPair;
		COLOR_PAIR m_PreviousColorPair;
		COLOR_PAIR m_PreviousCursorColorPair;
		COLORREF m_OriginalColorTable[16];
	};

	// ----------------------------------------------------------------
	// print/scan with format and color support
	// ----------------------------------------------------------------

	int clrvprintf(COLOR_PAIR ColorPair, char const* const _Format, va_list vargs);
	int clrvprintf(COLOR unForegroundColor, char const* const _Format, va_list vargs);
	int clrprintf(COLOR_PAIR ColorPair, char const* const _Format, ...);
	int clrprintf(COLOR unForegroundColor, char const* const _Format, ...);

	int clrvwprintf(COLOR_PAIR ColorPair, wchar_t const* const _Format, va_list vargs);
	int clrvwprintf(COLOR unForegroundColor, wchar_t const* const _Format, va_list vargs);
	int clrwprintf(COLOR_PAIR ColorPair, wchar_t const* const _Format, ...);
	int clrwprintf(COLOR unForegroundColor, wchar_t const* const _Format, ...);

#ifdef UNICODE
	int tclrvprintf(COLOR_PAIR ColorPair, wchar_t const* const _Format, va_list vargs);
	int tclrvprintf(COLOR unForegroundColor, wchar_t const* const _Format, va_list vargs);
	int tclrprintf(COLOR_PAIR ColorPair, wchar_t const* const _Format, ...);
	int tclrprintf(COLOR unForegroundColor, wchar_t const* const _Format, ...);
#else
	int tclrvprintf(COLOR_PAIR ColorPair, char const* const _Format, va_list vargs);
	int tclrvprintf(COLOR unForegroundColor, char const* const _Format, va_list vargs);
	int tclrprintf(COLOR_PAIR ColorPair, char const* const _Format, ...);
	int tclrprintf(COLOR unForegroundColor, char const* const _Format, ...);
#endif

	int clrvscanf(COLOR_PAIR ColorPair, char const* const _Format, va_list vargs);
	int clrvscanf(COLOR unForegroundColor, char const* const _Format, va_list vargs);
	int clrscanf(COLOR_PAIR ColorPair, char const* const _Format, ...);
	int clrscanf(COLOR unForegroundColor, char const* const _Format, ...);

	int clrvwscanf(COLOR_PAIR ColorPair, wchar_t const* const _Format, va_list vargs);
	int clrvwscanf(COLOR unForegroundColor, wchar_t const* const _Format, va_list vargs);
	int clrwscanf(COLOR_PAIR ColorPair, wchar_t const* const _Format, ...);
	int clrwscanf(COLOR unForegroundColor, wchar_t const* const _Format, ...);

#ifdef UNICODE
	int tclrvscanf(COLOR_PAIR ColorPair, wchar_t const* const _Format, va_list vargs);
	int tclrvscanf(COLOR unForegroundColor, wchar_t const* const _Format, va_list vargs);
	int tclrscanf(COLOR_PAIR ColorPair, wchar_t const* const _Format, ...);
	int tclrscanf(COLOR unForegroundColor, wchar_t const* const _Format, ...);
#else
	int tclrvscanf(COLOR_PAIR ColorPair, char const* const _Format, va_list vargs);
	int tclrvscanf(COLOR unForegroundColor, char const* const _Format, va_list vargs);
	int tclrscanf(COLOR_PAIR ColorPair, char const* const _Format, ...);
	int tclrscanf(COLOR unForegroundColor, char const* const _Format, ...);
#endif
}

#endif // !_CONSOLEUTILS_H_
