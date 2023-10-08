#pragma once

#ifndef _TERMINAL_H_
#define _TERMINAL_H_

// General
#include <Windows.h>
#include <tchar.h>

// STL
#include <memory>

// ----------------------------------------------------------------
// General definitions
// ----------------------------------------------------------------

#ifndef TERMINAL_BUFFER_SIZE
#define TERMINAL_BUFFER_SIZE 8192
#endif

#ifndef TERMINAL_MESSAGE_DATA_SIZE
#define TERMINAL_MESSAGE_DATA_SIZE TERMINAL_BUFFER_SIZE
#endif

// ----------------------------------------------------------------
// Terminal
// ----------------------------------------------------------------

namespace Terminal {

	// ----------------------------------------------------------------
	// Window
	// ----------------------------------------------------------------

	typedef struct _WINDOW_NATIVE_IO {
		HANDLE m_hIN;
		HANDLE m_hOUT;
	} WINDOW_NATIVE_IO, * PWINDOW_NATIVE_IO;

	typedef struct _WINDOW_IO {
		FILE* m_pIN;
		FILE* m_pOUT;
	} WINDOW_IO, * PWINDOW_IO;

	typedef struct _WINDOW_DATA {
		DWORD m_unMode;
		LONG m_nStyle;
		LONG m_nStyleEx;
	} WINDOW_DATA, * PWINDOW_DATA;

	class Window {
	public:
		Window(const bool bAutoClose = false);
		~Window();

	public:
		bool Open(const bool bUpdateIO = false);
		bool Close();
		bool Show();
		bool Hide();

	public:
		HWND GetWindow() const;
		bool GetNativeIO(PWINDOW_NATIVE_IO const pNativeIO);
		bool GetIO(PWINDOW_IO const pIO);

	private:
		const bool m_bAutoClose;
		HWND m_hWindow;
		WINDOW_NATIVE_IO m_NativeIO;
		WINDOW_IO m_IO;
		WINDOW_DATA m_Data;
	};

	// ----------------------------------------------------------------
	// Screen
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
		COLOR_AUTO = 0xFF
	} COLOR, * PCOLOR;

	typedef struct _COLOR_PAIR {
	public:
		_COLOR_PAIR() {
			m_unBackground = COLOR::COLOR_AUTO;
			m_unForeground = COLOR::COLOR_AUTO;
		}

		_COLOR_PAIR(COLOR unBackground, COLOR unForeground) {
			m_unBackground = unBackground;
			m_unForeground = unForeground;
		}

		_COLOR_PAIR(COLOR unForeground) {
			m_unBackground = COLOR::COLOR_AUTO;
			m_unForeground = unForeground;
		}

	public:
		COLOR m_unBackground;
		COLOR m_unForeground;
	} COLOR_PAIR, * PCOLOR_PAIR;

	class Screen {
	public:
		Screen(Window* const pWindow, const bool bAutoRestore = false);
		~Screen();

	public:
		bool ReadA(char* const szBuffer, const unsigned int unLength);
		bool ReadW(wchar_t* const szBuffer, const unsigned int unLength);
#ifdef _UNICODE
		bool Read(wchar_t* const szBuffer, const unsigned int unLength);
#else
		bool Read(char* const szBuffer, const unsigned int unLength);
#endif
		bool WriteA(char const* const szBuffer);
		bool WriteW(wchar_t const* const szBuffer);
#ifdef _UNICODE
		bool Write(wchar_t const* const szBuffer);
#else
		bool Write(char const* const szBuffer);
#endif

	public:
		bool PauseA(char const* szPromt = nullptr);
		bool PauseW(wchar_t const* szPromt = nullptr);
#ifdef _UNICODE
		bool Pause(wchar_t const* szPromt = nullptr);
#else
		bool Pause(char const* szPromt = nullptr);
#endif

	public:
		bool GetBufferInfo(PCONSOLE_SCREEN_BUFFER_INFOEX const pBufferInfoEx);
		bool SetBufferInfo(CONSOLE_SCREEN_BUFFER_INFOEX& BufferInfoEx);

	public:
		bool GetAttributes(PWORD const pAttributes);
		bool SetAttributes(const WORD& unAttributes);

	public:
		bool ChangeColorPalette(const COLOR& Color, const unsigned int unRGB);
		bool ChangeColorPalette(const COLOR& Color, const unsigned char unR, const unsigned char unG, const unsigned char unB);
		bool Flush(const bool bClearAll = false, const bool bUpdateOriginalColorPair = false, const bool bResetPreviousColorPair = false);

	public:
		bool GetColor(PCOLOR_PAIR const pColorPair);
		bool SetColor(const COLOR_PAIR& ColorPair);
		bool RestoreColor(const bool bRestorePrevious = false);

	public:
		bool GetCursorColor(PCOLOR_PAIR const pColorPair);
		bool SetCursorColor(const COLOR_PAIR& ColorPair);
		bool RestoreCursorColor(const bool bRestorePrevious = false);

	public:
		bool GetCursorInfo(PCONSOLE_CURSOR_INFO const pCursorInfo);
		bool SetCursorInfo(const CONSOLE_CURSOR_INFO& CursorInfo);

	public:
		bool ShowCursor();
		bool HideCursor();
		bool ToggleCursor();

	public:
		bool GetCursorPosition(PCOORD const pCursorPosition);
		bool SetCursorPosition(const COORD& CursorPosition);

	public:
		bool Erase(const COORD& CursorPosition, const unsigned int unLength);

	public:
		Window* const GetWindow() const;

	private:
		const bool m_bAutoRestore;
		Window* const m_pWindow;
		COLOR_PAIR m_OriginalColorPair;
		COLOR_PAIR m_OriginalCursorColorPair;
		COLOR_PAIR m_PreviousColorPair;
		COLOR_PAIR m_PreviousCursorColorPair;
		COLORREF m_OriginalColorTable[16];
	};

	// ----------------------------------------------------------------
	// Console
	// ----------------------------------------------------------------

	class Console {
	public:
		Console(Screen* const pScreen);

	public:
		int vprintf(const COLOR_PAIR& ColorPair, char const* const _Format, const va_list& vargs);
		int vprintf(const COLOR& unForegroundColor, char const* const _Format, const va_list& vargs);
		int printf(const COLOR_PAIR& ColorPair, char const* const _Format, ...);
		int printf(const COLOR& unForegroundColor, char const* const _Format, ...);

	public:
		int vwprintf(const COLOR_PAIR& ColorPair, wchar_t const* const _Format, const va_list& vargs);
		int vwprintf(const COLOR& unForegroundColor, wchar_t const* const _Format, const va_list& vargs);
		int wprintf(const COLOR_PAIR& ColorPair, wchar_t const* const _Format, ...);
		int wprintf(const COLOR& unForegroundColor, wchar_t const* const _Format, ...);

	public:
#ifdef _UNICODE
		int tvprintf(const COLOR_PAIR& ColorPair, wchar_t const* const _Format, const va_list& vargs);
		int tvprintf(const COLOR& unForegroundColor, wchar_t const* const _Format, const va_list& vargs);
		int tprintf(const COLOR_PAIR& ColorPair, wchar_t const* const _Format, ...);
		int tprintf(const COLOR& unForegroundColor, wchar_t const* const _Format, ...);
#else
		int tvprintf(const COLOR_PAIR& ColorPair, char const* const _Format, const va_list& vargs);
		int tvprintf(const COLOR& unForegroundColor, char const* const _Format, const va_list& vargs);
		int tprintf(const COLOR_PAIR& ColorPair, char const* const _Format, ...);
		int tprintf(const COLOR& unForegroundColor, char const* const _Format, ...);
#endif

	public:
		int vscanf(const COLOR_PAIR& ColorPair, char const* const _Format, const va_list& vargs);
		int vscanf(const COLOR& unForegroundColor, char const* const _Format, const va_list& vargs);
		int scanf(const COLOR_PAIR& ColorPair, char const* const _Format, ...);
		int scanf(const COLOR& unForegroundColor, char const* const _Format, ...);

	public:
		int vwscanf(const COLOR_PAIR& ColorPair, wchar_t const* const _Format, const va_list& vargs);
		int vwscanf(const COLOR& unForegroundColor, wchar_t const* const _Format, const va_list& vargs);
		int wscanf(const COLOR_PAIR& ColorPair, wchar_t const* const _Format, ...);
		int wscanf(const COLOR& unForegroundColor, wchar_t const* const _Format, ...);

	public:
#ifdef _UNICODE
		int tvscanf(const COLOR_PAIR& ColorPair, wchar_t const* const _Format, const va_list& vargs);
		int tvscanf(const COLOR& unForegroundColor, wchar_t const* const _Format, const va_list& vargs);
		int tscanf(const COLOR_PAIR& ColorPair, wchar_t const* const _Format, ...);
		int tscanf(const COLOR& unForegroundColor, wchar_t const* const _Format, ...);
#else
		int tvscanf(const COLOR_PAIR& ColorPair, char const* const _Format, const va_list& vargs);
		int tvscanf(const COLOR& unForegroundColor, char const* const _Format, const va_list& vargs);
		int tscanf(const COLOR_PAIR& ColorPair, char const* const _Format, ...);
		int tscanf(const COLOR& unForegroundColor, char const* const _Format, ...);
#endif

	public:
		Screen* const GetScreen() const;

	private:
		Screen* const m_pScreen;
	};

	// ----------------------------------------------------------------
	// Terminal Message
	// ----------------------------------------------------------------

	typedef enum class _TERMINAL_MESSAGE_ACTION : unsigned int {
		// PIPE
		ACTION_NONE = 0,
		ACTION_OPEN,
		ACTION_SUCCESS,
		ACTION_CLOSE,
		// SCREEN
		ACTION_READA,
		ACTION_READW,
		ACTION_WRITEA,
		ACTION_WRITEW,
		ACTION_PAUSEA,
		ACTION_PAUSEW,
		ACTION_GETBUFFERINFO,
		ACTION_SETBUFFERINFO,
		ACTION_SETATTRIBUTES,
		ACTION_FLUSH,
		ACTION_SETCOLOR,
		ACTION_RESTORECOLOR,
		ACTION_SETCURSORCOLOR,
		ACTION_RESTORECURSORCOLOR,
		ACTION_GETCURSORINFO,
		ACTION_SETCURSORINFO,
		ACTION_SETCURSORPOSITION,
		ACTION_ERASE
	} TERMINAL_MESSAGE_ACTION, * PTERMINAL_MESSAGE_ACTION;

	class TerminalMessage {
	public:
		TerminalMessage();
		~TerminalMessage() = default;

	public:
		TERMINAL_MESSAGE_ACTION GetAction() const;
		void SetAction(TERMINAL_MESSAGE_ACTION unAction);

	public:
		unsigned char* GetData();

	public:
		void ReadData(void* pBuffer, unsigned int unSize);
		void WriteData(void* pBuffer, unsigned int unSize);

	private:
		TERMINAL_MESSAGE_ACTION m_unAction;
		unsigned char m_pData[TERMINAL_MESSAGE_DATA_SIZE];
	};

	// ----------------------------------------------------------------
	// Server
	// ----------------------------------------------------------------

	class Server {
	public:
		Server(Screen* const pScreen);
		~Server();

	public:
		bool Open();
		bool Close();
		bool Launch();

	private:
		bool Send(const std::unique_ptr<TerminalMessage>& ptrMessage);
		bool Receive(const std::unique_ptr<TerminalMessage>& ptrMessage);
		bool Process(const std::unique_ptr<TerminalMessage>& ptrMessage);

	public:
		Screen* const GetScreen() const;
		bool GetSessionName(TCHAR szSessionName[64]);
		const HANDLE GetPipe() const;

	private:
		Screen* const m_pScreen;
		TCHAR m_szSessionName[64];
		HANDLE m_hPipe;
	};

	// ----------------------------------------------------------------
	// Client
	// ----------------------------------------------------------------

	class Client {
	public:
		Client();
		~Client();

	public:
		bool Open(TCHAR szSessionName[64]);
		bool Close();

	public:
		bool ReadA(char* const szBuffer, const unsigned int unLength);
		bool ReadW(wchar_t* const szBuffer, const unsigned int unLength);
#ifdef _UNICODE
		bool Read(wchar_t* const szBuffer, const unsigned int unLength);
#else
		bool Read(char* const szBuffer, const unsigned int unLength);
#endif
		bool WriteA(char const* const szBuffer);
		bool WriteW(wchar_t const* const szBuffer);
#ifdef _UNICODE
		bool Write(wchar_t const* const szBuffer);
#else
		bool Write(char const* const szBuffer);
#endif

	public:
		bool PauseA(char const* szPromt = nullptr);
		bool PauseW(wchar_t const* szPromt = nullptr);
#ifdef _UNICODE
		bool Pause(wchar_t const* szPromt = nullptr);
#else
		bool Pause(char const* szPromt = nullptr);
#endif

	public:
		bool GetBufferInfo(PCONSOLE_SCREEN_BUFFER_INFOEX const pBufferInfoEx);
		bool SetBufferInfo(CONSOLE_SCREEN_BUFFER_INFOEX& BufferInfoEx);

	public:
		bool GetAttributes(PWORD const pAttributes);
		bool SetAttributes(const WORD& unAttributes);

	public:
		bool ChangeColorPalette(const COLOR& Color, const unsigned int unRGB);
		bool ChangeColorPalette(const COLOR& Color, const unsigned char unR, const unsigned char unG, const unsigned char unB);
		bool Flush(const bool bClearAll = false, const bool bUpdateOriginalColorPair = false, const bool bResetPreviousColorPair = false);

	public:
		bool GetColor(PCOLOR_PAIR const pColorPair);
		bool SetColor(const COLOR_PAIR& ColorPair);
		bool RestoreColor(const bool bRestorePrevious = false);

	public:
		bool GetCursorColor(PCOLOR_PAIR const pColorPair);
		bool SetCursorColor(const COLOR_PAIR& ColorPair);
		bool RestoreCursorColor(const bool bRestorePrevious = false);

	public:
		bool GetCursorInfo(PCONSOLE_CURSOR_INFO const pCursorInfo);
		bool SetCursorInfo(const CONSOLE_CURSOR_INFO& CursorInfo);

	public:
		bool ShowCursor();
		bool HideCursor();
		bool ToggleCursor();

	public:
		bool GetCursorPosition(PCOORD const pCursorPosition);
		bool SetCursorPosition(const COORD& CursorPosition);

	public:
		bool Erase(const COORD& CursorPosition, const unsigned int unLength);

	public:
		int vprintf(const COLOR_PAIR& ColorPair, char const* const _Format, const va_list& vargs);
		int vprintf(const COLOR& unForegroundColor, char const* const _Format, const va_list& vargs);
		int printf(const COLOR_PAIR& ColorPair, char const* const _Format, ...);
		int printf(const COLOR& unForegroundColor, char const* const _Format, ...);

	public:
		int vwprintf(const COLOR_PAIR& ColorPair, wchar_t const* const _Format, const va_list& vargs);
		int vwprintf(const COLOR& unForegroundColor, wchar_t const* const _Format, const va_list& vargs);
		int wprintf(const COLOR_PAIR& ColorPair, wchar_t const* const _Format, ...);
		int wprintf(const COLOR& unForegroundColor, wchar_t const* const _Format, ...);

	public:
#ifdef _UNICODE
		int tvprintf(const COLOR_PAIR& ColorPair, wchar_t const* const _Format, const va_list& vargs);
		int tvprintf(const COLOR& unForegroundColor, wchar_t const* const _Format, const va_list& vargs);
		int tprintf(const COLOR_PAIR& ColorPair, wchar_t const* const _Format, ...);
		int tprintf(const COLOR& unForegroundColor, wchar_t const* const _Format, ...);
#else
		int tvprintf(const COLOR_PAIR& ColorPair, char const* const _Format, const va_list& vargs);
		int tvprintf(const COLOR& unForegroundColor, char const* const _Format, const va_list& vargs);
		int tprintf(const COLOR_PAIR& ColorPair, char const* const _Format, ...);
		int tprintf(const COLOR& unForegroundColor, char const* const _Format, ...);
#endif

	public:
		int vscanf(const COLOR_PAIR& ColorPair, char const* const _Format, const va_list& vargs);
		int vscanf(const COLOR& unForegroundColor, char const* const _Format, const va_list& vargs);
		int scanf(const COLOR_PAIR& ColorPair, char const* const _Format, ...);
		int scanf(const COLOR& unForegroundColor, char const* const _Format, ...);

	public:
		int vwscanf(const COLOR_PAIR& ColorPair, wchar_t const* const _Format, const va_list& vargs);
		int vwscanf(const COLOR& unForegroundColor, wchar_t const* const _Format, const va_list& vargs);
		int wscanf(const COLOR_PAIR& ColorPair, wchar_t const* const _Format, ...);
		int wscanf(const COLOR& unForegroundColor, wchar_t const* const _Format, ...);

	public:
#ifdef _UNICODE
		int tvscanf(const COLOR_PAIR& ColorPair, wchar_t const* const _Format, const va_list& vargs);
		int tvscanf(const COLOR& unForegroundColor, wchar_t const* const _Format, const va_list& vargs);
		int tscanf(const COLOR_PAIR& ColorPair, wchar_t const* const _Format, ...);
		int tscanf(const COLOR& unForegroundColor, wchar_t const* const _Format, ...);
#else
		int tvscanf(const COLOR_PAIR& ColorPair, char const* const _Format, const va_list& vargs);
		int tvscanf(const COLOR& unForegroundColor, char const* const _Format, const va_list& vargs);
		int tscanf(const COLOR_PAIR& ColorPair, char const* const _Format, ...);
		int tscanf(const COLOR& unForegroundColor, char const* const _Format, ...);
#endif

	private:
		bool Send(const std::unique_ptr<TerminalMessage>& ptrMessage);
		bool Receive(const std::unique_ptr<TerminalMessage>& ptrMessage);

	public:
		bool GetSessionName(TCHAR szSessionName[64]);
		const HANDLE GetPipe() const;

	private:
		TCHAR m_szSessionName[64];
		HANDLE m_hPipe;
	};
}

#endif // !_TERMINAL_H_
