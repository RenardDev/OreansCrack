#include "Terminal.h"

// C
#include <io.h>
#include <fcntl.h>
#include <conio.h>

// C++
#include <clocale>
#include <cstdio>

// ----------------------------------------------------------------
// Terminal
// ----------------------------------------------------------------

namespace Terminal {

	// ----------------------------------------------------------------
	// Window
	// ----------------------------------------------------------------

	Window::Window(const bool bAutoClose) : m_bAutoClose(bAutoClose) {
		m_hWindow = GetConsoleWindow();
		m_NativeIO.m_hIN = GetStdHandle(STD_INPUT_HANDLE);
		m_NativeIO.m_hOUT = GetStdHandle(STD_OUTPUT_HANDLE);
		memset(&m_IO, 0, sizeof(m_IO));
		memset(&m_Data, 0, sizeof(m_Data));

		if (m_hWindow) {
			_tsetlocale(LC_ALL, _T(""));

			if (m_NativeIO.m_hIN && (m_NativeIO.m_hIN != INVALID_HANDLE_VALUE)) {
				if (GetConsoleMode(m_NativeIO.m_hIN, &m_Data.m_unMode)) {
					SetConsoleMode(m_NativeIO.m_hIN, m_Data.m_unMode | ENABLE_INSERT_MODE);
				}
			}

			const LONG nStyle = GetWindowLong(m_hWindow, GWL_STYLE);
			if (nStyle != 0) {
				m_Data.m_nStyle = nStyle;
				SetWindowLong(m_hWindow, GWL_STYLE, nStyle & ~(WS_MAXIMIZEBOX | WS_MINIMIZEBOX));
			}

			const LONG nStyleEx = GetWindowLong(m_hWindow, GWL_EXSTYLE);
			if (nStyleEx != 0) {
				m_Data.m_nStyleEx = nStyleEx;
				SetWindowLong(m_hWindow, GWL_EXSTYLE, nStyleEx | WS_EX_LAYERED);
			}

			SetWindowPos(m_hWindow, nullptr, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER | SWP_FRAMECHANGED | SWP_NOOWNERZORDER);
		}
	}

	Window::~Window() {
		if (m_bAutoClose) {
			Close();
		}
	}

	bool Window::Open(const bool bUpdateIO) {
		if (m_hWindow) {
			return true;
		}

		if (m_IO.m_pIN) {
			if (_tfreopen_s(&m_IO.m_pIN, _T("nul"), _T("r"), stdin)) {
				return false;
			}

			if (m_IO.m_pIN) {
				fclose(m_IO.m_pIN);
				m_IO.m_pIN = nullptr;
			}
		}

		if (m_IO.m_pOUT) {
			if (_tfreopen_s(&m_IO.m_pOUT, _T("nul"), _T("w"), stdout)) {
				return false;
			}

			if (m_IO.m_pOUT) {
				fclose(m_IO.m_pOUT);
				m_IO.m_pOUT = nullptr;
			}
		}

		if (!AllocConsole()) {
			return false;
		}

		m_hWindow = GetConsoleWindow();
		if (!m_hWindow) {
			return false;
		}

		if (bUpdateIO) {
			if (_tfreopen_s(&m_IO.m_pIN, _T("nul"), _T("r"), stdin)) {
				return false;
			}

			if (_tfreopen_s(&m_IO.m_pOUT, _T("nul"), _T("w"), stdout)) {
				return false;
			}
		}

		const auto& hIN = GetStdHandle(STD_INPUT_HANDLE);
		if (!hIN || (hIN == INVALID_HANDLE_VALUE)) {
			return false;
		}

		m_NativeIO.m_hIN = hIN;

		if (bUpdateIO) {
			const int nInDescriptor = _open_osfhandle(reinterpret_cast<intptr_t>(hIN), _O_TEXT);
			if (nInDescriptor == -1) {
				return false;
			}

			const auto& pIN = _tfdopen(nInDescriptor, _T("r"));
			if (!pIN) {
				return false;
			}

			m_IO.m_pIN = pIN;

			if (_dup2(_fileno(pIN), _fileno(stdin)) != 0) {
				return false;
			}

			if (setvbuf(stdin, nullptr, _IONBF, 0) != 0) {
				return false;
			}
		}

		const auto& hOUT = GetStdHandle(STD_OUTPUT_HANDLE);
		if (!hOUT || (hOUT == INVALID_HANDLE_VALUE)) {
			return false;
		}

		m_NativeIO.m_hOUT = hOUT;

		if (bUpdateIO) {
			const int nOutDescriptor = _open_osfhandle(reinterpret_cast<intptr_t>(hOUT), _O_TEXT);
			if (nOutDescriptor == -1) {
				return false;
			}

			const auto& pOUT = _tfdopen(nOutDescriptor, _T("w"));
			if (!pOUT) {
				return false;
			}

			m_IO.m_pOUT = pOUT;

			if (_dup2(_fileno(pOUT), _fileno(stdout)) != 0) {
				return false;
			}

			if (setvbuf(stdout, nullptr, _IONBF, 0) != 0) {
				return false;
			}
		}

		_tsetlocale(LC_ALL, _T(""));

		if (m_NativeIO.m_hIN && (m_NativeIO.m_hIN != INVALID_HANDLE_VALUE)) {
			if (GetConsoleMode(m_NativeIO.m_hIN, &m_Data.m_unMode)) {
				SetConsoleMode(m_NativeIO.m_hIN, m_Data.m_unMode | ENABLE_INSERT_MODE);
			}
		}

		const LONG nStyle = GetWindowLong(m_hWindow, GWL_STYLE);
		if (nStyle != 0) {
			m_Data.m_nStyle = nStyle;
			SetWindowLong(m_hWindow, GWL_STYLE, nStyle & ~(WS_MAXIMIZEBOX | WS_MINIMIZEBOX));
		}

		const LONG nStyleEx = GetWindowLong(m_hWindow, GWL_EXSTYLE);
		if (nStyleEx != 0) {
			m_Data.m_nStyleEx = nStyleEx;
			SetWindowLong(m_hWindow, GWL_EXSTYLE, nStyleEx | WS_EX_LAYERED);
		}

		SetWindowPos(m_hWindow, nullptr, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER | SWP_FRAMECHANGED | SWP_NOOWNERZORDER);

		return true;
	}

	bool Window::Close() {
		if (!m_hWindow) {
			return false;
		}

		if (m_Data.m_nStyleEx != 0) {
			SetWindowLong(m_hWindow, GWL_EXSTYLE, m_Data.m_nStyleEx);
		}

		if (m_Data.m_nStyle != 0) {
			SetWindowLong(m_hWindow, GWL_STYLE, m_Data.m_nStyle);
		}

		if (m_NativeIO.m_hIN && (m_NativeIO.m_hIN != INVALID_HANDLE_VALUE) && m_Data.m_unMode) {
			SetConsoleMode(m_NativeIO.m_hIN, m_Data.m_unMode);
		}

		if (m_IO.m_pIN) {
			if (_tfreopen_s(&m_IO.m_pIN, _T("nul"), _T("r"), stdin)) {
				return false;
			}

			if (m_IO.m_pIN) {
				fclose(m_IO.m_pIN);
				m_IO.m_pIN = nullptr;
			}
		}

		if (m_IO.m_pOUT) {
			if (_tfreopen_s(&m_IO.m_pOUT, _T("nul"), _T("w"), stdout)) {
				return false;
			}

			if (m_IO.m_pOUT) {
				fclose(m_IO.m_pOUT);
				m_IO.m_pOUT = nullptr;
			}
		}

		if (!FreeConsole()) {
			return false;
		}

		if (!DestroyWindow(m_hWindow)) {
			return false;
		}

		m_hWindow = nullptr;

		return true;
	}

	bool Window::Show() {
		if (!m_hWindow) {
			return false;
		}

		if (!ShowWindow(m_hWindow, SW_SHOW)) {
			return false;
		}

		return true;
	}

	bool Window::Hide() {
		if (!m_hWindow) {
			return false;
		}

		if (!ShowWindow(m_hWindow, SW_HIDE)) {
			return false;
		}

		return true;
	}

	HWND Window::GetWindow() const {
		return m_hWindow;
	}

	bool Window::GetNativeIO(PWINDOW_NATIVE_IO const pNativeIO) {
		if (!pNativeIO) {
			return false;
		}

		*pNativeIO = m_NativeIO;

		return true;
	}

	bool Window::GetIO(PWINDOW_IO const pIO) {
		if (!pIO) {
			return false;
		}

		*pIO = m_IO;

		return true;
	}

	// ----------------------------------------------------------------
	// Screen
	// ----------------------------------------------------------------

	Screen::Screen(Window* const pWindow, const bool bAutoRestore) : m_bAutoRestore(bAutoRestore), m_pWindow(pWindow) {
		memset(&m_OriginalColorPair, 0, sizeof(m_OriginalColorPair));
		memset(&m_OriginalCursorColorPair, 0, sizeof(m_OriginalCursorColorPair));
		memset(&m_PreviousColorPair, 0, sizeof(m_PreviousColorPair));
		memset(&m_PreviousCursorColorPair, 0, sizeof(m_PreviousCursorColorPair));
		memset(&m_OriginalColorTable, 0, sizeof(m_OriginalColorTable));

		if (pWindow && bAutoRestore) {
			GetColor(&m_OriginalColorPair);
			GetCursorColor(&m_OriginalCursorColorPair);

			CONSOLE_SCREEN_BUFFER_INFOEX csbi;
			if (GetBufferInfo(&csbi)) {
				for (unsigned char i = 0; i < 16; ++i) {
					m_OriginalColorTable[i] = csbi.ColorTable[i];
				}
			}
		}
	}

	Screen::~Screen() {
		if (m_pWindow && m_bAutoRestore) {
			CONSOLE_SCREEN_BUFFER_INFOEX csbi;
			if (GetBufferInfo(&csbi)) {
				for (unsigned char i = 0; i < 16; ++i) {
					csbi.ColorTable[i] = m_OriginalColorTable[i];
				}

				SetBufferInfo(csbi);
			}

			SetColor(m_OriginalColorPair);
			SetCursorColor(m_OriginalCursorColorPair);
		}
	}

	bool Screen::ReadA(char* const szBuffer, const unsigned int unLength) {
		if (!szBuffer) {
			return false;
		}

		if (!unLength) {
			return false;
		}

		if (!m_pWindow) {
			return false;
		}

		if (!fgets(szBuffer, unLength, stdin)) {
			return false;
		}

		return true;
	}

	bool Screen::ReadW(wchar_t* const szBuffer, const unsigned int unLength) {
		if (!szBuffer) {
			return false;
		}

		if (!unLength) {
			return false;
		}

		if (!m_pWindow) {
			return false;
		}

		if (!fgetws(szBuffer, unLength, stdin)) {
			return false;
		}

		return true;
	}

#ifdef _UNICODE
	bool Screen::Read(wchar_t* const szBuffer, const unsigned int unLength) {
		return ReadW(szBuffer, unLength);
	}
#else
	bool Screen::Read(char* const szBuffer, const unsigned int unLength) {
		return ReadA(szBuffer, unLength);
	}
#endif

	bool Screen::WriteA(char const* const szBuffer) {
		if (!szBuffer) {
			return false;
		}

		if (!m_pWindow) {
			return false;
		}

		if (fputs(szBuffer, stdout) == EOF) {
			return false;
		}

		return true;
	}

	bool Screen::WriteW(wchar_t const* const szBuffer) {
		if (!szBuffer) {
			return false;
		}

		if (!m_pWindow) {
			return false;
		}

		if (fputws(szBuffer, stdout) == EOF) {
			return false;
		}

		return true;
	}

#ifdef _UNICODE
	bool Screen::Write(wchar_t const* const szBuffer) {
		return WriteW(szBuffer);
	}
#else
	bool Screen::Write(char const* const szBuffer) {
		return WriteA(szBuffer);
	}
#endif

	bool Screen::PauseA(char const* szPromt) {
		if (!szPromt) {
			szPromt = "Press any key to continue...";
		}

		if (!m_pWindow) {
			return false;
		}

		if (!WriteA(szPromt)) {
			return false;
		}

		if (!HideCursor()) {
			return false;
		}

		_CRT_UNUSED(_getch());

		if (!ShowCursor()) {
			return false;
		}

		return true;
	}

	bool Screen::PauseW(wchar_t const* szPromt) {
		if (!szPromt) {
			szPromt = L"Press any key to continue...";
		}

		if (!m_pWindow) {
			return false;
		}

		if (!WriteW(szPromt)) {
			return false;
		}

		if (!HideCursor()) {
			return false;
		}

		_CRT_UNUSED(_getch());

		if (!ShowCursor()) {
			return false;
		}

		return true;
	}

#ifdef _UNICODE
	bool Screen::Pause(wchar_t const* szPromt) {
		return PauseW(szPromt);
	}
#else
	bool Screen::Pause(char const* szPromt) {
		return PauseA(szPromt);
	}
#endif

	bool Screen::GetBufferInfo(PCONSOLE_SCREEN_BUFFER_INFOEX const pBufferInfo) {
		if (!pBufferInfo) {
			return false;
		}

		if (!m_pWindow) {
			return false;
		}

		WINDOW_NATIVE_IO IO;
		if (!m_pWindow->GetNativeIO(&IO)) {
			return false;
		}

		if (!IO.m_hOUT || (IO.m_hOUT == INVALID_HANDLE_VALUE)) {
			return false;
		}

		memset(pBufferInfo, 0, sizeof(CONSOLE_SCREEN_BUFFER_INFOEX));
		pBufferInfo->cbSize = sizeof(CONSOLE_SCREEN_BUFFER_INFOEX);

		if (!GetConsoleScreenBufferInfoEx(IO.m_hOUT, pBufferInfo)) {
			return false;
		}

		return true;
	}

	bool Screen::SetBufferInfo(CONSOLE_SCREEN_BUFFER_INFOEX& BufferInfo) {
		if (!m_pWindow) {
			return false;
		}

		WINDOW_NATIVE_IO IO;
		if (!m_pWindow->GetNativeIO(&IO)) {
			return false;
		}

		if (!IO.m_hOUT || (IO.m_hOUT == INVALID_HANDLE_VALUE)) {
			return false;
		}

		++BufferInfo.srWindow.Bottom;
		++BufferInfo.srWindow.Right;

		if (!SetConsoleScreenBufferInfoEx(IO.m_hOUT, &BufferInfo)) {
			return false;
		}

		--BufferInfo.srWindow.Bottom;
		--BufferInfo.srWindow.Right;

		return true;
	}

	bool Screen::GetAttributes(PWORD const pAttributes) {
		if (!pAttributes) {
			return false;
		}

		CONSOLE_SCREEN_BUFFER_INFOEX csbi;
		if (!GetBufferInfo(&csbi)) {
			return false;
		}

		*pAttributes = csbi.wAttributes;

		return true;
	}

	bool Screen::SetAttributes(const WORD& unAttributes) {
		if (!m_pWindow) {
			return false;
		}

		WINDOW_NATIVE_IO IO;
		if (!m_pWindow->GetNativeIO(&IO)) {
			return false;
		}

		if (!IO.m_hOUT || (IO.m_hOUT == INVALID_HANDLE_VALUE)) {
			return false;
		}

		if (!SetConsoleTextAttribute(IO.m_hOUT, unAttributes)) {
			return false;
		}

		return true;
	}

	bool Screen::ChangeColorPalette(const COLOR& Color, const unsigned int unRGB) {
		if (static_cast<unsigned char>(Color) > 15) {
			return false;
		}

		CONSOLE_SCREEN_BUFFER_INFOEX csbi;
		if (!GetBufferInfo(&csbi)) {
			return false;
		}

		const unsigned char unR = (unRGB >> 16) & 0xFF;
		const unsigned char unG = (unRGB >> 8) & 0xFF;
		const unsigned char unB = unRGB & 0xFF;

		csbi.ColorTable[static_cast<unsigned char>(Color)] = RGB(unR, unG, unB);

		if (!SetBufferInfo(csbi)) {
			return false;
		}

		return true;
	}

	bool Screen::ChangeColorPalette(const COLOR& Color, const unsigned char unR, const unsigned char unG, const unsigned char unB) {
		if (static_cast<unsigned char>(Color) > 15) {
			return false;
		}

		CONSOLE_SCREEN_BUFFER_INFOEX csbi;
		if (!GetBufferInfo(&csbi)) {
			return false;
		}

		csbi.ColorTable[static_cast<unsigned char>(Color)] = RGB(unR, unG, unB);

		if (!SetBufferInfo(csbi)) {
			return false;
		}

		return true;
	}

	bool Screen::Flush(const bool bClear, const bool bUpdateOriginalColorPair, const bool bResetPreviousColorPair) {
		CONSOLE_SCREEN_BUFFER_INFOEX csbi;
		if (!GetBufferInfo(&csbi)) {
			return false;
		}

		WINDOW_NATIVE_IO IO;
		if (!m_pWindow->GetNativeIO(&IO)) {
			return false;
		}

		if (!IO.m_hOUT || (IO.m_hOUT == INVALID_HANDLE_VALUE)) {
			return false;
		}

		if (bClear) {
			SMALL_RECT Scroll;
			memset(&Scroll, 0, sizeof(Scroll));

			Scroll.Left = 0;
			Scroll.Top = 0;
			Scroll.Right = csbi.dwSize.X;
			Scroll.Bottom = csbi.dwSize.Y;

			COORD ScrollTarget;
			memset(&ScrollTarget, 0, sizeof(ScrollTarget));

			ScrollTarget.X = 0;
			ScrollTarget.Y = -csbi.dwSize.Y;

			CHAR_INFO Fill;
			memset(&Fill, 0, sizeof(Fill));

#ifdef _UNICODE
			Fill.Char.UnicodeChar = L' ';
#else
			Fill.Char.AsciiChar = ' ';
#endif
			Fill.Attributes = csbi.wAttributes;

			if (!ScrollConsoleScreenBuffer(IO.m_hOUT, &Scroll, nullptr, ScrollTarget, &Fill)) {
				return false;
			}

			csbi.dwCursorPosition.X = 0;
			csbi.dwCursorPosition.Y = 0;

			if (!SetConsoleCursorPosition(IO.m_hOUT, csbi.dwCursorPosition)) {
				return false;
			}
		}

		COORD Coord;
		memset(&Coord, 0, sizeof(Coord));

		Coord.X = 0;
		Coord.Y = 0;

		DWORD unWrittenAttributes = 0;
		if (!FillConsoleOutputAttribute(IO.m_hOUT, csbi.wAttributes, csbi.dwSize.Y * csbi.dwSize.X, Coord, &unWrittenAttributes)) {
			return false;
		}

		if (bUpdateOriginalColorPair) {
			COLOR_PAIR CurrentColorPair;
			if (!GetColor(&CurrentColorPair)) {
				m_OriginalColorPair = CurrentColorPair;
			}
		}

		if (bResetPreviousColorPair) {
			m_PreviousColorPair = COLOR_PAIR();
		}

		return true;
	}

	bool Screen::GetColor(PCOLOR_PAIR const pColorPair) {
		if (!pColorPair) {
			return false;
		}

		WORD unAttributes = 0;
		if (!GetAttributes(&unAttributes)) {
			return false;
		}

		*pColorPair = COLOR_PAIR(static_cast<COLOR>((unAttributes & 0xF0) >> 4), static_cast<COLOR>(unAttributes & 0x0F));

		return true;
	}

	bool Screen::SetColor(const COLOR_PAIR& ColorPair) {
		if (!m_pWindow) {
			return false;
		}

		WINDOW_NATIVE_IO IO;
		if (!m_pWindow->GetNativeIO(&IO)) {
			return false;
		}

		if (!IO.m_hOUT || (IO.m_hOUT == INVALID_HANDLE_VALUE)) {
			return false;
		}

		WORD unAttributes = 0;
		if (!GetAttributes(&unAttributes)) {
			return false;
		}

		const COLOR_PAIR CurrentColorPair(static_cast<COLOR>((unAttributes & 0xF0) >> 4), static_cast<COLOR>(unAttributes & 0x0F));

		if (ColorPair.m_unBackground != COLOR::COLOR_AUTO) {
			unAttributes = static_cast<unsigned char>((static_cast<unsigned char>(ColorPair.m_unBackground) & 0x0F) << 4);
		}
		else {
			unAttributes = static_cast<unsigned char>(CurrentColorPair.m_unBackground);
		}

		if (ColorPair.m_unForeground != COLOR::COLOR_AUTO) {
			unAttributes |= static_cast<unsigned char>((static_cast<unsigned char>(ColorPair.m_unForeground) & 0x0F));
		}
		else {
			unAttributes |= static_cast<unsigned char>(CurrentColorPair.m_unForeground);
		}

		m_PreviousColorPair = CurrentColorPair;

		CONSOLE_SCREEN_BUFFER_INFOEX csbi;
		if (!GetBufferInfo(&csbi)) {
			return false;
		}

		COORD Coord;
		memset(&Coord, 0, sizeof(Coord));

		Coord.X = 0;
		Coord.Y = 0;

		DWORD unWrittenAttributes = 0;
		if (!FillConsoleOutputAttribute(IO.m_hOUT, unAttributes, csbi.dwSize.Y * csbi.dwSize.X, Coord, &unWrittenAttributes)) {
			return false;
		}

		return true;
	}

	bool Screen::RestoreColor(const bool bRestorePrevious) {
		if (bRestorePrevious) {
			return SetColor(m_PreviousColorPair);
		}

		return SetColor(m_OriginalColorPair);
	}

	bool Screen::GetCursorColor(PCOLOR_PAIR const pColorPair) {
		return GetColor(pColorPair);
	}

	bool Screen::SetCursorColor(const COLOR_PAIR& ColorPair) {
		WORD unAttributes = 0;
		if (!GetAttributes(&unAttributes)) {
			return false;
		}

		const COLOR_PAIR CurrentColorPair(static_cast<COLOR>((unAttributes & 0xF0) >> 4), static_cast<COLOR>(unAttributes & 0x0F));

		if (ColorPair.m_unBackground != COLOR::COLOR_AUTO) {
			unAttributes = static_cast<unsigned char>((static_cast<unsigned char>(ColorPair.m_unBackground) & 0x0F) << 4);
		}
		else {
			unAttributes = static_cast<unsigned char>(CurrentColorPair.m_unBackground);
		}

		if (ColorPair.m_unForeground != COLOR::COLOR_AUTO) {
			unAttributes |= static_cast<unsigned char>((static_cast<unsigned char>(ColorPair.m_unForeground) & 0x0F));
		}
		else {
			unAttributes |= static_cast<unsigned char>(CurrentColorPair.m_unForeground);
		}

		m_PreviousCursorColorPair = CurrentColorPair;

		if (!SetAttributes(unAttributes)) {
			return false;
		}

		return true;
	}

	bool Screen::RestoreCursorColor(const bool bRestorePrevious) {
		if (bRestorePrevious) {
			return SetCursorColor(m_PreviousCursorColorPair);
		}

		return SetCursorColor(m_OriginalCursorColorPair);
	}

	bool Screen::GetCursorInfo(PCONSOLE_CURSOR_INFO const pCursorInfo) {
		if (!pCursorInfo) {
			return false;
		}

		if (!m_pWindow) {
			return false;
		}

		WINDOW_NATIVE_IO IO;
		if (!m_pWindow->GetNativeIO(&IO)) {
			return false;
		}

		if (!IO.m_hOUT || (IO.m_hOUT == INVALID_HANDLE_VALUE)) {
			return false;
		}

		memset(pCursorInfo, 0, sizeof(CONSOLE_CURSOR_INFO));

		if (!GetConsoleCursorInfo(IO.m_hOUT, pCursorInfo)) {
			return false;
		}

		return true;
	}

	bool Screen::SetCursorInfo(const CONSOLE_CURSOR_INFO& CursorInfo) {
		if (!m_pWindow) {
			return false;
		}

		WINDOW_NATIVE_IO IO;
		if (!m_pWindow->GetNativeIO(&IO)) {
			return false;
		}

		if (!IO.m_hOUT || (IO.m_hOUT == INVALID_HANDLE_VALUE)) {
			return false;
		}

		if (!SetConsoleCursorInfo(IO.m_hOUT, &CursorInfo)) {
			return false;
		}

		return true;
	}

	bool Screen::ShowCursor() {
		CONSOLE_CURSOR_INFO cci;
		if (!GetCursorInfo(&cci)) {
			return false;
		}

		cci.bVisible = TRUE;

		if (!SetCursorInfo(cci)) {
			return false;
		}

		return true;
	}

	bool Screen::HideCursor() {
		CONSOLE_CURSOR_INFO cci;
		if (!GetCursorInfo(&cci)) {
			return false;
		}

		cci.bVisible = FALSE;

		if (!SetCursorInfo(cci)) {
			return false;
		}

		return true;
	}

	bool Screen::ToggleCursor() {
		CONSOLE_CURSOR_INFO cci;
		if (!GetCursorInfo(&cci)) {
			return false;
		}

		cci.bVisible = (cci.bVisible & 1) == 0;

		if (!SetCursorInfo(cci)) {
			return false;
		}

		return true;
	}

	bool Screen::GetCursorPosition(PCOORD const pCursorPosition) {
		if (!pCursorPosition) {
			return false;
		}

		CONSOLE_SCREEN_BUFFER_INFOEX csbi;
		if (!GetBufferInfo(&csbi)) {
			return false;
		}

		pCursorPosition->X = csbi.dwCursorPosition.X;
		pCursorPosition->Y = csbi.dwCursorPosition.Y;

		return true;
	}

	bool Screen::SetCursorPosition(const COORD& CursorPosition) {
		if (!m_pWindow) {
			return false;
		}

		WINDOW_NATIVE_IO IO;
		if (!m_pWindow->GetNativeIO(&IO)) {
			return false;
		}

		if (!IO.m_hOUT || (IO.m_hOUT == INVALID_HANDLE_VALUE)) {
			return false;
		}

		if (!SetConsoleCursorPosition(IO.m_hOUT, CursorPosition)) {
			return false;
		}

		return true;
	}

	bool Screen::Erase(const COORD& CursorPosition, const unsigned int unLength) {
		if (!m_pWindow) {
			return false;
		}

		WINDOW_NATIVE_IO IO;
		if (!m_pWindow->GetNativeIO(&IO)) {
			return false;
		}

		if (!IO.m_hOUT || (IO.m_hOUT == INVALID_HANDLE_VALUE)) {
			return false;
		}

		DWORD unWrittenAttributes = 0;
		if (!FillConsoleOutputCharacter(IO.m_hOUT, _T(' '), unLength, CursorPosition, &unWrittenAttributes)) {
			return false;
		}

		WORD unAttributes = 0;
		if (!GetAttributes(&unAttributes)) {
			return false;
		}

		unWrittenAttributes = 0;
		if (!FillConsoleOutputAttribute(IO.m_hOUT, unAttributes, unLength, CursorPosition, &unWrittenAttributes)) {
			return false;
		}

		return true;
	}

	Window* const Screen::GetWindow() const {
		return m_pWindow;
	}

	// ----------------------------------------------------------------
	// Console
	// ----------------------------------------------------------------

	Console::Console(Screen* const pScreen) : m_pScreen(pScreen) {
		// Nothing...
	}

	int Console::vprintf(const COLOR_PAIR& ColorPair, char const* const _Format, const va_list& vargs) {
		if (!m_pScreen) {
			return -1;
		}

		const auto& hHeap = GetProcessHeap();
		if (!hHeap) {
			return -1;
		}

		const auto& pBuffer = reinterpret_cast<char*>(HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(char) * TERMINAL_BUFFER_SIZE));
		if (!pBuffer) {
			return -1;
		}

		if (!m_pScreen->SetCursorColor(ColorPair)) {
			HeapFree(hHeap, NULL, pBuffer);
			return -1;
		}

		const int nLength = vsprintf_s(pBuffer, TERMINAL_BUFFER_SIZE, _Format, vargs);
		if (nLength == -1) {
			m_pScreen->RestoreCursorColor(true);
			HeapFree(hHeap, NULL, pBuffer);
			return -1;
		}

		pBuffer[TERMINAL_BUFFER_SIZE - 1] = 0;

		if (!m_pScreen->WriteA(pBuffer)) {
			m_pScreen->RestoreCursorColor(true);
			HeapFree(hHeap, NULL, pBuffer);
			return -1;
		}

		if (!m_pScreen->RestoreCursorColor(true)) {
			HeapFree(hHeap, NULL, pBuffer);
			return -1;
		}

		HeapFree(hHeap, NULL, pBuffer);
		return nLength;
	}

	int Console::vprintf(const COLOR& unForegroundColor, char const* const _Format, const va_list& vargs) {
		return vprintf(COLOR_PAIR(unForegroundColor), _Format, vargs);
	}

	int Console::printf(const COLOR_PAIR& ColorPair, char const* const _Format, ...) {
		va_list vargs;
		va_start(vargs, _Format);
		const int nLength = vprintf(ColorPair, _Format, vargs);
		va_end(vargs);
		return nLength;
	}

	int Console::printf(const COLOR& unForegroundColor, char const* const _Format, ...) {
		va_list vargs;
		va_start(vargs, _Format);
		const int nLength = vprintf(unForegroundColor, _Format, vargs);
		va_end(vargs);
		return nLength;
	}

	int Console::vwprintf(const COLOR_PAIR& ColorPair, wchar_t const* const _Format, const va_list& vargs) {
		if (!m_pScreen) {
			return -1;
		}

		const auto& hHeap = GetProcessHeap();
		if (!hHeap) {
			return -1;
		}

		const auto& pBuffer = reinterpret_cast<wchar_t*>(HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(wchar_t) * TERMINAL_BUFFER_SIZE));
		if (!pBuffer) {
			return -1;
		}

		if (!m_pScreen->SetCursorColor(ColorPair)) {
			HeapFree(hHeap, NULL, pBuffer);
			return -1;
		}

		const int nLength = vswprintf_s(pBuffer, TERMINAL_BUFFER_SIZE, _Format, vargs);
		if (nLength == -1) {
			m_pScreen->RestoreCursorColor(true);
			HeapFree(hHeap, NULL, pBuffer);
			return -1;
		}

		pBuffer[TERMINAL_BUFFER_SIZE - 1] = 0;

		if (!m_pScreen->WriteW(pBuffer)) {
			m_pScreen->RestoreCursorColor(true);
			HeapFree(hHeap, NULL, pBuffer);
			return -1;
		}

		if (!m_pScreen->RestoreCursorColor(true)) {
			HeapFree(hHeap, NULL, pBuffer);
			return -1;
		}

		HeapFree(hHeap, NULL, pBuffer);
		return nLength;
	}

	int Console::vwprintf(const COLOR& unForegroundColor, wchar_t const* const _Format, const va_list& vargs) {
		return vwprintf(COLOR_PAIR(unForegroundColor), _Format, vargs);
	}

	int Console::wprintf(const COLOR_PAIR& ColorPair, wchar_t const* const _Format, ...) {
		va_list vargs;
		va_start(vargs, _Format);
		const int nLength = vwprintf(ColorPair, _Format, vargs);
		va_end(vargs);
		return nLength;
	}

	int Console::wprintf(const COLOR& unForegroundColor, wchar_t const* const _Format, ...) {
		va_list vargs;
		va_start(vargs, _Format);
		const int nLength = vwprintf(unForegroundColor, _Format, vargs);
		va_end(vargs);
		return nLength;
	}

#ifdef _UNICODE
	int Console::tvprintf(const COLOR_PAIR& ColorPair, wchar_t const* const _Format, const va_list& vargs) {
		return vwprintf(ColorPair, _Format, vargs);
	}

	int Console::tvprintf(const COLOR& unForegroundColor, wchar_t const* const _Format, const va_list& vargs) {
		return vwprintf(unForegroundColor, _Format, vargs);
	}

	int Console::tprintf(const COLOR_PAIR& ColorPair, wchar_t const* const _Format, ...) {
		va_list vargs;
		va_start(vargs, _Format);
		const int nLength = tvprintf(ColorPair, _Format, vargs);
		va_end(vargs);
		return nLength;
	}

	int Console::tprintf(const COLOR& unForegroundColor, wchar_t const* const _Format, ...) {
		va_list vargs;
		va_start(vargs, _Format);
		const int nLength = tvprintf(unForegroundColor, _Format, vargs);
		va_end(vargs);
		return nLength;
	}
#else
	int Console::tvprintf(const COLOR_PAIR& ColorPair, char const* const _Format, const va_list& vargs) {
		return vprintf(ColorPair, _Format, vargs);
	}

	int Console::tvprintf(const COLOR& unForegroundColor, char const* const _Format, const va_list& vargs) {
		return vprintf(unForegroundColor, _Format, vargs);
	}

	int Console::tprintf(const COLOR_PAIR& ColorPair, char const* const _Format, ...) {
		va_list vargs;
		va_start(vargs, _Format);
		const int nLength = tvprintf(ColorPair, _Format, vargs);
		va_end(vargs);
		return nLength;
	}

	int Console::tprintf(const COLOR& unForegroundColor, char const* const _Format, ...) {
		va_list vargs;
		va_start(vargs, _Format);
		const int nLength = tvprintf(unForegroundColor, _Format, vargs);
		va_end(vargs);
		return nLength;
	}
#endif

	int Console::vscanf(const COLOR_PAIR& ColorPair, char const* const _Format, const va_list& vargs) {
		if (!m_pScreen) {
			return -1;
		}

		const auto& hHeap = GetProcessHeap();
		if (!hHeap) {
			return -1;
		}

		const auto& pBuffer = reinterpret_cast<char*>(HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(char) * TERMINAL_BUFFER_SIZE));
		if (!pBuffer) {
			return -1;
		}

		if (!m_pScreen->SetCursorColor(ColorPair)) {
			HeapFree(hHeap, NULL, pBuffer);
			return -1;
		}

		if (!m_pScreen->ReadA(pBuffer, TERMINAL_BUFFER_SIZE - 1)) {
			m_pScreen->RestoreCursorColor(true);
			HeapFree(hHeap, NULL, pBuffer);
			return -1;
		}

		if (!m_pScreen->RestoreCursorColor(true)) {
			HeapFree(hHeap, NULL, pBuffer);
			return -1;
		}

		const int nLength = vsscanf_s(pBuffer, _Format, vargs);
		if (nLength == -1) {
			HeapFree(hHeap, NULL, pBuffer);
			return -1;
		}

		HeapFree(hHeap, NULL, pBuffer);
		return nLength;
	}

	int Console::vscanf(const COLOR& unForegroundColor, char const* const _Format, const va_list& vargs) {
		return vscanf(COLOR_PAIR(unForegroundColor), _Format, vargs);
	}

	int Console::scanf(const COLOR_PAIR& ColorPair, char const* const _Format, ...) {
		va_list vargs;
		va_start(vargs, _Format);
		const int nLength = vscanf(ColorPair, _Format, vargs);
		va_end(vargs);
		return nLength;
	}

	int Console::scanf(const COLOR& unForegroundColor, char const* const _Format, ...) {
		va_list vargs;
		va_start(vargs, _Format);
		const int nLength = vscanf(COLOR_PAIR(unForegroundColor), _Format, vargs);
		va_end(vargs);
		return nLength;
	}

	int Console::vwscanf(const COLOR_PAIR& ColorPair, wchar_t const* const _Format, const va_list& vargs) {
		if (!m_pScreen) {
			return -1;
		}

		const auto& hHeap = GetProcessHeap();
		if (!hHeap) {
			return -1;
		}

		const auto& pBuffer = reinterpret_cast<wchar_t*>(HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(wchar_t) * TERMINAL_BUFFER_SIZE));
		if (!pBuffer) {
			return -1;
		}

		if (!m_pScreen->SetCursorColor(ColorPair)) {
			HeapFree(hHeap, NULL, pBuffer);
			return -1;
		}

		if (!m_pScreen->ReadW(pBuffer, TERMINAL_BUFFER_SIZE - 1)) {
			m_pScreen->RestoreCursorColor(true);
			HeapFree(hHeap, NULL, pBuffer);
			return -1;
		}

		if (!m_pScreen->RestoreCursorColor(true)) {
			HeapFree(hHeap, NULL, pBuffer);
			return -1;
		}

		const int nLength = vswscanf_s(pBuffer, _Format, vargs);
		if (nLength == -1) {
			HeapFree(hHeap, NULL, pBuffer);
			return -1;
		}

		HeapFree(hHeap, NULL, pBuffer);
		return nLength;
	}

	int Console::vwscanf(const COLOR& unForegroundColor, wchar_t const* const _Format, const va_list& vargs) {
		return vwscanf(COLOR_PAIR(unForegroundColor), _Format, vargs);
	}

	int Console::wscanf(const COLOR_PAIR& ColorPair, wchar_t const* const _Format, ...) {
		va_list vargs;
		va_start(vargs, _Format);
		const int nLength = vwscanf(ColorPair, _Format, vargs);
		va_end(vargs);
		return nLength;
	}

	int Console::wscanf(const COLOR& unForegroundColor, wchar_t const* const _Format, ...) {
		va_list vargs;
		va_start(vargs, _Format);
		const int nLength = vwscanf(COLOR_PAIR(unForegroundColor), _Format, vargs);
		va_end(vargs);
		return nLength;
	}

#ifdef _UNICODE
	int Console::tvscanf(const COLOR_PAIR& ColorPair, wchar_t const* const _Format, const va_list& vargs) {
		return vwscanf(ColorPair, _Format, vargs);
	}

	int Console::tvscanf(const COLOR& unForegroundColor, wchar_t const* const _Format, const va_list& vargs) {
		return vwscanf(unForegroundColor, _Format, vargs);
	}

	int Console::tscanf(const COLOR_PAIR& ColorPair, wchar_t const* const _Format, ...) {
		va_list vargs;
		va_start(vargs, _Format);
		const int nLength = tvscanf(ColorPair, _Format, vargs);
		va_end(vargs);
		return nLength;
	}

	int Console::tscanf(const COLOR& unForegroundColor, wchar_t const* const _Format, ...) {
		va_list vargs;
		va_start(vargs, _Format);
		const int nLength = tvscanf(unForegroundColor, _Format, vargs);
		va_end(vargs);
		return nLength;
	}
#else
	int Console::tvscanf(const COLOR_PAIR& ColorPair, char const* const _Format, const va_list& vargs) {
		return vscanf(ColorPair, _Format, vargs);
	}

	int Console::tvscanf(const COLOR& unForegroundColor, char const* const _Format, const va_list& vargs) {
		return vscanf(unForegroundColor, _Format, vargs);
	}

	int Console::tscanf(const COLOR_PAIR& ColorPair, char const* const _Format, ...) {
		va_list vargs;
		va_start(vargs, _Format);
		const int nLength = tvscanf(ColorPair, _Format, vargs);
		va_end(vargs);
		return nLength;
	}

	int Console::tscanf(const COLOR& unForegroundColor, char const* const _Format, ...) {
		va_list vargs;
		va_start(vargs, _Format);
		const int nLength = tvscanf(unForegroundColor, _Format, vargs);
		va_end(vargs);
		return nLength;
	}
#endif

	Screen* const Console::GetScreen() const {
		return m_pScreen;
	}

	// ----------------------------------------------------------------
	// TerminalMessage
	// ----------------------------------------------------------------

	TerminalMessage::TerminalMessage() {
		m_unAction = TERMINAL_MESSAGE_ACTION::ACTION_NONE;
		memset(m_pData, 0, sizeof(m_pData));
	}

	TERMINAL_MESSAGE_ACTION TerminalMessage::GetAction() const {
		return m_unAction;
	}

	void TerminalMessage::SetAction(TERMINAL_MESSAGE_ACTION unAction) {
		m_unAction = unAction;
	}

	unsigned char* TerminalMessage::GetData() {
		return m_pData;
	}

	void TerminalMessage::ReadData(void* pBuffer, unsigned int unSize) {
		memcpy(pBuffer, m_pData, unSize);
	}

	void TerminalMessage::WriteData(void* pBuffer, unsigned int unSize) {
		memcpy(m_pData, pBuffer, unSize);
	}

	// ----------------------------------------------------------------
	// Server
	// ----------------------------------------------------------------

	Server::Server(Screen* const pScreen) : m_pScreen(pScreen) {
		memset(m_szSessionName, 0, sizeof(m_szSessionName));
		m_hPipe = nullptr;

		const DWORD unPID = GetCurrentProcessId();
		const DWORD unTID = GetCurrentThreadId();
		const DWORD64 unCycle = __rdtsc();
		_stprintf_s(m_szSessionName, _T("GLOBAL:%08X:%08X:%08X%08X"), 0xFFFFFFFF - unPID, 0xFFFFFFFF - unTID, static_cast<DWORD>(unCycle & 0xFFFFFFFF), static_cast<DWORD>((unCycle >> 32) & 0xFFFFFFFF));

		TCHAR szPipe[64];
		memset(szPipe, 0, sizeof(szPipe));
		_stprintf_s(szPipe, _T("\\\\.\\pipe\\%s"), m_szSessionName);

		m_hPipe = CreateNamedPipe(szPipe, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 1, sizeof(TerminalMessage), sizeof(TerminalMessage), NMPWAIT_USE_DEFAULT_WAIT, nullptr);
	}

	Server::~Server() {
		Close();
	}

	bool Server::Open() {
		if (!m_hPipe || (m_hPipe == INVALID_HANDLE_VALUE)) {
			return false;
		}

		if (!ConnectNamedPipe(m_hPipe, nullptr)) {
			return false;
		}

		auto MessagePtr = std::make_unique<TerminalMessage>();
		if (!MessagePtr) {
			return false;
		}

		memset(MessagePtr.get(), 0, sizeof(TerminalMessage));

		MessagePtr->SetAction(TERMINAL_MESSAGE_ACTION::ACTION_OPEN);

		if (!Send(MessagePtr)) {
			Close();
			return false;
		}

		if (!Receive(MessagePtr)) {
			Close();
			return false;
		}

		if (MessagePtr->GetAction() != TERMINAL_MESSAGE_ACTION::ACTION_SUCCESS) {
			Close();
			return false;
		}

		return true;
	}

	bool Server::Close() {
		if (!m_hPipe || (m_hPipe == INVALID_HANDLE_VALUE)) {
			return false;
		}

		auto MessagePtr = std::make_unique<TerminalMessage>();
		if (!MessagePtr) {
			return false;
		}

		memset(MessagePtr.get(), 0, sizeof(TerminalMessage));

		MessagePtr->SetAction(TERMINAL_MESSAGE_ACTION::ACTION_CLOSE);

		if (!Send(MessagePtr)) {
			return false;
		}

		if (!CloseHandle(m_hPipe)) {
			return false;
		}

		m_hPipe = nullptr;

		memset(m_szSessionName, 0, sizeof(m_szSessionName));

		const DWORD unPID = GetCurrentProcessId();
		const DWORD unTID = GetCurrentThreadId();
		const DWORD64 unCycle = __rdtsc();
		_stprintf_s(m_szSessionName, _T("GLOBAL:%08X:%08X:%08X%08X"), 0xFFFFFFFF - unPID, 0xFFFFFFFF - unTID, static_cast<DWORD>(unCycle & 0xFFFFFFFF), static_cast<DWORD>((unCycle >> 32) & 0xFFFFFFFF));

		return true;
	}

	bool Server::Launch() {
		if (!m_hPipe || (m_hPipe == INVALID_HANDLE_VALUE)) {
			return false;
		}

		auto MessagePtr = std::make_unique<TerminalMessage>();
		if (!MessagePtr) {
			Close();
			return false;
		}

		while (MessagePtr->GetAction() != TERMINAL_MESSAGE_ACTION::ACTION_CLOSE) {
			memset(MessagePtr.get(), 0, sizeof(TerminalMessage));

			if (!Receive(MessagePtr)) {
				return false;
			}

			if (!Process(MessagePtr)) {
				return false;
			}
		}

		return true;
	}

	bool Server::Send(const std::unique_ptr<TerminalMessage>& ptrMessage) {
		if (!ptrMessage) {
			return false;
		}

		if (!m_hPipe || (m_hPipe == INVALID_HANDLE_VALUE)) {
			return false;
		}

		DWORD unNumberOfBytesWritten = 0;
		if (!WriteFile(m_hPipe, ptrMessage.get(), sizeof(TerminalMessage), &unNumberOfBytesWritten, nullptr)) {
			if (GetLastError() == ERROR_NO_DATA) {
				return true;
			}

			return false;
		}

		if (unNumberOfBytesWritten != sizeof(TerminalMessage)) {
			return false;
		}

		return true;
	}

	bool Server::Receive(const std::unique_ptr<TerminalMessage>& ptrMessage) {
		if (!ptrMessage) {
			return false;
		}

		if (!m_hPipe || (m_hPipe == INVALID_HANDLE_VALUE)) {
			return false;
		}

		DWORD unNumberOfBytesRead = 0;
		if (!ReadFile(m_hPipe, ptrMessage.get(), sizeof(TerminalMessage), &unNumberOfBytesRead, nullptr)) {
			if (GetLastError() == ERROR_BROKEN_PIPE) {
				ptrMessage->SetAction(TERMINAL_MESSAGE_ACTION::ACTION_CLOSE);
				return true;
			}

			return false;
		}

		if (unNumberOfBytesRead != sizeof(TerminalMessage)) {
			return false;
		}

		return true;
	}

	bool Server::Process(const std::unique_ptr<TerminalMessage>& ptrMessage) {
		if (!m_pScreen) {
			return false;
		}

		if (!ptrMessage) {
			return false;
		}

		switch (ptrMessage->GetAction()) {
			case TERMINAL_MESSAGE_ACTION::ACTION_CLOSE: {
				if (!CloseHandle(m_hPipe)) {
					return false;
				}

				m_hPipe = nullptr;

				memset(m_szSessionName, 0, sizeof(m_szSessionName));

				const DWORD unPID = GetCurrentProcessId();
				const DWORD unTID = GetCurrentThreadId();
				const DWORD64 unCycle = __rdtsc();
				_stprintf_s(m_szSessionName, _T("GLOBAL:%08X:%08X:%08X%08X"), 0xFFFFFFFF - unPID, 0xFFFFFFFF - unTID, static_cast<DWORD>(unCycle & 0xFFFFFFFF), static_cast<DWORD>((unCycle >> 32) & 0xFFFFFFFF));

				return true;
			}

			case TERMINAL_MESSAGE_ACTION::ACTION_READA: {
				ptrMessage->SetAction(m_pScreen->ReadA(reinterpret_cast<char*>(ptrMessage->GetData()), TERMINAL_BUFFER_SIZE) ? TERMINAL_MESSAGE_ACTION::ACTION_SUCCESS : TERMINAL_MESSAGE_ACTION::ACTION_NONE);
				if (Send(ptrMessage)) {
					return true;
				}

				break;
			}

			case TERMINAL_MESSAGE_ACTION::ACTION_READW: {
				ptrMessage->SetAction(m_pScreen->ReadW(reinterpret_cast<wchar_t*>(ptrMessage->GetData()), TERMINAL_BUFFER_SIZE) ? TERMINAL_MESSAGE_ACTION::ACTION_SUCCESS : TERMINAL_MESSAGE_ACTION::ACTION_NONE);
				if (Send(ptrMessage)) {
					return true;
				}

				break;
			}

			case TERMINAL_MESSAGE_ACTION::ACTION_WRITEA: {
				ptrMessage->SetAction(m_pScreen->WriteA(reinterpret_cast<char*>(ptrMessage->GetData())) ? TERMINAL_MESSAGE_ACTION::ACTION_SUCCESS : TERMINAL_MESSAGE_ACTION::ACTION_NONE);
				if (Send(ptrMessage)) {
					return true;
				}

				break;
			}

			case TERMINAL_MESSAGE_ACTION::ACTION_WRITEW: {
				ptrMessage->SetAction(m_pScreen->WriteW(reinterpret_cast<wchar_t*>(ptrMessage->GetData())) ? TERMINAL_MESSAGE_ACTION::ACTION_SUCCESS : TERMINAL_MESSAGE_ACTION::ACTION_NONE);
				if (Send(ptrMessage)) {
					return true;
				}

				break;
			}

			case TERMINAL_MESSAGE_ACTION::ACTION_PAUSEA: {
				ptrMessage->SetAction(m_pScreen->PauseA(reinterpret_cast<char*>(ptrMessage->GetData())) ? TERMINAL_MESSAGE_ACTION::ACTION_SUCCESS : TERMINAL_MESSAGE_ACTION::ACTION_NONE);
				if (Send(ptrMessage)) {
					return true;
				}

				break;
			}

			case TERMINAL_MESSAGE_ACTION::ACTION_PAUSEW: {
				ptrMessage->SetAction(m_pScreen->PauseW(reinterpret_cast<wchar_t*>(ptrMessage->GetData())) ? TERMINAL_MESSAGE_ACTION::ACTION_SUCCESS : TERMINAL_MESSAGE_ACTION::ACTION_NONE);
				if (Send(ptrMessage)) {
					return true;
				}

				break;
			}

			case TERMINAL_MESSAGE_ACTION::ACTION_GETBUFFERINFO: {
				ptrMessage->SetAction(m_pScreen->GetBufferInfo(reinterpret_cast<PCONSOLE_SCREEN_BUFFER_INFOEX>(ptrMessage->GetData())) ? TERMINAL_MESSAGE_ACTION::ACTION_SUCCESS : TERMINAL_MESSAGE_ACTION::ACTION_NONE);
				if (Send(ptrMessage)) {
					return true;
				}

				break;
			}

			case TERMINAL_MESSAGE_ACTION::ACTION_SETBUFFERINFO: {
				ptrMessage->SetAction(m_pScreen->SetBufferInfo(*reinterpret_cast<PCONSOLE_SCREEN_BUFFER_INFOEX>(ptrMessage->GetData())) ? TERMINAL_MESSAGE_ACTION::ACTION_SUCCESS : TERMINAL_MESSAGE_ACTION::ACTION_NONE);
				if (Send(ptrMessage)) {
					return true;
				}

				break;
			}

			case TERMINAL_MESSAGE_ACTION::ACTION_SETATTRIBUTES: {
				ptrMessage->SetAction(m_pScreen->SetAttributes(*reinterpret_cast<PWORD>(ptrMessage->GetData())) ? TERMINAL_MESSAGE_ACTION::ACTION_SUCCESS : TERMINAL_MESSAGE_ACTION::ACTION_NONE);
				if (Send(ptrMessage)) {
					return true;
				}

				break;
			}

			case TERMINAL_MESSAGE_ACTION::ACTION_FLUSH: {
				struct _FLUSH {
					bool m_bClearAll;
					bool m_bUpdateOriginalColorPair;
					bool m_bResetPreviousColorPair;
				} Data = *reinterpret_cast<_FLUSH*>(ptrMessage->GetData());

				ptrMessage->SetAction(m_pScreen->Flush(Data.m_bClearAll, Data.m_bUpdateOriginalColorPair, Data.m_bResetPreviousColorPair) ? TERMINAL_MESSAGE_ACTION::ACTION_SUCCESS : TERMINAL_MESSAGE_ACTION::ACTION_NONE);
				if (Send(ptrMessage)) {
					return true;
				}

				break;
			}

			case TERMINAL_MESSAGE_ACTION::ACTION_SETCOLOR: {
				ptrMessage->SetAction(m_pScreen->SetColor(*reinterpret_cast<PCOLOR_PAIR>(ptrMessage->GetData())) ? TERMINAL_MESSAGE_ACTION::ACTION_SUCCESS : TERMINAL_MESSAGE_ACTION::ACTION_NONE);
				if (Send(ptrMessage)) {
					return true;
				}

				break;
			}

			case TERMINAL_MESSAGE_ACTION::ACTION_RESTORECOLOR: {
				ptrMessage->SetAction(m_pScreen->RestoreColor(*reinterpret_cast<bool*>(ptrMessage->GetData())) ? TERMINAL_MESSAGE_ACTION::ACTION_SUCCESS : TERMINAL_MESSAGE_ACTION::ACTION_NONE);
				if (Send(ptrMessage)) {
					return true;
				}

				break;
			}

			case TERMINAL_MESSAGE_ACTION::ACTION_SETCURSORCOLOR: {
				ptrMessage->SetAction(m_pScreen->SetCursorColor(*reinterpret_cast<PCOLOR_PAIR>(ptrMessage->GetData())) ? TERMINAL_MESSAGE_ACTION::ACTION_SUCCESS : TERMINAL_MESSAGE_ACTION::ACTION_NONE);
				if (Send(ptrMessage)) {
					return true;
				}

				break;
			}

			case TERMINAL_MESSAGE_ACTION::ACTION_RESTORECURSORCOLOR: {
				ptrMessage->SetAction(m_pScreen->RestoreCursorColor(*reinterpret_cast<bool*>(ptrMessage->GetData())) ? TERMINAL_MESSAGE_ACTION::ACTION_SUCCESS : TERMINAL_MESSAGE_ACTION::ACTION_NONE);
				if (Send(ptrMessage)) {
					return true;
				}

				break;
			}

			case TERMINAL_MESSAGE_ACTION::ACTION_GETCURSORINFO: {
				ptrMessage->SetAction(m_pScreen->GetCursorInfo(reinterpret_cast<PCONSOLE_CURSOR_INFO>(ptrMessage->GetData())) ? TERMINAL_MESSAGE_ACTION::ACTION_SUCCESS : TERMINAL_MESSAGE_ACTION::ACTION_NONE);
				if (Send(ptrMessage)) {
					return true;
				}

				break;
			}

			case TERMINAL_MESSAGE_ACTION::ACTION_SETCURSORINFO: {
				ptrMessage->SetAction(m_pScreen->SetCursorInfo(*reinterpret_cast<PCONSOLE_CURSOR_INFO>(ptrMessage->GetData())) ? TERMINAL_MESSAGE_ACTION::ACTION_SUCCESS : TERMINAL_MESSAGE_ACTION::ACTION_NONE);
				if (Send(ptrMessage)) {
					return true;
				}

				break;
			}

			case TERMINAL_MESSAGE_ACTION::ACTION_SETCURSORPOSITION: {
				ptrMessage->SetAction(m_pScreen->SetCursorPosition(*reinterpret_cast<PCOORD>(ptrMessage->GetData())) ? TERMINAL_MESSAGE_ACTION::ACTION_SUCCESS : TERMINAL_MESSAGE_ACTION::ACTION_NONE);
				if (Send(ptrMessage)) {
					return true;
				}

				break;
			}

			case TERMINAL_MESSAGE_ACTION::ACTION_ERASE: {
				struct _ERASE {
					COORD m_CursorPosition;
					unsigned int m_unLength;
				} Data = *reinterpret_cast<_ERASE*>(ptrMessage->GetData());

				ptrMessage->SetAction(m_pScreen->Erase(Data.m_CursorPosition, Data.m_unLength) ? TERMINAL_MESSAGE_ACTION::ACTION_SUCCESS : TERMINAL_MESSAGE_ACTION::ACTION_NONE);
				if (Send(ptrMessage)) {
					return true;
				}

				break;
			}

			default: {
				break;
			}
		}

		return false;
	}

	Screen* const Server::GetScreen() const {
		return m_pScreen;
	}

	bool Server::GetSessionName(TCHAR szSessionName[64]) {
		memcpy(szSessionName, m_szSessionName, sizeof(m_szSessionName));
		return true;
	}

	const HANDLE Server::GetPipe() const {
		return m_hPipe;
	}

	// ----------------------------------------------------------------
	// Client
	// ----------------------------------------------------------------

	Client::Client() {
		memset(m_szSessionName, 0, sizeof(m_szSessionName));
		m_hPipe = nullptr;
	}

	Client::~Client() {
		Close();
	}

	bool Client::Open(TCHAR szSessionName[64]) {
		if (!szSessionName) {
			return false;
		}

		TCHAR szPipe[64];
		memset(szPipe, 0, sizeof(szPipe));
		_stprintf_s(szPipe, _T("\\\\.\\pipe\\%s"), szSessionName);

		m_hPipe = CreateFile(szPipe, GENERIC_READ | GENERIC_WRITE, NULL, nullptr, OPEN_EXISTING, NULL, nullptr);
		if (!m_hPipe || (m_hPipe == INVALID_HANDLE_VALUE)) {
			return false;
		}

		auto MessagePtr = std::make_unique<TerminalMessage>();
		if (!MessagePtr) {
			return false;
		}

		memset(MessagePtr.get(), 0, sizeof(TerminalMessage));

		if (!Receive(MessagePtr)) {
			Close();
			return false;
		}

		if (MessagePtr->GetAction() != TERMINAL_MESSAGE_ACTION::ACTION_OPEN) {
			Close();
			return false;
		}

		MessagePtr->SetAction(TERMINAL_MESSAGE_ACTION::ACTION_SUCCESS);

		if (!Send(MessagePtr)) {
			Close();
			return false;
		}

		return true;
	}

	bool Client::Close() {
		if (!m_hPipe || (m_hPipe == INVALID_HANDLE_VALUE)) {
			return false;
		}

		auto MessagePtr = std::make_unique<TerminalMessage>();
		if (!MessagePtr) {
			return false;
		}

		memset(MessagePtr.get(), 0, sizeof(TerminalMessage));

		MessagePtr->SetAction(TERMINAL_MESSAGE_ACTION::ACTION_CLOSE);

		if (!Send(MessagePtr)) {
			return false;
		}

		if (!CloseHandle(m_hPipe)) {
			return false;
		}

		m_hPipe = nullptr;

		memset(m_szSessionName, 0, sizeof(m_szSessionName));

		return true;
	}

	bool Client::ReadA(char* const szBuffer, const unsigned int unLength) {
		if (!szBuffer) {
			return false;
		}

		if (!unLength) {
			return false;
		}

		auto MessagePtr = std::make_unique<TerminalMessage>();
		if (!MessagePtr) {
			return false;
		}

		memset(MessagePtr.get(), 0, sizeof(TerminalMessage));

		MessagePtr->SetAction(TERMINAL_MESSAGE_ACTION::ACTION_READA);

		if (!Send(MessagePtr)) {
			Close();
			return false;
		}

		if (!Receive(MessagePtr)) {
			Close();
			return false;
		}

		if (MessagePtr->GetAction() != TERMINAL_MESSAGE_ACTION::ACTION_SUCCESS) {
			return false;
		}

		MessagePtr->ReadData(szBuffer, min(TERMINAL_MESSAGE_DATA_SIZE, unLength));

		return true;
	}

	bool Client::ReadW(wchar_t* const szBuffer, const unsigned int unLength) {
		if (!szBuffer) {
			return false;
		}

		if (!unLength) {
			return false;
		}

		auto MessagePtr = std::make_unique<TerminalMessage>();
		if (!MessagePtr) {
			return false;
		}

		memset(MessagePtr.get(), 0, sizeof(TerminalMessage));

		MessagePtr->SetAction(TERMINAL_MESSAGE_ACTION::ACTION_READW);

		if (!Send(MessagePtr)) {
			Close();
			return false;
		}

		if (!Receive(MessagePtr)) {
			Close();
			return false;
		}

		if (MessagePtr->GetAction() != TERMINAL_MESSAGE_ACTION::ACTION_SUCCESS) {
			return false;
		}

		MessagePtr->ReadData(szBuffer, min(TERMINAL_MESSAGE_DATA_SIZE, unLength * sizeof(wchar_t)));

		return true;
	}

#ifdef _UNICODE
	bool Client::Read(wchar_t* const szBuffer, const unsigned int unLength) {
		return ReadW(szBuffer, unLength);
	}
#else
	bool Client::Read(char* const szBuffer, const unsigned int unLength) {
		return ReadA(szBuffer, unLength);
	}
#endif

	bool Client::WriteA(char const* const szBuffer) {
		if (!szBuffer) {
			return false;
		}

		auto MessagePtr = std::make_unique<TerminalMessage>();
		if (!MessagePtr) {
			return false;
		}

		memset(MessagePtr.get(), 0, sizeof(TerminalMessage));

		MessagePtr->SetAction(TERMINAL_MESSAGE_ACTION::ACTION_WRITEA);

		const unsigned int unLength = static_cast<unsigned int>(strnlen_s(szBuffer, TERMINAL_MESSAGE_DATA_SIZE));
		MessagePtr->WriteData(const_cast<char*>(szBuffer), unLength);

		if (!Send(MessagePtr)) {
			Close();
			return false;
		}

		if (!Receive(MessagePtr)) {
			Close();
			return false;
		}

		if (MessagePtr->GetAction() != TERMINAL_MESSAGE_ACTION::ACTION_SUCCESS) {
			return false;
		}

		return true;
	}

	bool Client::WriteW(wchar_t const* const szBuffer) {
		if (!szBuffer) {
			return false;
		}

		auto MessagePtr = std::make_unique<TerminalMessage>();
		if (!MessagePtr) {
			return false;
		}

		memset(MessagePtr.get(), 0, sizeof(TerminalMessage));

		MessagePtr->SetAction(TERMINAL_MESSAGE_ACTION::ACTION_WRITEW);

		const unsigned int unLength = static_cast<unsigned int>(wcsnlen_s(szBuffer, TERMINAL_MESSAGE_DATA_SIZE) * sizeof(wchar_t));
		MessagePtr->WriteData(const_cast<wchar_t*>(szBuffer), unLength);

		if (!Send(MessagePtr)) {
			Close();
			return false;
		}

		if (!Receive(MessagePtr)) {
			Close();
			return false;
		}

		if (MessagePtr->GetAction() != TERMINAL_MESSAGE_ACTION::ACTION_SUCCESS) {
			return false;
		}

		return true;
	}

#ifdef _UNICODE
	bool Client::Write(wchar_t const* const szBuffer) {
		return WriteW(szBuffer);
	}
#else
	bool Client::Write(char const* const szBuffer) {
		return WriteA(szBuffer);
	}
#endif

	bool Client::PauseA(char const* szPromt) {
		if (!szPromt) {
			szPromt = "Press any key to continue...";
		}

		auto MessagePtr = std::make_unique<TerminalMessage>();
		if (!MessagePtr) {
			return false;
		}

		memset(MessagePtr.get(), 0, sizeof(TerminalMessage));

		MessagePtr->SetAction(TERMINAL_MESSAGE_ACTION::ACTION_PAUSEA);

		const unsigned int unLength = static_cast<unsigned int>(strnlen_s(szPromt, TERMINAL_MESSAGE_DATA_SIZE));
		MessagePtr->WriteData(const_cast<char*>(szPromt), unLength);

		if (!Send(MessagePtr)) {
			Close();
			return false;
		}

		if (!Receive(MessagePtr)) {
			Close();
			return false;
		}

		if (MessagePtr->GetAction() != TERMINAL_MESSAGE_ACTION::ACTION_SUCCESS) {
			return false;
		}

		return true;
	}

	bool Client::PauseW(wchar_t const* szPromt) {
		if (!szPromt) {
			szPromt = L"Press any key to continue...";
		}

		auto MessagePtr = std::make_unique<TerminalMessage>();
		if (!MessagePtr) {
			return false;
		}

		memset(MessagePtr.get(), 0, sizeof(TerminalMessage));

		MessagePtr->SetAction(TERMINAL_MESSAGE_ACTION::ACTION_PAUSEW);

		const unsigned int unLength = static_cast<unsigned int>(wcsnlen_s(szPromt, TERMINAL_MESSAGE_DATA_SIZE) * sizeof(wchar_t));
		MessagePtr->WriteData(const_cast<wchar_t*>(szPromt), unLength);

		if (!Send(MessagePtr)) {
			Close();
			return false;
		}

		if (!Receive(MessagePtr)) {
			Close();
			return false;
		}

		if (MessagePtr->GetAction() != TERMINAL_MESSAGE_ACTION::ACTION_SUCCESS) {
			return false;
		}

		return true;
	}

#ifdef _UNICODE
	bool Client::Pause(wchar_t const* szPromt) {
		return PauseW(szPromt);
	}
#else
	bool Client::Pause(char const* szPromt) {
		return PauseA(szPromt);
	}
#endif

	bool Client::GetBufferInfo(PCONSOLE_SCREEN_BUFFER_INFOEX const pBufferInfoEx) {
		if (!pBufferInfoEx) {
			return false;
		}

		auto MessagePtr = std::make_unique<TerminalMessage>();
		if (!MessagePtr) {
			return false;
		}

		memset(MessagePtr.get(), 0, sizeof(TerminalMessage));

		MessagePtr->SetAction(TERMINAL_MESSAGE_ACTION::ACTION_GETBUFFERINFO);

		if (!Send(MessagePtr)) {
			Close();
			return false;
		}

		if (!Receive(MessagePtr)) {
			Close();
			return false;
		}

		if (MessagePtr->GetAction() != TERMINAL_MESSAGE_ACTION::ACTION_SUCCESS) {
			return false;
		}

		MessagePtr->ReadData(pBufferInfoEx, sizeof(CONSOLE_SCREEN_BUFFER_INFOEX));

		return true;
	}

	bool Client::SetBufferInfo(CONSOLE_SCREEN_BUFFER_INFOEX& BufferInfoEx) {
		auto MessagePtr = std::make_unique<TerminalMessage>();
		if (!MessagePtr) {
			return false;
		}

		memset(MessagePtr.get(), 0, sizeof(TerminalMessage));

		MessagePtr->SetAction(TERMINAL_MESSAGE_ACTION::ACTION_SETBUFFERINFO);
		MessagePtr->WriteData(&BufferInfoEx, sizeof(CONSOLE_SCREEN_BUFFER_INFOEX));

		if (!Send(MessagePtr)) {
			Close();
			return false;
		}

		if (!Receive(MessagePtr)) {
			Close();
			return false;
		}

		if (MessagePtr->GetAction() != TERMINAL_MESSAGE_ACTION::ACTION_SUCCESS) {
			return false;
		}

		return true;
	}

	bool Client::GetAttributes(PWORD const pAttributes) {
		if (!pAttributes) {
			return false;
		}

		CONSOLE_SCREEN_BUFFER_INFOEX csbi;
		if (!GetBufferInfo(&csbi)) {
			return false;
		}

		*pAttributes = csbi.wAttributes;

		return true;
	}

	bool Client::SetAttributes(const WORD& unAttributes) {
		auto MessagePtr = std::make_unique<TerminalMessage>();
		if (!MessagePtr) {
			return false;
		}

		memset(MessagePtr.get(), 0, sizeof(TerminalMessage));

		MessagePtr->SetAction(TERMINAL_MESSAGE_ACTION::ACTION_SETATTRIBUTES);
		MessagePtr->WriteData(const_cast<PWORD>(&unAttributes), sizeof(WORD));

		if (!Send(MessagePtr)) {
			Close();
			return false;
		}

		if (!Receive(MessagePtr)) {
			Close();
			return false;
		}

		if (MessagePtr->GetAction() != TERMINAL_MESSAGE_ACTION::ACTION_SUCCESS) {
			return false;
		}

		return true;
	}

	bool Client::ChangeColorPalette(const COLOR& Color, const unsigned int unRGB) {
		if (static_cast<unsigned char>(Color) > 15) {
			return false;
		}

		CONSOLE_SCREEN_BUFFER_INFOEX csbi;
		if (!GetBufferInfo(&csbi)) {
			return false;
		}

		const unsigned char unR = (unRGB >> 16) & 0xFF;
		const unsigned char unG = (unRGB >> 8) & 0xFF;
		const unsigned char unB = unRGB & 0xFF;

		csbi.ColorTable[static_cast<unsigned char>(Color)] = RGB(unR, unG, unB);

		if (!SetBufferInfo(csbi)) {
			return false;
		}

		return true;
	}

	bool Client::ChangeColorPalette(const COLOR& Color, const unsigned char unR, const unsigned char unG, const unsigned char unB) {
		if (static_cast<unsigned char>(Color) > 15) {
			return false;
		}

		CONSOLE_SCREEN_BUFFER_INFOEX csbi;
		if (!GetBufferInfo(&csbi)) {
			return false;
		}

		csbi.ColorTable[static_cast<unsigned char>(Color)] = RGB(unR, unG, unB);

		if (!SetBufferInfo(csbi)) {
			return false;
		}

		return true;
	}

	bool Client::Flush(const bool bClearAll, const bool bUpdateOriginalColorPair, const bool bResetPreviousColorPair) {
		auto MessagePtr = std::make_unique<TerminalMessage>();
		if (!MessagePtr) {
			return false;
		}

		memset(MessagePtr.get(), 0, sizeof(TerminalMessage));

		MessagePtr->SetAction(TERMINAL_MESSAGE_ACTION::ACTION_FLUSH);

		struct _FLUSH {
			bool m_bClearAll;
			bool m_bUpdateOriginalColorPair;
			bool m_bResetPreviousColorPair;
		} Data;

		memset(&Data, 0, sizeof(Data));

		Data.m_bClearAll = bClearAll;
		Data.m_bUpdateOriginalColorPair = bUpdateOriginalColorPair;
		Data.m_bResetPreviousColorPair = bResetPreviousColorPair;

		MessagePtr->WriteData(&Data, sizeof(Data));

		if (!Send(MessagePtr)) {
			Close();
			return false;
		}

		if (!Receive(MessagePtr)) {
			Close();
			return false;
		}

		if (MessagePtr->GetAction() != TERMINAL_MESSAGE_ACTION::ACTION_SUCCESS) {
			return false;
		}

		return true;
	}

	bool Client::GetColor(PCOLOR_PAIR const pColorPair) {
		if (!pColorPair) {
			return false;
		}

		WORD unAttributes = 0;
		if (!GetAttributes(&unAttributes)) {
			return false;
		}

		*pColorPair = COLOR_PAIR(static_cast<COLOR>((unAttributes & 0xF0) >> 4), static_cast<COLOR>(unAttributes & 0x0F));

		return true;
	}

	bool Client::SetColor(const COLOR_PAIR& ColorPair) {
		auto MessagePtr = std::make_unique<TerminalMessage>();
		if (!MessagePtr) {
			return false;
		}

		memset(MessagePtr.get(), 0, sizeof(TerminalMessage));

		MessagePtr->SetAction(TERMINAL_MESSAGE_ACTION::ACTION_SETCOLOR);
		MessagePtr->WriteData(const_cast<PCOLOR_PAIR>(&ColorPair), sizeof(COLOR_PAIR));

		if (!Send(MessagePtr)) {
			Close();
			return false;
		}

		if (!Receive(MessagePtr)) {
			Close();
			return false;
		}

		if (MessagePtr->GetAction() != TERMINAL_MESSAGE_ACTION::ACTION_SUCCESS) {
			return false;
		}

		return true;
	}

	bool Client::RestoreColor(const bool bRestorePrevious) {
		auto MessagePtr = std::make_unique<TerminalMessage>();
		if (!MessagePtr) {
			return false;
		}

		memset(MessagePtr.get(), 0, sizeof(TerminalMessage));

		MessagePtr->SetAction(TERMINAL_MESSAGE_ACTION::ACTION_RESTORECOLOR);
		MessagePtr->WriteData(const_cast<bool*>(&bRestorePrevious), sizeof(bool));

		if (!Send(MessagePtr)) {
			Close();
			return false;
		}

		if (!Receive(MessagePtr)) {
			Close();
			return false;
		}

		if (MessagePtr->GetAction() != TERMINAL_MESSAGE_ACTION::ACTION_SUCCESS) {
			return false;
		}

		return true;
	}

	bool Client::GetCursorColor(PCOLOR_PAIR const pColorPair) {
		return GetColor(pColorPair);
	}

	bool Client::SetCursorColor(const COLOR_PAIR& ColorPair) {
		auto MessagePtr = std::make_unique<TerminalMessage>();
		if (!MessagePtr) {
			return false;
		}

		memset(MessagePtr.get(), 0, sizeof(TerminalMessage));

		MessagePtr->SetAction(TERMINAL_MESSAGE_ACTION::ACTION_SETCURSORCOLOR);
		MessagePtr->WriteData(const_cast<PCOLOR_PAIR>(&ColorPair), sizeof(COLOR_PAIR));

		if (!Send(MessagePtr)) {
			Close();
			return false;
		}

		if (!Receive(MessagePtr)) {
			Close();
			return false;
		}

		if (MessagePtr->GetAction() != TERMINAL_MESSAGE_ACTION::ACTION_SUCCESS) {
			return false;
		}

		return true;
	}

	bool Client::RestoreCursorColor(const bool bRestorePrevious) {
		auto MessagePtr = std::make_unique<TerminalMessage>();
		if (!MessagePtr) {
			return false;
		}

		memset(MessagePtr.get(), 0, sizeof(TerminalMessage));

		MessagePtr->SetAction(TERMINAL_MESSAGE_ACTION::ACTION_RESTORECURSORCOLOR);
		MessagePtr->WriteData(const_cast<bool*>(&bRestorePrevious), sizeof(bool));

		if (!Send(MessagePtr)) {
			Close();
			return false;
		}

		if (!Receive(MessagePtr)) {
			Close();
			return false;
		}

		if (MessagePtr->GetAction() != TERMINAL_MESSAGE_ACTION::ACTION_SUCCESS) {
			return false;
		}

		return true;
	}

	bool Client::GetCursorInfo(PCONSOLE_CURSOR_INFO const pCursorInfo) {
		if (!pCursorInfo) {
			return false;
		}

		auto MessagePtr = std::make_unique<TerminalMessage>();
		if (!MessagePtr) {
			return false;
		}

		memset(MessagePtr.get(), 0, sizeof(TerminalMessage));

		MessagePtr->SetAction(TERMINAL_MESSAGE_ACTION::ACTION_GETCURSORINFO);

		if (!Send(MessagePtr)) {
			Close();
			return false;
		}

		if (!Receive(MessagePtr)) {
			Close();
			return false;
		}

		if (MessagePtr->GetAction() != TERMINAL_MESSAGE_ACTION::ACTION_SUCCESS) {
			return false;
		}

		MessagePtr->ReadData(pCursorInfo, min(TERMINAL_MESSAGE_DATA_SIZE, sizeof(CONSOLE_CURSOR_INFO)));

		return true;
	}

	bool Client::SetCursorInfo(const CONSOLE_CURSOR_INFO& CursorInfo) {
		auto MessagePtr = std::make_unique<TerminalMessage>();
		if (!MessagePtr) {
			return false;
		}

		memset(MessagePtr.get(), 0, sizeof(TerminalMessage));

		MessagePtr->SetAction(TERMINAL_MESSAGE_ACTION::ACTION_SETCURSORINFO);
		MessagePtr->WriteData(const_cast<PCONSOLE_CURSOR_INFO>(&CursorInfo), sizeof(CONSOLE_CURSOR_INFO));

		if (!Send(MessagePtr)) {
			Close();
			return false;
		}

		if (!Receive(MessagePtr)) {
			Close();
			return false;
		}

		if (MessagePtr->GetAction() != TERMINAL_MESSAGE_ACTION::ACTION_SUCCESS) {
			return false;
		}

		return true;
	}

	bool Client::ShowCursor() {
		CONSOLE_CURSOR_INFO cci;
		if (!GetCursorInfo(&cci)) {
			return false;
		}

		cci.bVisible = TRUE;

		if (!SetCursorInfo(cci)) {
			return false;
		}

		return true;
	}

	bool Client::HideCursor() {
		CONSOLE_CURSOR_INFO cci;
		if (!GetCursorInfo(&cci)) {
			return false;
		}

		cci.bVisible = FALSE;

		if (!SetCursorInfo(cci)) {
			return false;
		}

		return true;
	}

	bool Client::ToggleCursor() {
		CONSOLE_CURSOR_INFO cci;
		if (!GetCursorInfo(&cci)) {
			return false;
		}

		cci.bVisible = (cci.bVisible & 1) == 0;

		if (!SetCursorInfo(cci)) {
			return false;
		}

		return true;
	}

	bool Client::GetCursorPosition(PCOORD const pCursorPosition) {
		if (!pCursorPosition) {
			return false;
		}

		CONSOLE_SCREEN_BUFFER_INFOEX csbi;
		if (!GetBufferInfo(&csbi)) {
			return false;
		}

		pCursorPosition->X = csbi.dwCursorPosition.X;
		pCursorPosition->Y = csbi.dwCursorPosition.Y;

		return true;
	}

	bool Client::SetCursorPosition(const COORD& CursorPosition) {
		auto MessagePtr = std::make_unique<TerminalMessage>();
		if (!MessagePtr) {
			return false;
		}

		memset(MessagePtr.get(), 0, sizeof(TerminalMessage));

		MessagePtr->SetAction(TERMINAL_MESSAGE_ACTION::ACTION_SETCURSORPOSITION);
		MessagePtr->WriteData(const_cast<PCOORD>(&CursorPosition), sizeof(COORD));

		if (!Send(MessagePtr)) {
			Close();
			return false;
		}

		if (!Receive(MessagePtr)) {
			Close();
			return false;
		}

		if (MessagePtr->GetAction() != TERMINAL_MESSAGE_ACTION::ACTION_SUCCESS) {
			return false;
		}

		return true;
	}

	bool Client::Erase(const COORD& CursorPosition, const unsigned int unLength) {
		auto MessagePtr = std::make_unique<TerminalMessage>();
		if (!MessagePtr) {
			return false;
		}

		memset(MessagePtr.get(), 0, sizeof(TerminalMessage));

		MessagePtr->SetAction(TERMINAL_MESSAGE_ACTION::ACTION_SETCURSORPOSITION);

		struct _ERASE {
			COORD m_CursorPosition;
			unsigned int m_unLength;
		} Data;

		memset(&Data, 0, sizeof(Data));

		Data.m_CursorPosition = CursorPosition;
		Data.m_unLength = unLength;

		MessagePtr->WriteData(&Data, sizeof(Data));

		if (!Send(MessagePtr)) {
			Close();
			return false;
		}

		if (!Receive(MessagePtr)) {
			Close();
			return false;
		}

		if (MessagePtr->GetAction() != TERMINAL_MESSAGE_ACTION::ACTION_SUCCESS) {
			return false;
		}

		return true;
	}

	int Client::vprintf(const COLOR_PAIR& ColorPair, char const* const _Format, const va_list& vargs) {
		const auto& hHeap = GetProcessHeap();
		if (!hHeap) {
			return -1;
		}

		const auto& pBuffer = reinterpret_cast<char*>(HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(char) * TERMINAL_BUFFER_SIZE));
		if (!pBuffer) {
			return -1;
		}

		if (!SetCursorColor(ColorPair)) {
			HeapFree(hHeap, NULL, pBuffer);
			return -1;
		}

		const int nLength = vsprintf_s(pBuffer, TERMINAL_BUFFER_SIZE, _Format, vargs);
		if (nLength == -1) {
			RestoreCursorColor(true);
			HeapFree(hHeap, NULL, pBuffer);
			return -1;
		}

		pBuffer[TERMINAL_BUFFER_SIZE - 1] = 0;

		if (!WriteA(pBuffer)) {
			RestoreCursorColor(true);
			HeapFree(hHeap, NULL, pBuffer);
			return -1;
		}

		if (!RestoreCursorColor(true)) {
			HeapFree(hHeap, NULL, pBuffer);
			return -1;
		}

		HeapFree(hHeap, NULL, pBuffer);
		return nLength;
	}

	int Client::vprintf(const COLOR& unForegroundColor, char const* const _Format, const va_list& vargs) {
		return vprintf(COLOR_PAIR(unForegroundColor), _Format, vargs);
	}

	int Client::printf(const COLOR_PAIR& ColorPair, char const* const _Format, ...) {
		va_list vargs;
		va_start(vargs, _Format);
		const int nLength = vprintf(ColorPair, _Format, vargs);
		va_end(vargs);
		return nLength;
	}

	int Client::printf(const COLOR& unForegroundColor, char const* const _Format, ...) {
		va_list vargs;
		va_start(vargs, _Format);
		const int nLength = vprintf(unForegroundColor, _Format, vargs);
		va_end(vargs);
		return nLength;
	}

	int Client::vwprintf(const COLOR_PAIR& ColorPair, wchar_t const* const _Format, const va_list& vargs) {
		const auto& hHeap = GetProcessHeap();
		if (!hHeap) {
			return -1;
		}

		const auto& pBuffer = reinterpret_cast<wchar_t*>(HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(wchar_t) * TERMINAL_BUFFER_SIZE));
		if (!pBuffer) {
			return -1;
		}

		if (!SetCursorColor(ColorPair)) {
			HeapFree(hHeap, NULL, pBuffer);
			return -1;
		}

		const int nLength = vswprintf_s(pBuffer, TERMINAL_BUFFER_SIZE, _Format, vargs);
		if (nLength == -1) {
			RestoreCursorColor(true);
			HeapFree(hHeap, NULL, pBuffer);
			return -1;
		}

		pBuffer[TERMINAL_BUFFER_SIZE - 1] = 0;

		if (!WriteW(pBuffer)) {
			RestoreCursorColor(true);
			HeapFree(hHeap, NULL, pBuffer);
			return -1;
		}

		if (!RestoreCursorColor(true)) {
			HeapFree(hHeap, NULL, pBuffer);
			return -1;
		}

		HeapFree(hHeap, NULL, pBuffer);
		return nLength;
	}

	int Client::vwprintf(const COLOR& unForegroundColor, wchar_t const* const _Format, const va_list& vargs) {
		return vwprintf(COLOR_PAIR(unForegroundColor), _Format, vargs);
	}

	int Client::wprintf(const COLOR_PAIR& ColorPair, wchar_t const* const _Format, ...) {
		va_list vargs;
		va_start(vargs, _Format);
		const int nLength = vwprintf(ColorPair, _Format, vargs);
		va_end(vargs);
		return nLength;
	}

	int Client::wprintf(const COLOR& unForegroundColor, wchar_t const* const _Format, ...) {
		va_list vargs;
		va_start(vargs, _Format);
		const int nLength = vwprintf(unForegroundColor, _Format, vargs);
		va_end(vargs);
		return nLength;
	}

#ifdef _UNICODE
	int Client::tvprintf(const COLOR_PAIR& ColorPair, wchar_t const* const _Format, const va_list& vargs) {
		return vwprintf(ColorPair, _Format, vargs);
	}

	int Client::tvprintf(const COLOR& unForegroundColor, wchar_t const* const _Format, const va_list& vargs) {
		return vwprintf(unForegroundColor, _Format, vargs);
	}

	int Client::tprintf(const COLOR_PAIR& ColorPair, wchar_t const* const _Format, ...) {
		va_list vargs;
		va_start(vargs, _Format);
		const int nLength = tvprintf(ColorPair, _Format, vargs);
		va_end(vargs);
		return nLength;
	}

	int Client::tprintf(const COLOR& unForegroundColor, wchar_t const* const _Format, ...) {
		va_list vargs;
		va_start(vargs, _Format);
		const int nLength = tvprintf(unForegroundColor, _Format, vargs);
		va_end(vargs);
		return nLength;
	}
#else
	int Client::tvprintf(const COLOR_PAIR& ColorPair, char const* const _Format, const va_list& vargs) {
		return vprintf(ColorPair, _Format, vargs);
	}

	int Client::tvprintf(const COLOR& unForegroundColor, char const* const _Format, const va_list& vargs) {
		return vprintf(unForegroundColor, _Format, vargs);
	}

	int Client::tprintf(const COLOR_PAIR& ColorPair, char const* const _Format, ...) {
		va_list vargs;
		va_start(vargs, _Format);
		const int nLength = tvprintf(ColorPair, _Format, vargs);
		va_end(vargs);
		return nLength;
	}

	int Client::tprintf(const COLOR& unForegroundColor, char const* const _Format, ...) {
		va_list vargs;
		va_start(vargs, _Format);
		const int nLength = tvprintf(unForegroundColor, _Format, vargs);
		va_end(vargs);
		return nLength;
	}
#endif

	int Client::vscanf(const COLOR_PAIR& ColorPair, char const* const _Format, const va_list& vargs) {
		const auto& hHeap = GetProcessHeap();
		if (!hHeap) {
			return -1;
		}

		const auto& pBuffer = reinterpret_cast<char*>(HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(char) * TERMINAL_BUFFER_SIZE));
		if (!pBuffer) {
			return -1;
		}

		if (!SetCursorColor(ColorPair)) {
			HeapFree(hHeap, NULL, pBuffer);
			return -1;
		}

		if (!ReadA(pBuffer, TERMINAL_BUFFER_SIZE - 1)) {
			RestoreCursorColor(true);
			HeapFree(hHeap, NULL, pBuffer);
			return -1;
		}

		if (!RestoreCursorColor(true)) {
			HeapFree(hHeap, NULL, pBuffer);
			return -1;
		}

		const int nLength = vsscanf_s(pBuffer, _Format, vargs);
		if (nLength == -1) {
			HeapFree(hHeap, NULL, pBuffer);
			return -1;
		}

		HeapFree(hHeap, NULL, pBuffer);
		return nLength;
	}

	int Client::vscanf(const COLOR& unForegroundColor, char const* const _Format, const va_list& vargs) {
		return vscanf(COLOR_PAIR(unForegroundColor), _Format, vargs);
	}

	int Client::scanf(const COLOR_PAIR& ColorPair, char const* const _Format, ...) {
		va_list vargs;
		va_start(vargs, _Format);
		const int nLength = vscanf(ColorPair, _Format, vargs);
		va_end(vargs);
		return nLength;
	}

	int Client::scanf(const COLOR& unForegroundColor, char const* const _Format, ...) {
		va_list vargs;
		va_start(vargs, _Format);
		const int nLength = vscanf(COLOR_PAIR(unForegroundColor), _Format, vargs);
		va_end(vargs);
		return nLength;
	}

	int Client::vwscanf(const COLOR_PAIR& ColorPair, wchar_t const* const _Format, const va_list& vargs) {
		const auto& hHeap = GetProcessHeap();
		if (!hHeap) {
			return -1;
		}

		const auto& pBuffer = reinterpret_cast<wchar_t*>(HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(wchar_t) * TERMINAL_BUFFER_SIZE));
		if (!pBuffer) {
			return -1;
		}

		if (!SetCursorColor(ColorPair)) {
			HeapFree(hHeap, NULL, pBuffer);
			return -1;
		}

		if (!ReadW(pBuffer, TERMINAL_BUFFER_SIZE - 1)) {
			RestoreCursorColor(true);
			HeapFree(hHeap, NULL, pBuffer);
			return -1;
		}

		if (!RestoreCursorColor(true)) {
			HeapFree(hHeap, NULL, pBuffer);
			return -1;
		}

		const int nLength = vswscanf_s(pBuffer, _Format, vargs);
		if (nLength == -1) {
			HeapFree(hHeap, NULL, pBuffer);
			return -1;
		}

		HeapFree(hHeap, NULL, pBuffer);
		return nLength;
	}

	int Client::vwscanf(const COLOR& unForegroundColor, wchar_t const* const _Format, const va_list& vargs) {
		return vwscanf(COLOR_PAIR(unForegroundColor), _Format, vargs);
	}

	int Client::wscanf(const COLOR_PAIR& ColorPair, wchar_t const* const _Format, ...) {
		va_list vargs;
		va_start(vargs, _Format);
		const int nLength = vwscanf(ColorPair, _Format, vargs);
		va_end(vargs);
		return nLength;
	}

	int Client::wscanf(const COLOR& unForegroundColor, wchar_t const* const _Format, ...) {
		va_list vargs;
		va_start(vargs, _Format);
		const int nLength = vwscanf(COLOR_PAIR(unForegroundColor), _Format, vargs);
		va_end(vargs);
		return nLength;
	}

#ifdef _UNICODE
	int Client::tvscanf(const COLOR_PAIR& ColorPair, wchar_t const* const _Format, const va_list& vargs) {
		return vwscanf(ColorPair, _Format, vargs);
	}

	int Client::tvscanf(const COLOR& unForegroundColor, wchar_t const* const _Format, const va_list& vargs) {
		return vwscanf(unForegroundColor, _Format, vargs);
	}

	int Client::tscanf(const COLOR_PAIR& ColorPair, wchar_t const* const _Format, ...) {
		va_list vargs;
		va_start(vargs, _Format);
		const int nLength = tvscanf(ColorPair, _Format, vargs);
		va_end(vargs);
		return nLength;
	}

	int Client::tscanf(const COLOR& unForegroundColor, wchar_t const* const _Format, ...) {
		va_list vargs;
		va_start(vargs, _Format);
		const int nLength = tvscanf(unForegroundColor, _Format, vargs);
		va_end(vargs);
		return nLength;
	}
#else
	int Client::tvscanf(const COLOR_PAIR& ColorPair, char const* const _Format, const va_list& vargs) {
		return vscanf(ColorPair, _Format, vargs);
	}

	int Client::tvscanf(const COLOR& unForegroundColor, char const* const _Format, const va_list& vargs) {
		return vscanf(unForegroundColor, _Format, vargs);
	}

	int Client::tscanf(const COLOR_PAIR& ColorPair, char const* const _Format, ...) {
		va_list vargs;
		va_start(vargs, _Format);
		const int nLength = tvscanf(ColorPair, _Format, vargs);
		va_end(vargs);
		return nLength;
	}

	int Client::tscanf(const COLOR& unForegroundColor, char const* const _Format, ...) {
		va_list vargs;
		va_start(vargs, _Format);
		const int nLength = tvscanf(unForegroundColor, _Format, vargs);
		va_end(vargs);
		return nLength;
	}
#endif

	bool Client::GetSessionName(TCHAR szSessionName[64]) {
		if (!m_hPipe || (m_hPipe == INVALID_HANDLE_VALUE)) {
			return false;
		}

		memcpy(szSessionName, m_szSessionName, sizeof(m_szSessionName));

		return true;
	}

	const HANDLE Client::GetPipe() const {
		return m_hPipe;
	}

	bool Client::Send(const std::unique_ptr<TerminalMessage>& ptrMessage) {
		if (!ptrMessage) {
			return false;
		}

		if (!m_hPipe || (m_hPipe == INVALID_HANDLE_VALUE)) {
			return false;
		}

		DWORD unNumberOfBytesWritten = 0;
		if (!WriteFile(m_hPipe, ptrMessage.get(), sizeof(TerminalMessage), &unNumberOfBytesWritten, nullptr)) {
			return false;
		}

		if (unNumberOfBytesWritten != sizeof(TerminalMessage)) {
			return false;
		}

		return true;
	}

	bool Client::Receive(const std::unique_ptr<TerminalMessage>& ptrMessage) {
		if (!ptrMessage) {
			return false;
		}

		if (!m_hPipe || (m_hPipe == INVALID_HANDLE_VALUE)) {
			return false;
		}

		DWORD unNumberOfBytesRead = 0;
		if (!ReadFile(m_hPipe, ptrMessage.get(), sizeof(TerminalMessage), &unNumberOfBytesRead, nullptr)) {
			return false;
		}

		if (unNumberOfBytesRead != sizeof(TerminalMessage)) {
			return false;
		}

		return true;
	}
}
