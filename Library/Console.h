#pragma once

#ifndef _CONSOLE_H_
#define _CONSOLE_H_

// Default
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

// General definitions

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

bool ConnectToConsole();

int clrvprintf(COLOR_PAIR ColorPair, char const* const _Format, va_list vargs);
int clrvprintf(COLOR unForegroundColor, char const* const _Format, va_list vargs);
int clrprintf(COLOR_PAIR ColorPair, char const* const _Format, ...);
int clrprintf(COLOR unForegroundColor, char const* const _Format, ...);

#endif // !_CONSOLE_H_
