#pragma once

#ifndef _HOOKMANAGER_H_
#define _HOOKMANAGER_H_

// Default
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <tchar.h>

// STL
#include <vector>

// Detours
#include "Detours.h"

// ----------------------------------------------------------------
// General definitions
// ----------------------------------------------------------------

#define DECLARE_INLINE_HOOK(NAME, RETURN_TYPE, CALLING_CONVENTION, ...) \
	RETURN_TYPE CALLING_CONVENTION NAME##Hook(__VA_ARGS__); \
	using fn##NAME = RETURN_TYPE(CALLING_CONVENTION*)(__VA_ARGS__); \
	class Hook##NAME : public BaseHook { \
	public: \
		Hook##NAME(); \
	public: \
		bool Hook() override; \
		bool UnHook() override; \
	public: \
		template<typename... Args> \
		RETURN_TYPE Call(Args... args) { return reinterpret_cast<fn##NAME>(m_Hook.GetTrampoline())(args...); } \
	private: \
		Detours::Hook::InlineHook m_Hook; \
	}; \
	extern Hook##NAME g_Hook##NAME;

#define DEFINE_INLINE_HOOK(NAME, ADDRESS_LAMBDA, RETURN_TYPE, CALLING_CONVENTION, ...) \
	Hook##NAME::Hook##NAME() { \
		g_HookManager.AddHook(this); \
	} \
	bool Hook##NAME::Hook() { \
		void* const pAddress = ([]() -> void* ADDRESS_LAMBDA)(); \
		if (!pAddress) { return false; } \
		if (!m_Hook.Set(pAddress)) { return false; } \
		if (!m_Hook.Hook(NAME##Hook)) { return false; } \
		return true; \
	} \
	bool Hook##NAME::UnHook() { return m_Hook.UnHook(); } \
	Hook##NAME g_Hook##NAME; \
	RETURN_TYPE CALLING_CONVENTION NAME##Hook(__VA_ARGS__)

class BaseHook {
public:
	virtual bool Hook() = 0;
	virtual bool UnHook() = 0;
};

class HookManager {
public:
	bool AddHook(BaseHook* pHook);

public:
	bool HookAll() const;
	bool UnHookAll() const;

private:
	std::vector<BaseHook*> m_vecHooks;
};

extern HookManager g_HookManager;

#endif // !_HOOKMANAGER_H_
