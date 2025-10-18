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
#include "Detours/Detours.h"

// Log
#include "Log.h"

// ----------------------------------------------------------------
// General definitions
// ----------------------------------------------------------------

#ifdef _M_X64
#define _THISCALL_TO_FASTCALL_ARGUMENTS(...) __VA_ARGS__
#define _FASTCALL_TO_THISCALL_ARGUMENTS(...) __VA_ARGS__
#define _RAW_HOOK_CALLING_CONVENTION __fastcall
#elif _M_IX86
#define _THISCALL_TO_FASTCALL_ARGUMENTS_IMPL(...) void* pECX, void* pEDX
#define _THISCALL_TO_FASTCALL_ARGUMENTS_IMPL_MORE(X, ...) X, void* pEDX __VA_OPT__(,) __VA_ARGS__
#define _THISCALL_TO_FASTCALL_ARGUMENTS(...) _THISCALL_TO_FASTCALL_ARGUMENTS_IMPL ## __VA_OPT__(_MORE) (__VA_ARGS__)
#define _FASTCALL_TO_THISCALL_ARGUMENTS_IMPL(...) pECX, pEDX
#define _FASTCALL_TO_THISCALL_ARGUMENTS_IMPL_MORE(X, ...) X, pEDX __VA_OPT__(,) __VA_ARGS__
#define _FASTCALL_TO_THISCALL_ARGUMENTS(...) _FASTCALL_TO_THISCALL_ARGUMENTS_IMPL ## __VA_OPT__(_MORE) (__VA_ARGS__)
#define _RAW_HOOK_CALLING_CONVENTION __cdecl
#endif

#define DECLARE_INLINE_HOOK(NAME, RETURN_TYPE, CALLING_CONVENTION, ...)                                        \
	RETURN_TYPE CALLING_CONVENTION NAME##Hook(__VA_ARGS__);                                                    \
	using fn##NAME = RETURN_TYPE(CALLING_CONVENTION*)(__VA_ARGS__);                                            \
	class Hook##NAME : public BaseHook {                                                                       \
	public:                                                                                                    \
		Hook##NAME();                                                                                          \
		~Hook##NAME();                                                                                         \
	public:                                                                                                    \
		bool Hook() override;                                                                                  \
		bool UnHook() override;                                                                                \
	public:                                                                                                    \
		template<typename... Args>                                                                             \
		RETURN_TYPE Call(Args... args) { return reinterpret_cast<fn##NAME>(m_Hook.GetTrampoline())(args...); } \
	private:                                                                                                   \
		void* m_pAddress;                                                                                      \
		Detours::Hook::InlineHook m_Hook;                                                                      \
	};                                                                                                         \
	extern Hook##NAME g_Hook##NAME;

#define DECLARE_INLINE_WRAPPER_HOOK(NAME, RETURN_TYPE, CALLING_CONVENTION, ...)                                \
	RETURN_TYPE CALLING_CONVENTION NAME##Hook(__VA_ARGS__);                                                    \
	using fn##NAME = RETURN_TYPE(CALLING_CONVENTION*)(__VA_ARGS__);                                            \
	class Hook##NAME : public BaseHook {                                                                       \
	public:                                                                                                    \
		Hook##NAME();                                                                                          \
		~Hook##NAME();                                                                                         \
	public:                                                                                                    \
		bool Hook() override;                                                                                  \
		bool UnHook() override;                                                                                \
	public:                                                                                                    \
		template<typename... Args>                                                                             \
		RETURN_TYPE Call(Args... args) { return reinterpret_cast<fn##NAME>(m_Hook.GetTrampoline())(args...); } \
	private:                                                                                                   \
		void* m_pAddress;                                                                                      \
		Detours::Hook::InlineWrapperHook m_Hook;                                                               \
	};                                                                                                         \
	extern Hook##NAME g_Hook##NAME;

#define DECLARE_RAW_HOOK(NAME) \
	bool _RAW_HOOK_CALLING_CONVENTION NAME##Hook(Detours::Hook::PRAW_CONTEXT pCTX); \
	class Hook##NAME : public BaseHook {                                            \
	public:                                                                         \
		Hook##NAME();                                                               \
		~Hook##NAME();                                                              \
	public:                                                                         \
		bool Hook() override;                                                       \
		bool UnHook() override;                                                     \
	public:                                                                         \
		void* GetTrampoline() const { return m_Hook.GetTrampoline(); };             \
	private:                                                                        \
		void* m_pAddress;                                                           \
		Detours::Hook::RawHook m_Hook;                                              \
	};                                                                              \
	extern Hook##NAME g_Hook##NAME;

#define DEFINE_INLINE_HOOK(NAME, AVAILABILITY_FUNCTION, ADDRESS_FUNCTION, RETURN_TYPE, CALLING_CONVENTION, ...)                    \
	Hook##NAME::Hook##NAME() {                                                                                                     \
		m_pAddress = nullptr;                                                                                                      \
		if (!GetHookManager().AddHook(this)) { LOG_WARNING(_T("`%s` - Failed to add hook in hook manager!\n"), _T(#NAME)); }       \
	}                                                                                                                              \
	Hook##NAME::~Hook##NAME() {                                                                                                    \
		if (!GetHookManager().RemoveHook(this)) { LOG_WARNING(_T("`%s` - Failed to remove hook in hook manager!\n"), _T(#NAME)); } \
	}                                                                                                                              \
	bool Hook##NAME::Hook() {                                                                                                      \
		LOG_INFO(_T("`%s` - Hooking...\n"), _T(#NAME));                                                                            \
		if (!AVAILABILITY_FUNCTION()) { LOG_INFO(_T("`%s` - Disabled!\n"), _T(#NAME)); return true; }                              \
		m_pAddress = ADDRESS_FUNCTION();                                                                                           \
		if (!m_pAddress) { LOG_WARNING(_T("`%s` - Null address!\n"), _T(#NAME)); return false; }                                   \
		if (!m_Hook.Set(m_pAddress)) { LOG_WARNING(_T("`%s` - Wrong address!\n"), _T(#NAME)); return false; }                      \
		if (!m_Hook.Hook(NAME##Hook)) { LOG_WARNING(_T("`%s` - Failed!\n"), _T(#NAME)); return false; }                            \
		LOG_INFO(_T("`%s` - Hooked!\n"), _T(#NAME));                                                                               \
		return true;                                                                                                               \
	}                                                                                                                              \
	bool Hook##NAME::UnHook() {                                                                                                    \
		LOG_INFO(_T("`%s` - Unhooking...\n"), _T(#NAME));                                                                          \
		if (!AVAILABILITY_FUNCTION()) { LOG_INFO(_T("`%s` - Disabled!\n"), _T(#NAME)); return true; }                              \
		if (!m_Hook.UnHook()) { LOG_ERROR(_T("`%s` - Failed!\n"), _T(#NAME)); return false; }                                      \
		LOG_INFO(_T("`%s` - Unhooked!\n"), _T(#NAME));                                                                             \
		return true;                                                                                                               \
	}                                                                                                                              \
	Hook##NAME g_Hook##NAME;                                                                                                       \
	RETURN_TYPE CALLING_CONVENTION NAME##Hook(__VA_ARGS__      )

#define DEFINE_INLINE_SHORT_HOOK(NAME, AVAILABILITY_FUNCTION, ADDRESS_FUNCTION, RETURN_TYPE, CALLING_CONVENTION, ...)              \
	Hook##NAME::Hook##NAME() {                                                                                                     \
		m_pAddress = nullptr;                                                                                                      \
		if (!GetHookManager().AddHook(this)) { LOG_WARNING(_T("`%s` - Failed to add hook in hook manager!\n"), _T(#NAME)); }       \
	}                                                                                                                              \
	Hook##NAME::~Hook##NAME() {                                                                                                    \
		if (!GetHookManager().RemoveHook(this)) { LOG_WARNING(_T("`%s` - Failed to remove hook in hook manager!\n"), _T(#NAME)); } \
	}                                                                                                                              \
	bool Hook##NAME::Hook() {                                                                                                      \
		LOG_INFO(_T("`%s` - Hooking...\n"), _T(#NAME));                                                                            \
		if (!AVAILABILITY_FUNCTION()) { LOG_INFO(_T("`%s` - Disabled!\n"), _T(#NAME)); return true; }                              \
		m_pAddress = ADDRESS_FUNCTION();                                                                                           \
		if (!m_pAddress) { LOG_WARNING(_T("`%s` - Null address!\n"), _T(#NAME)); return false; }                                   \
		if (!m_Hook.Set(m_pAddress)) { LOG_WARNING(_T("`%s` - Wrong address!\n"), _T(#NAME)); return false; }                      \
		if (!m_Hook.Hook(NAME##Hook, true)) { LOG_WARNING(_T("`%s` - Failed!\n"), _T(#NAME)); return false; }                      \
		LOG_INFO(_T("`%s` - Hooked!\n"), _T(#NAME));                                                                               \
		return true;                                                                                                               \
	}                                                                                                                              \
	bool Hook##NAME::UnHook() {                                                                                                    \
		LOG_INFO(_T("`%s` - Unhooking...\n"), _T(#NAME));                                                                          \
		if (!AVAILABILITY_FUNCTION()) { LOG_INFO(_T("`%s` - Disabled!\n"), _T(#NAME)); return true; }                              \
		if (!m_Hook.UnHook()) { LOG_ERROR(_T("`%s` - Failed!\n"), _T(#NAME)); return false; }                                      \
		LOG_INFO(_T("`%s` - Unhooked!\n"), _T(#NAME));                                                                             \
		return true;                                                                                                               \
	}                                                                                                                              \
	Hook##NAME g_Hook##NAME;                                                                                                       \
	RETURN_TYPE CALLING_CONVENTION NAME##Hook(__VA_ARGS__)

#define DEFINE_RAW_HOOK(NAME, AVAILABILITY_FUNCTION, ADDRESS_FUNCTION)                                                             \
	Hook##NAME::Hook##NAME() {                                                                                                     \
		m_pAddress = nullptr;                                                                                                      \
		if (!GetHookManager().AddHook(this)) { LOG_WARNING(_T("`%s` - Failed to add hook in hook manager!\n"), _T(#NAME)); }       \
	}                                                                                                                              \
	Hook##NAME::~Hook##NAME() {                                                                                                    \
		if (!GetHookManager().RemoveHook(this)) { LOG_WARNING(_T("`%s` - Failed to remove hook in hook manager!\n"), _T(#NAME)); } \
	}                                                                                                                              \
	bool Hook##NAME::Hook() {                                                                                                      \
		LOG_INFO(_T("`%s` - Hooking...\n"), _T(#NAME));                                                                            \
		if (!AVAILABILITY_FUNCTION()) { LOG_INFO(_T("`%s` - Disabled!\n"), _T(#NAME)); return true; }                              \
		m_pAddress = ADDRESS_FUNCTION();                                                                                           \
		if (!m_pAddress) { LOG_WARNING(_T("`%s` - Null address!\n"), _T(#NAME)); return false; }                                   \
		if (!m_Hook.Set(m_pAddress)) { LOG_WARNING(_T("`%s` - Wrong address!\n"), _T(#NAME)); return false; }                      \
		if (!m_Hook.Hook(NAME##Hook)) { LOG_WARNING(_T("`%s` - Failed!\n"), _T(#NAME)); return false; }                            \
		LOG_INFO(_T("`%s` - Hooked!\n"), _T(#NAME));                                                                               \
		return true;                                                                                                               \
	}                                                                                                                              \
	bool Hook##NAME::UnHook() {                                                                                                    \
		LOG_INFO(_T("`%s` - UnHooking...\n"), _T(#NAME));                                                                          \
		if (!AVAILABILITY_FUNCTION()) { LOG_INFO(_T("`%s` - Disabled!\n"), _T(#NAME)); return true; }                              \
		if (!m_Hook.UnHook()) { LOG_ERROR(_T("`%s` - Failed!\n"), _T(#NAME)); return false; }                                      \
		LOG_INFO(_T("`%s` - UnHooked!\n"), _T(#NAME));                                                                             \
		return true;                                                                                                               \
	}                                                                                                                              \
	Hook##NAME g_Hook##NAME;                                                                                                       \
	bool _RAW_HOOK_CALLING_CONVENTION NAME##Hook(Detours::Hook::PRAW_CONTEXT pCTX)

#define DEFINE_NATIVE_RAW_HOOK(NAME, AVAILABILITY_FUNCTION, ADDRESS_FUNCTION)                                                      \
	Hook##NAME::Hook##NAME() {                                                                                                     \
		m_pAddress = nullptr;                                                                                                      \
		if (!GetHookManager().AddHook(this)) { LOG_WARNING(_T("`%s` - Failed to add hook in hook manager!\n"), _T(#NAME)); }       \
	}                                                                                                                              \
	Hook##NAME::~Hook##NAME() {                                                                                                    \
		if (!GetHookManager().RemoveHook(this)) { LOG_WARNING(_T("`%s` - Failed to remove hook in hook manager!\n"), _T(#NAME)); } \
	}                                                                                                                              \
	bool Hook##NAME::Hook() {                                                                                                      \
		LOG_INFO(_T("`%s` - Hooking...\n"), _T(#NAME));                                                                            \
		if (!AVAILABILITY_FUNCTION()) { LOG_INFO(_T("`%s` - Disabled!\n"), _T(#NAME)); return true; }                              \
		m_pAddress = ADDRESS_FUNCTION();                                                                                           \
		if (!m_pAddress) { LOG_WARNING(_T("`%s` - Null address!\n"), _T(#NAME)); return false; }                                   \
		if (!m_Hook.Set(m_pAddress)) { LOG_WARNING(_T("`%s` - Wrong address!\n"), _T(#NAME)); return false; }                      \
		if (!m_Hook.Hook(NAME##Hook, true)) { LOG_WARNING(_T("`%s` - Failed!\n"), _T(#NAME)); return false; }                      \
		LOG_INFO(_T("`%s` - Hooked!\n"), _T(#NAME));                                                                               \
		return true;                                                                                                               \
	}                                                                                                                              \
	bool Hook##NAME::UnHook() {                                                                                                    \
		LOG_INFO(_T("`%s` - UnHooking...\n"), _T(#NAME));                                                                          \
		if (!AVAILABILITY_FUNCTION()) { LOG_INFO(_T("`%s` - Disabled!\n"), _T(#NAME)); return true; }                              \
		if (!m_Hook.UnHook()) { LOG_ERROR(_T("`%s` - Failed!\n"), _T(#NAME)); return false; }                                      \
		LOG_INFO(_T("`%s` - UnHooked!\n"), _T(#NAME));                                                                             \
		return true;                                                                                                               \
	}                                                                                                                              \
	Hook##NAME g_Hook##NAME;                                                                                                       \
	bool _RAW_HOOK_CALLING_CONVENTION NAME##Hook(Detours::Hook::PRAW_CONTEXT pCTX)

class BaseHook {
public:
	virtual bool Hook() = 0;
	virtual bool UnHook() = 0;
};

class HookManager {
public:
	bool AddHook(BaseHook* pHook);
	bool RemoveHook(BaseHook* pHook);

public:
	bool HookAll() const;
	bool UnHookAll() const;

private:
	std::vector<BaseHook*> m_vecHooks;
};

HookManager& GetHookManager();

#endif // !_HOOKMANAGER_H_
