#include "HookManager.h"

bool HookManager::AddHook(BaseHook* pHook) {
	if (!pHook) {
		return false;
	}

	m_vecHooks.push_back(pHook);

	return true;
}

bool HookManager::HookAll() const {
	if (m_vecHooks.empty()) {
		return true;
	}

	for (const auto& pHook : m_vecHooks) {
		if (!pHook->Hook()) {
			return false;
		}
	}

	return true;
}

bool HookManager::UnHookAll() const {
	if (m_vecHooks.empty()) {
		return true;
	}

	for (const auto& pHook : m_vecHooks) {
		if (!pHook->UnHook()) {
			return false;
		}
	}

	return true;
}

HookManager g_HookManager;
