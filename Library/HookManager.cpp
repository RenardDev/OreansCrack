#include "HookManager.h"

bool HookManager::AddHook(BaseHook* pHook) {
	if (!pHook) {
		return false;
	}

	m_vecHooks.push_back(pHook);

	return true;
}

bool HookManager::RemoveHook(BaseHook* pHook) {
	if (!pHook) {
		return false;
	}

	for (auto it = m_vecHooks.begin(); it != m_vecHooks.end(); ++it) {
		if ((*it) == pHook) {
			m_vecHooks.erase(it);
			break;
		}
	}

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

HookManager& GetHookManager() {
	static HookManager instance;
	return instance;
}
