#pragma once

#ifndef _COMPILESTACKSTRING_H_
#define _COMPILESTACKSTRING_H_

// Edition for OreansCrack (Source: https://github.com/RenardDev/CompileUtils)

// ----------------------------------------------------------------
// Default
// ----------------------------------------------------------------

// Default
#define NOMINMAX
#include <Windows.h>

// STL
#include <type_traits>

// Detours
#include "Detours/Detours.h"

// General definitions

DEFINE_SECTION(".load", SECTION_READWRITE)

#define _STACKSTRING_NO_INLINE DEFINE_CODE_IN_SECTION(".load") __declspec(noinline)
#define _STACKSTRING_FORCE_INLINE DEFINE_CODE_IN_SECTION(".load") __forceinline

namespace StackString {

	template <class T>
	using clean_type = std::remove_const_t<std::remove_reference_t<T>>;

	template <typename T, std::size_t N>
	struct ByteIO;

	template <typename T>
	struct ByteIO<T, 1> {
		_STACKSTRING_FORCE_INLINE
		static constexpr void to(T value, unsigned char (&out)[1]) noexcept {
			out[0] = static_cast<unsigned char>(value);
		}

		_STACKSTRING_FORCE_INLINE
		static constexpr T from(const unsigned char (&in)[1]) noexcept {
			return static_cast<T>(in[0]);
		}
	};

	template <typename T>
	struct ByteIO<T, 2> {
		_STACKSTRING_FORCE_INLINE
		static constexpr void to(T value, unsigned char (&out)[2]) noexcept {
			const unsigned short x = static_cast<unsigned short>(value);
			out[0] = static_cast<unsigned char>(x & 0xFF);
			out[1] = static_cast<unsigned char>((x >> 8) & 0xFF);
		}

		_STACKSTRING_FORCE_INLINE
		static constexpr T from(const unsigned char (&in)[2]) noexcept {
			const unsigned short x =
			    static_cast<unsigned short>(in[0]) |
			    (static_cast<unsigned short>(in[1]) << 8);
			return static_cast<T>(x);
		}
	};

	template <typename T>
	struct ByteIO<T, 4> {
		_STACKSTRING_FORCE_INLINE
		static constexpr void to(T value, unsigned char (&out)[4]) noexcept {
			const unsigned int x = static_cast<unsigned int>(value);
			out[0] = static_cast<unsigned char>(x & 0xFF);
			out[1] = static_cast<unsigned char>((x >> 8) & 0xFF);
			out[2] = static_cast<unsigned char>((x >> 16) & 0xFF);
			out[3] = static_cast<unsigned char>((x >> 24) & 0xFF);
		}

		_STACKSTRING_FORCE_INLINE
		static constexpr T from(const unsigned char (&in)[4]) noexcept {
			const unsigned int x =
			    static_cast<unsigned int>(in[0]) |
			    (static_cast<unsigned int>(in[1]) << 8) |
			    (static_cast<unsigned int>(in[2]) << 16) |
			    (static_cast<unsigned int>(in[3]) << 24);
			return static_cast<T>(x);
		}
	};

	template <unsigned long long unLength, typename T, unsigned long long unLine = 0, unsigned long long unCounter = 0>
	class StackString {
	private:
		static constexpr std::size_t kLength = static_cast<std::size_t>(unLength);
		static constexpr std::size_t kPlainBytes = kLength * sizeof(T);

	public:
		class DecryptedString {
		public:
			_STACKSTRING_FORCE_INLINE
			explicit DecryptedString(const StackString& enc) noexcept {
				for (std::size_t i = 0; i < kLength; ++i) {
					unsigned char tmp[sizeof(T)];

					for (std::size_t k = 0; k < sizeof(T); ++k) {
						const std::size_t j = i * sizeof(T) + k;
						tmp[k] = enc.m_pStorage[j] ^ 0xFF;
					}

					m_pBuffer[i] = ByteIO<T, sizeof(T)>::from(tmp);
				}
			}

			_STACKSTRING_FORCE_INLINE
			~DecryptedString() noexcept {
				Clear();
			}

			DecryptedString(const DecryptedString&) = delete;
			DecryptedString& operator=(const DecryptedString&) = delete;

			_STACKSTRING_FORCE_INLINE
			DecryptedString(DecryptedString&& other) noexcept {
				for (std::size_t i = 0; i < kLength; ++i)
					m_pBuffer[i] = other.m_pBuffer[i];
				other.Clear();
			}

			_STACKSTRING_FORCE_INLINE
			DecryptedString& operator=(DecryptedString&& other) noexcept {
				if (this != &other) {
					for (std::size_t i = 0; i < kLength; ++i)
						m_pBuffer[i] = other.m_pBuffer[i];
					other.Clear();
				}
				return *this;
			}

			_STACKSTRING_FORCE_INLINE T* get() noexcept {
				return m_pBuffer;
			}

			_STACKSTRING_FORCE_INLINE const T* c_str() const noexcept {
				return m_pBuffer;
			}

			_STACKSTRING_FORCE_INLINE operator T*() noexcept {
				return get();
			}

			_STACKSTRING_FORCE_INLINE operator const T*() const noexcept {
				return c_str();
			}

		private:
			_STACKSTRING_FORCE_INLINE void Clear() noexcept {
				volatile T* p = m_pBuffer;
				for (std::size_t i = 0; i < kLength; ++i)
					p[i] = T {};
			}

			T m_pBuffer[kLength];
		};

		_STACKSTRING_FORCE_INLINE constexpr StackString(T* pData) noexcept {
			static_assert(sizeof(T) == 1 || sizeof(T) == 2 || sizeof(T) == 4, "Unsupported character size");

			for (std::size_t i = 0; i < kLength; ++i) {
				unsigned char bytes[sizeof(T)] {};
				ByteIO<T, sizeof(T)>::to(pData[i], bytes);

				for (std::size_t k = 0; k < sizeof(T); ++k) {
					const std::size_t j = i * sizeof(T) + k;
					m_pStorage[j] = static_cast<unsigned char>(bytes[k] ^ 0xFF);
				}
			}
		}

		_STACKSTRING_FORCE_INLINE
		DecryptedString Decrypt() const noexcept {
			return DecryptedString(*this);
		}

	private:
		unsigned char m_pStorage[kPlainBytes] {};
	};

}

#define _STACKSTRING(S)                                                                                                                                                                         \
	([]() -> auto {                                                                                                                                                                             \
		constexpr size_t unLength = std::extent_v<std::remove_reference_t<decltype(S)>>;                                                                                                        \
		constexpr auto Encrypted = StackString::StackString<unLength, StackString::clean_type<decltype(S[0])>, __LINE__, __COUNTER__>(const_cast<StackString::clean_type<decltype(S[0])>*>(S)); \
		return Encrypted.Decrypt();                                                                                                                                                             \
	} ())

#define STACKSTRING(S) _STACKSTRING(S)

#undef _STACKSTRING_FORCE_INLINE
#undef _STACKSTRING_NO_INLINE

#endif // !_COMPILESTACKSTRING_H_
