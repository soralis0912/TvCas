// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>

namespace TvCasMac {

class Multi2Decoder {
public:
    static constexpr int kScrambleRounds = 4;

    Multi2Decoder() noexcept = default;

    bool Initialize(const uint8_t *systemKey32, const uint8_t *initialCbc8) noexcept;
    bool SetScrambleKey(const uint8_t *scrambleKey16) noexcept;
    void ClearScrambleKey() noexcept;

    bool IsInitialized() const noexcept { return m_sysKeyValid; }
    bool HasScrambleKey() const noexcept { return m_workKeyValid; }

    // scrCtrl: 0 = unscrambled (no-op), 2 = Even, 3 = Odd.
    bool Decode(uint8_t *data, size_t size, uint8_t scrCtrl) const noexcept;

    // Symmetric MULTI2 CBC+OFB encryption (used for self-tests and verification).
    bool Encode(uint8_t *data, size_t size, uint8_t scrCtrl) const noexcept;

private:
    struct SysKey {
        uint32_t k[8] = {};
        void SetBigEndian(const uint8_t *src) noexcept;
    };

    struct DatKey {
        uint32_t left = 0;
        uint32_t right = 0;
        void SetBigEndian(const uint8_t *src) noexcept;
        void GetBigEndian(uint8_t *dst) const noexcept;
        DatKey &operator^=(const DatKey &rhs) noexcept {
            left ^= rhs.left;
            right ^= rhs.right;
            return *this;
        }
    };

    static inline uint32_t RotL(uint32_t v, uint32_t r) noexcept {
        return (v << r) | (v >> (32U - r));
    }
    static inline void Pi1(DatKey &b) noexcept;
    static inline void Pi2(DatKey &b, uint32_t k1) noexcept;
    static inline void Pi3(DatKey &b, uint32_t k2, uint32_t k3) noexcept;
    static inline void Pi4(DatKey &b, uint32_t k4) noexcept;
    static void KeySchedule(SysKey &workKey, const SysKey &sysKey, DatKey dataKey) noexcept;
    static void EncryptBlock(DatKey &block, const SysKey &wk) noexcept;
    static void DecryptBlock(DatKey &block, const SysKey &wk) noexcept;

    DatKey m_initialCbc;
    SysKey m_systemKey;
    SysKey m_workKeyOdd;
    SysKey m_workKeyEven;
    bool m_sysKeyValid = false;
    bool m_workKeyValid = false;
};

} // namespace TvCasMac
