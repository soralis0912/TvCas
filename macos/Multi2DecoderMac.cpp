// SPDX-License-Identifier: GPL-2.0-or-later
#include "Multi2DecoderMac.hpp"
#include <cstring>

namespace TvCasMac {

namespace {

inline uint32_t LoadBE32(const uint8_t *p) noexcept {
    uint32_t v;
    std::memcpy(&v, p, sizeof(v));
    return __builtin_bswap32(v);
}

inline void StoreBE32(uint8_t *p, uint32_t v) noexcept {
    v = __builtin_bswap32(v);
    std::memcpy(p, &v, sizeof(v));
}

} // namespace

void Multi2Decoder::SysKey::SetBigEndian(const uint8_t *src) noexcept {
    for (int i = 0; i < 8; ++i) {
        k[i] = LoadBE32(src + i * 4);
    }
}

void Multi2Decoder::DatKey::SetBigEndian(const uint8_t *src) noexcept {
    left = LoadBE32(src + 0);
    right = LoadBE32(src + 4);
}

void Multi2Decoder::DatKey::GetBigEndian(uint8_t *dst) const noexcept {
    StoreBE32(dst + 0, left);
    StoreBE32(dst + 4, right);
}

inline void Multi2Decoder::Pi1(DatKey &b) noexcept {
    b.right ^= b.left;
}

inline void Multi2Decoder::Pi2(DatKey &b, uint32_t k1) noexcept {
    const uint32_t y = b.right + k1;
    const uint32_t z = RotL(y, 1U) + y - 1U;
    b.left ^= RotL(z, 4U) ^ z;
}

inline void Multi2Decoder::Pi3(DatKey &b, uint32_t k2, uint32_t k3) noexcept {
    const uint32_t y = b.left + k2;
    const uint32_t z = RotL(y, 2U) + y + 1U;
    const uint32_t a = RotL(z, 8U) ^ z;
    const uint32_t bb = a + k3;
    const uint32_t c = RotL(bb, 1U) - bb;
    b.right ^= (RotL(c, 16U) ^ (c | b.left));
}

inline void Multi2Decoder::Pi4(DatKey &b, uint32_t k4) noexcept {
    const uint32_t y = b.right + k4;
    b.left ^= (RotL(y, 2U) + y + 1U);
}

void Multi2Decoder::KeySchedule(SysKey &workKey, const SysKey &sysKey, DatKey dataKey) noexcept {
    Pi1(dataKey);
    Pi2(dataKey, sysKey.k[0]);
    workKey.k[0] = dataKey.left;

    Pi3(dataKey, sysKey.k[1], sysKey.k[2]);
    workKey.k[1] = dataKey.right;

    Pi4(dataKey, sysKey.k[3]);
    workKey.k[2] = dataKey.left;

    Pi1(dataKey);
    workKey.k[3] = dataKey.right;

    Pi2(dataKey, sysKey.k[4]);
    workKey.k[4] = dataKey.left;

    Pi3(dataKey, sysKey.k[5], sysKey.k[6]);
    workKey.k[5] = dataKey.right;

    Pi4(dataKey, sysKey.k[7]);
    workKey.k[6] = dataKey.left;

    Pi1(dataKey);
    workKey.k[7] = dataKey.right;
}

void Multi2Decoder::EncryptBlock(DatKey &block, const SysKey &wk) noexcept {
    for (int round = 0; round < kScrambleRounds; ++round) {
        Pi1(block);
        Pi2(block, wk.k[0]);
        Pi3(block, wk.k[1], wk.k[2]);
        Pi4(block, wk.k[3]);
        Pi1(block);
        Pi2(block, wk.k[4]);
        Pi3(block, wk.k[5], wk.k[6]);
        Pi4(block, wk.k[7]);
    }
}

void Multi2Decoder::DecryptBlock(DatKey &block, const SysKey &wk) noexcept {
    for (int round = 0; round < kScrambleRounds; ++round) {
        Pi4(block, wk.k[7]);
        Pi3(block, wk.k[5], wk.k[6]);
        Pi2(block, wk.k[4]);
        Pi1(block);
        Pi4(block, wk.k[3]);
        Pi3(block, wk.k[1], wk.k[2]);
        Pi2(block, wk.k[0]);
        Pi1(block);
    }
}

bool Multi2Decoder::Initialize(const uint8_t *systemKey32, const uint8_t *initialCbc8) noexcept {
    if (!systemKey32 || !initialCbc8) {
        return false;
    }
    m_systemKey.SetBigEndian(systemKey32);
    m_initialCbc.SetBigEndian(initialCbc8);
    m_sysKeyValid = true;
    m_workKeyValid = false;
    return true;
}

bool Multi2Decoder::SetScrambleKey(const uint8_t *scrambleKey16) noexcept {
    if (!m_sysKeyValid) {
        return false;
    }
    if (!scrambleKey16) {
        m_workKeyValid = false;
        return false;
    }
    DatKey oddKey, evenKey;
    oddKey.SetBigEndian(scrambleKey16 + 0);
    evenKey.SetBigEndian(scrambleKey16 + 8);
    KeySchedule(m_workKeyOdd, m_systemKey, oddKey);
    KeySchedule(m_workKeyEven, m_systemKey, evenKey);
    m_workKeyValid = true;
    return true;
}

void Multi2Decoder::ClearScrambleKey() noexcept {
    m_workKeyValid = false;
}

bool Multi2Decoder::Decode(uint8_t *data, size_t size, uint8_t scrCtrl) const noexcept {
    if (scrCtrl == 0) {
        return true;
    }
    if (!data || !m_sysKeyValid || !m_workKeyValid || (scrCtrl != 2U && scrCtrl != 3U)) {
        return false;
    }

    const SysKey &wk = (scrCtrl == 3U) ? m_workKeyOdd : m_workKeyEven;
    DatKey cbc = m_initialCbc;
    const size_t fullBytes = size & ~size_t{7};
    uint8_t *p = data;
    uint8_t *const end = data + fullBytes;

    // CBC mode for full 64-bit blocks
    while (p < end) {
        DatKey cipher;
        cipher.SetBigEndian(p);
        DatKey plain = cipher;
        DecryptBlock(plain, wk);
        plain ^= cbc;
        cbc = cipher;
        plain.GetBigEndian(p);
        p += 8;
    }

    // OFB mode for trailing 1..7 bytes
    const size_t rem = size & size_t{7};
    if (rem > 0) {
        EncryptBlock(cbc, wk);
        uint8_t keystream[8];
        cbc.GetBigEndian(keystream);
        for (size_t i = 0; i < rem; ++i) {
            p[i] ^= keystream[i];
        }
    }
    return true;
}

bool Multi2Decoder::Encode(uint8_t *data, size_t size, uint8_t scrCtrl) const noexcept {
    if (scrCtrl == 0) {
        return true;
    }
    if (!data || !m_sysKeyValid || !m_workKeyValid || (scrCtrl != 2U && scrCtrl != 3U)) {
        return false;
    }

    const SysKey &wk = (scrCtrl == 3U) ? m_workKeyOdd : m_workKeyEven;
    DatKey cbc = m_initialCbc;
    const size_t fullBytes = size & ~size_t{7};
    uint8_t *p = data;
    uint8_t *const end = data + fullBytes;

    while (p < end) {
        DatKey block;
        block.SetBigEndian(p);
        block ^= cbc;
        EncryptBlock(block, wk);
        cbc = block;
        block.GetBigEndian(p);
        p += 8;
    }

    const size_t rem = size & size_t{7};
    if (rem > 0) {
        EncryptBlock(cbc, wk);
        uint8_t keystream[8];
        cbc.GetBigEndian(keystream);
        for (size_t i = 0; i < rem; ++i) {
            p[i] ^= keystream[i];
        }
    }
    return true;
}

} // namespace TvCasMac
