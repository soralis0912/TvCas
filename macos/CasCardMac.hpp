// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once

#include "CardReaderMac.hpp"
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace TvCasMac {

struct CasCardInfo {
    uint16_t caSystemID = 0;
    uint8_t cardID[6] = {};
    uint8_t cardType = 0xFF;
    uint8_t messagePartitionLength = 0;
    uint8_t systemKey[32] = {};
    uint8_t initialCbc[8] = {};
    uint8_t cardManufacturerID = 0;
    uint8_t cardVersion = 0;
    uint16_t checkCode = 0;
};

class CasCard {
public:
    static constexpr size_t kMinEcmSize = 30;
    static constexpr size_t kMaxEcmSize = 256;
    static constexpr size_t kMaxEmmSize = 263;

    CasCard() = default;
    ~CasCard() { Close(); }

    // Takes ownership of an already-opened (or un-opened) CardReader.
    bool Open(std::unique_ptr<CardReader> reader, const std::string &readerName = "");
    void Close();
    bool IsOpen() const { return m_reader && m_reader->IsOpen() && m_initialized; }

    const CasCardInfo &GetCardInfo() const noexcept { return m_info; }
    std::string GetReaderName() const { return m_reader ? m_reader->GetReaderName() : ""; }
    std::string GetLastError() const { return m_lastError; }
    std::string FormatCardID() const;

    // Sends ECM (0x90 0x34) and returns pointer to 16-byte Ks (Odd[8] + Even[8]) or nullptr.
    const uint8_t *GetKsFromEcm(const uint8_t *ecmData, size_t ecmSize);

    // Sends EMM (0x90 0x36).
    bool SendEmmSection(const uint8_t *emmData, size_t emmSize);

private:
    bool RunInitialSetting();

    std::unique_ptr<CardReader> m_reader;
    CasCardInfo m_info;
    bool m_initialized = false;
    std::string m_lastError;

    size_t m_lastEcmSize = 0;
    uint8_t m_lastEcmData[kMaxEcmSize] = {};
    uint8_t m_ksData[16] = {};
    bool m_lastEcmSucceeded = false;
};

} // namespace TvCasMac
