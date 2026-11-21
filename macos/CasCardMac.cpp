// SPDX-License-Identifier: GPL-2.0-or-later
#include "CasCardMac.hpp"

#include <cstdio>
#include <cstring>

namespace TvCasMac {

namespace {

inline uint16_t ReadReturnCode(const uint8_t *recv) noexcept {
    return static_cast<uint16_t>((static_cast<uint16_t>(recv[4]) << 8) | recv[5]);
}

bool IsZeroBytes(const uint8_t *p, size_t n) noexcept {
    for (size_t i = 0; i < n; ++i) {
        if (p[i] != 0) return false;
    }
    return true;
}

} // namespace

bool CasCard::Open(std::unique_ptr<CardReader> reader, const std::string &readerName) {
    Close();
    if (!reader) {
        m_lastError = "カードリーダーが指定されていません";
        return false;
    }
    if (!reader->IsOpen() && !reader->Open(readerName)) {
        m_lastError = reader->GetLastError();
        return false;
    }
    m_reader = std::move(reader);
    if (!RunInitialSetting()) {
        Close();
        return false;
    }
    m_initialized = true;
    m_lastError.clear();
    return true;
}

void CasCard::Close() {
    m_initialized = false;
    m_lastEcmSize = 0;
    m_lastEcmSucceeded = false;
    if (m_reader) {
        m_reader->Close();
        m_reader.reset();
    }
}

bool CasCard::RunInitialSetting() {
    uint8_t recv[264] = {};
    size_t recvSize = sizeof(recv);

    // Initial Setting Conditions Command (ARIB STD-B25)
    static const uint8_t kInitCmd[] = {0x90U, 0x30U, 0x00U, 0x00U, 0x00U};
    if (!m_reader->Transmit(kInitCmd, sizeof(kInitCmd), recv, &recvSize)) {
        m_lastError = m_reader->GetLastError();
        return false;
    }
    if (recvSize < 57) {
        m_lastError = "B-CAS 初期設定コマンドの応答サイズが不正です";
        return false;
    }

    m_info = CasCardInfo{};
    m_info.caSystemID = static_cast<uint16_t>((static_cast<uint16_t>(recv[6]) << 8) | recv[7]);
    std::memcpy(m_info.cardID, &recv[8], 6);
    m_info.cardType = recv[14];
    m_info.messagePartitionLength = recv[15];
    std::memcpy(m_info.systemKey, &recv[16], 32);
    std::memcpy(m_info.initialCbc, &recv[48], 8);

    if (IsZeroBytes(m_info.cardID, 6)) {
        m_lastError = "B-CAS カード ID が不正です";
        return false;
    }

    // Card ID Information Acquire Command (optional fallback if unsupported)
    static const uint8_t kCardIDCmd[] = {0x90U, 0x32U, 0x00U, 0x00U, 0x00U};
    std::memset(recv, 0, sizeof(recv));
    recvSize = sizeof(recv);
    if (m_reader->Transmit(kCardIDCmd, sizeof(kCardIDCmd), recv, &recvSize) && recvSize >= 19) {
        m_info.cardManufacturerID = recv[7];
        m_info.cardVersion = recv[8];
        m_info.checkCode = static_cast<uint16_t>((static_cast<uint16_t>(recv[15]) << 8) | recv[16]);
    }

    m_lastEcmSize = 0;
    m_lastEcmSucceeded = false;
    return true;
}

std::string CasCard::FormatCardID() const {
    const uint64_t id =
        ((((static_cast<uint64_t>(m_info.cardID[0] & 0x1F) << 40) |
           (static_cast<uint64_t>(m_info.cardID[1]) << 32) |
           (static_cast<uint64_t>(m_info.cardID[2]) << 24) |
           (static_cast<uint64_t>(m_info.cardID[3]) << 16) |
           (static_cast<uint64_t>(m_info.cardID[4]) << 8) |
            static_cast<uint64_t>(m_info.cardID[5])) * 100000ULL) +
         static_cast<uint64_t>(m_info.checkCode));

    char buf[64];
    std::snprintf(buf, sizeof(buf),
                  "%d%03lu %04lu %04lu %04lu %04lu",
                  static_cast<int>(m_info.cardID[0] >> 5),
                  static_cast<unsigned long>((id / 10000000000000000ULL) % 10000ULL),
                  static_cast<unsigned long>((id / 1000000000000ULL) % 10000ULL),
                  static_cast<unsigned long>((id / 100000000ULL) % 10000ULL),
                  static_cast<unsigned long>((id / 10000ULL) % 10000ULL),
                  static_cast<unsigned long>(id % 10000ULL));
    return std::string(buf);
}

const uint8_t *CasCard::GetKsFromEcm(const uint8_t *ecmData, size_t ecmSize) {
    if (!IsOpen()) {
        m_lastError = "カードが開かれていません";
        return nullptr;
    }
    if (!ecmData || ecmSize < kMinEcmSize || ecmSize > kMaxEcmSize) {
        m_lastError = "ECM サイズが不正です";
        return nullptr;
    }

    if (m_lastEcmSize == ecmSize && std::memcmp(m_lastEcmData, ecmData, ecmSize) == 0) {
        return m_lastEcmSucceeded ? m_ksData : nullptr;
    }

    uint8_t send[kMaxEcmSize + 6];
    send[0] = 0x90U;
    send[1] = 0x34U;
    send[2] = 0x00U;
    send[3] = 0x00U;
    send[4] = static_cast<uint8_t>(ecmSize);
    std::memcpy(&send[5], ecmData, ecmSize);
    send[5 + ecmSize] = 0x00U;

    uint8_t recv[264] = {};
    size_t recvSize = sizeof(recv);
    if (!m_reader->Transmit(send, 6 + ecmSize, recv, &recvSize)) {
        m_lastEcmSize = 0;
        m_lastEcmSucceeded = false;
        m_lastError = m_reader->GetLastError();
        return nullptr;
    }
    if (recvSize < 25) {
        m_lastEcmSize = 0;
        m_lastEcmSucceeded = false;
        m_lastError = "ECM 応答サイズが不正です";
        return nullptr;
    }

    m_lastEcmSize = ecmSize;
    std::memcpy(m_lastEcmData, ecmData, ecmSize);
    std::memcpy(m_ksData, &recv[6], 16);

    switch (ReadReturnCode(recv)) {
    case 0x0200U: // Payment-deferred PPV
    case 0x0400U: // Prepaid PPV
    case 0x0800U: // Tier
    case 0x4480U:
    case 0x4280U:
        m_lastEcmSucceeded = true;
        m_lastError.clear();
        return m_ksData;
    default:
        m_lastEcmSucceeded = false;
        m_lastError = "ECM がカードに拒否されました（未契約または視聴不可）";
        return nullptr;
    }
}

bool CasCard::SendEmmSection(const uint8_t *emmData, size_t emmSize) {
    if (!IsOpen()) {
        m_lastError = "カードが開かれていません";
        return false;
    }
    if (!emmData || emmSize < 17 || emmSize > kMaxEmmSize) {
        m_lastError = "EMM サイズが不正です";
        return false;
    }

    uint8_t send[kMaxEmmSize + 6];
    send[0] = 0x90U;
    send[1] = 0x36U;
    send[2] = 0x00U;
    send[3] = 0x00U;
    send[4] = static_cast<uint8_t>(emmSize);
    std::memcpy(&send[5], emmData, emmSize);
    send[5 + emmSize] = 0x00U;

    uint8_t recv[264] = {};
    size_t recvSize = sizeof(recv);
    if (!m_reader->Transmit(send, 6 + emmSize, recv, &recvSize)) {
        m_lastError = m_reader->GetLastError();
        return false;
    }
    if (recvSize < 8) {
        m_lastError = "EMM 応答サイズが不正です";
        return false;
    }
    if (ReadReturnCode(recv) == 0x2100U) {
        m_lastError.clear();
        return true;
    }
    m_lastError = "EMM がカードに受け付けられませんでした";
    return false;
}

} // namespace TvCasMac
