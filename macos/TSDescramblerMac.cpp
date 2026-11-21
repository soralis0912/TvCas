// SPDX-License-Identifier: GPL-2.0-or-later
#include "TSDescramblerMac.hpp"

#include <algorithm>
#include <cstring>

namespace TvCasMac {

uint32_t TSDescrambler::CalcCRC32MPEG2(const uint8_t *data, size_t len) noexcept {
    uint32_t crc = 0xFFFFFFFFU;
    for (size_t i = 0; i < len; ++i) {
        crc ^= static_cast<uint32_t>(data[i]) << 24;
        for (int b = 0; b < 8; ++b) {
            crc = (crc & 0x80000000U) ? ((crc << 1) ^ 0x04C11DB7U) : (crc << 1);
        }
    }
    return crc;
}

uint16_t TSDescrambler::FindCADescriptorEcmPID(const uint8_t *desc, size_t descLen, uint16_t caSystemID) noexcept {
    size_t pos = 0;
    while (pos + 2 <= descLen) {
        const uint8_t tag = desc[pos];
        const uint8_t len = desc[pos + 1];
        if (pos + 2 + len > descLen) {
            break;
        }
        if (tag == 0x09U && len >= 4) {
            const uint16_t sysID = static_cast<uint16_t>((desc[pos + 2] << 8) | desc[pos + 3]);
            const uint16_t caPID = static_cast<uint16_t>(((desc[pos + 4] & 0x1FU) << 8) | desc[pos + 5]);
            if (caSystemID == 0 || sysID == caSystemID) {
                return caPID;
            }
        }
        pos += 2 + len;
    }
    return 0xFFFFU;
}

bool TSDescrambler::OpenCard(std::unique_ptr<CardReader> reader, const std::string &readerName) {
    std::lock_guard<std::mutex> lock(m_lock);
    const bool ok = m_card.Open(std::move(reader), readerName);
    m_patAsm.Reset();
    m_catAsm.Reset();
    m_pmtAssemblers.clear();
    m_emmAssemblers.clear();
    m_ecmContexts.clear();
    m_esPidToEcmPid.clear();
    m_stats = DescramblerStats{};
    return ok;
}

void TSDescrambler::CloseCard() {
    std::lock_guard<std::mutex> lock(m_lock);
    m_card.Close();
    m_ecmContexts.clear();
    m_esPidToEcmPid.clear();
}

bool TSDescrambler::IsCardOpen() const {
    std::lock_guard<std::mutex> lock(m_lock);
    return m_card.IsOpen();
}

void TSDescrambler::Reset() {
    std::lock_guard<std::mutex> lock(m_lock);
    m_patAsm.Reset();
    m_catAsm.Reset();
    m_pmtAssemblers.clear();
    m_emmAssemblers.clear();
    m_ecmContexts.clear();
    m_esPidToEcmPid.clear();
    m_stats = DescramblerStats{};
}

CasCardInfo TSDescrambler::GetCardInfo() const {
    std::lock_guard<std::mutex> lock(m_lock);
    return m_card.GetCardInfo();
}

std::string TSDescrambler::GetCardIDText() const {
    std::lock_guard<std::mutex> lock(m_lock);
    return m_card.IsOpen() ? m_card.FormatCardID() : "";
}

std::string TSDescrambler::GetReaderName() const {
    std::lock_guard<std::mutex> lock(m_lock);
    return m_card.GetReaderName();
}

std::string TSDescrambler::GetLastError() const {
    std::lock_guard<std::mutex> lock(m_lock);
    return m_card.GetLastError();
}

DescramblerStats TSDescrambler::GetStats() const {
    std::lock_guard<std::mutex> lock(m_lock);
    return m_stats;
}

TSDescrambler::EcmContext &TSDescrambler::EnsureEcmContext(uint16_t ecmPid) {
    auto it = m_ecmContexts.find(ecmPid);
    if (it != m_ecmContexts.end()) {
        return it->second;
    }
    EcmContext &ctx = m_ecmContexts[ecmPid];
    if (m_card.IsOpen()) {
        const auto &info = m_card.GetCardInfo();
        ctx.decoder.Initialize(info.systemKey, info.initialCbc);
    }
    return ctx;
}

void TSDescrambler::DescramblePackets(uint8_t *data, size_t size) {
    std::lock_guard<std::mutex> lock(m_lock);
    if (!data || size < kTSPacketSize) {
        return;
    }
    size_t pos = 0;
    while (pos + kTSPacketSize <= size) {
        if (data[pos] != 0x47U) {
            ++pos;
            continue;
        }
        ProcessSinglePacket(data + pos);
        pos += kTSPacketSize;
    }
}

void TSDescrambler::ProcessSinglePacket(uint8_t *pkt) {
    ++m_stats.inputPackets;

    // Skip packets with transport_error_indicator set
    if (pkt[1] & 0x80U) {
        return;
    }

    const uint16_t pid = static_cast<uint16_t>(((pkt[1] & 0x1FU) << 8) | pkt[2]);
    const uint8_t scrCtrl = static_cast<uint8_t>((pkt[3] >> 6) & 0x03U);
    const uint8_t afc = static_cast<uint8_t>((pkt[3] >> 4) & 0x03U);

    // Payload-bearing scrambled packet?
    if (scrCtrl == 2U || scrCtrl == 3U) {
        if ((afc & 0x01U) == 0) {
            return;
        }
        size_t payloadOffset = 4;
        if (afc & 0x02U) {
            const size_t afLen = pkt[4];
            payloadOffset = 5 + afLen;
            if (payloadOffset >= kTSPacketSize) {
                return;
            }
        }
        auto esIt = m_esPidToEcmPid.find(pid);
        if (esIt != m_esPidToEcmPid.end()) {
            auto ecmIt = m_ecmContexts.find(esIt->second);
            if (ecmIt != m_ecmContexts.end() && ecmIt->second.hasValidKey) {
                if (ecmIt->second.decoder.Decode(pkt + payloadOffset, kTSPacketSize - payloadOffset, scrCtrl)) {
                    pkt[3] &= 0x3FU; // Clear transport_scrambling_control
                    ++m_stats.descrambledPackets;
                    return;
                }
            }
        }
        ++m_stats.undescrambledPackets;
        return;
    }

    if (scrCtrl != 0 || !m_card.IsOpen()) {
        return;
    }

    // Clear PSI/SI/ECM/EMM tables
    if (pid == 0x0000U) {
        FeedSection(m_patAsm, pkt, &TSDescrambler::OnPATSection);
    } else if (pid == 0x0001U) {
        if (m_enableEmm) {
            FeedSection(m_catAsm, pkt, &TSDescrambler::OnCATSection);
        }
    } else {
        auto pmtIt = m_pmtAssemblers.find(pid);
        if (pmtIt != m_pmtAssemblers.end()) {
            FeedSection(pmtIt->second, pkt, &TSDescrambler::OnPMTSection);
            return;
        }
        auto ecmIt = m_ecmContexts.find(pid);
        if (ecmIt != m_ecmContexts.end()) {
            FeedSection(ecmIt->second.assembler, pkt, &TSDescrambler::OnECMSection);
            return;
        }
        if (m_enableEmm) {
            auto emmIt = m_emmAssemblers.find(pid);
            if (emmIt != m_emmAssemblers.end()) {
                FeedSection(emmIt->second, pkt, &TSDescrambler::OnEMMSection);
            }
        }
    }
}

void TSDescrambler::FeedSection(
    SectionAssembler &asmbl, const uint8_t *pkt,
    void (TSDescrambler::*onSection)(uint16_t pid, const uint8_t *sec, size_t len)) {
    const uint8_t afc = static_cast<uint8_t>((pkt[3] >> 4) & 0x03U);
    if ((afc & 0x01U) == 0) {
        return;
    }
    size_t pos = 4;
    if (afc & 0x02U) {
        pos = 5 + pkt[4];
        if (pos >= kTSPacketSize) {
            return;
        }
    }

    const uint16_t pid = static_cast<uint16_t>(((pkt[1] & 0x1FU) << 8) | pkt[2]);
    const bool pusi = (pkt[1] & 0x40U) != 0;

    if (pusi) {
        const size_t ptr = pkt[pos++];
        if (pos + ptr > kTSPacketSize) {
            asmbl.Reset();
            return;
        }
        if (asmbl.collecting && ptr > 0) {
            asmbl.buf.insert(asmbl.buf.end(), pkt + pos, pkt + pos + ptr);
            if (asmbl.expectedLength > 0 && asmbl.buf.size() >= asmbl.expectedLength) {
                (this->*onSection)(pid, asmbl.buf.data(), asmbl.expectedLength);
            }
        }
        pos += ptr;
        asmbl.Reset();
        if (pos + 3 > kTSPacketSize || pkt[pos] == 0xFFU) {
            return;
        }
        const size_t secLen = static_cast<size_t>(((pkt[pos + 1] & 0x0FU) << 8) | pkt[pos + 2]);
        const size_t totalLen = 3 + secLen;
        if (totalLen > 4096) {
            return;
        }
        asmbl.expectedLength = totalLen;
        asmbl.collecting = true;
        const size_t avail = kTSPacketSize - pos;
        const size_t copy = std::min(avail, totalLen);
        asmbl.buf.assign(pkt + pos, pkt + pos + copy);
        if (asmbl.buf.size() >= asmbl.expectedLength) {
            (this->*onSection)(pid, asmbl.buf.data(), asmbl.expectedLength);
            asmbl.Reset();
        }
    } else if (asmbl.collecting) {
        const size_t avail = kTSPacketSize - pos;
        const size_t remain = (asmbl.expectedLength > asmbl.buf.size())
            ? (asmbl.expectedLength - asmbl.buf.size()) : 0;
        const size_t copy = std::min(avail, remain);
        asmbl.buf.insert(asmbl.buf.end(), pkt + pos, pkt + pos + copy);
        if (asmbl.buf.size() >= asmbl.expectedLength) {
            (this->*onSection)(pid, asmbl.buf.data(), asmbl.expectedLength);
            asmbl.Reset();
        }
    }
}

void TSDescrambler::OnPATSection(uint16_t, const uint8_t *sec, size_t len) {
    if (len < 12 || sec[0] != 0x00U || (sec[5] & 0x01U) == 0) {
        return;
    }
    if (CalcCRC32MPEG2(sec, len) != 0) {
        return;
    }
    const size_t entriesEnd = len - 4;
    for (size_t i = 8; i + 4 <= entriesEnd; i += 4) {
        const uint16_t programNum = static_cast<uint16_t>((sec[i] << 8) | sec[i + 1]);
        const uint16_t pmtPid = static_cast<uint16_t>(((sec[i + 2] & 0x1FU) << 8) | sec[i + 3]);
        if (programNum != 0 && pmtPid != 0 && pmtPid < 0x1FFFU) {
            m_pmtAssemblers.try_emplace(pmtPid);
        }
    }
}

void TSDescrambler::OnCATSection(uint16_t, const uint8_t *sec, size_t len) {
    if (len < 12 || sec[0] != 0x01U || (sec[5] & 0x01U) == 0) {
        return;
    }
    if (CalcCRC32MPEG2(sec, len) != 0) {
        return;
    }
    const uint16_t caSysID = m_card.GetCardInfo().caSystemID;
    const uint16_t emmPid = FindCADescriptorEcmPID(sec + 8, len - 12, caSysID);
    if (emmPid != 0xFFFFU && emmPid < 0x1FFFU) {
        m_emmAssemblers.try_emplace(emmPid);
    }
}

void TSDescrambler::OnPMTSection(uint16_t, const uint8_t *sec, size_t len) {
    if (len < 16 || sec[0] != 0x02U || (sec[5] & 0x01U) == 0) {
        return;
    }
    if (CalcCRC32MPEG2(sec, len) != 0) {
        return;
    }
    const uint16_t caSysID = m_card.GetCardInfo().caSystemID;
    const size_t progInfoLen = static_cast<size_t>(((sec[10] & 0x0FU) << 8) | sec[11]);
    if (12 + progInfoLen + 4 > len) {
        return;
    }
    const uint16_t progEcmPid = FindCADescriptorEcmPID(sec + 12, progInfoLen, caSysID);
    if (progEcmPid != 0xFFFFU) {
        EnsureEcmContext(progEcmPid);
    }

    size_t pos = 12 + progInfoLen;
    const size_t end = len - 4;
    while (pos + 5 <= end) {
        const uint16_t esPid = static_cast<uint16_t>(((sec[pos + 1] & 0x1FU) << 8) | sec[pos + 2]);
        const size_t esInfoLen = static_cast<size_t>(((sec[pos + 3] & 0x0FU) << 8) | sec[pos + 4]);
        if (pos + 5 + esInfoLen > end) {
            break;
        }
        uint16_t esEcmPid = FindCADescriptorEcmPID(sec + pos + 5, esInfoLen, caSysID);
        if (esEcmPid == 0xFFFFU) {
            esEcmPid = progEcmPid;
        }
        if (esEcmPid != 0xFFFFU) {
            EnsureEcmContext(esEcmPid);
            m_esPidToEcmPid[esPid] = esEcmPid;
        }
        pos += 5 + esInfoLen;
    }
}

void TSDescrambler::OnECMSection(uint16_t pid, const uint8_t *sec, size_t len) {
    // ARIB STD-B25 ECM table_id is 0x82 (or 0x83).
    // Most Japanese ISDB broadcasts use short section format (section_syntax_indicator == 0:
    // 3-byte header, no CRC-32), while extended format (SSI == 1) has 8-byte header + 4-byte CRC-32.
    if (len < 3 || (sec[0] != 0x82U && sec[0] != 0x83U)) {
        return;
    }
    const bool isExtended = (sec[1] & 0x80U) != 0;
    const uint8_t *ecmBody = nullptr;
    size_t ecmBodyLen = 0;
    if (isExtended) {
        if (len < 12 || (sec[5] & 0x01U) == 0 || CalcCRC32MPEG2(sec, len) != 0) {
            return;
        }
        ecmBody = sec + 8;
        ecmBodyLen = len - 12;
    } else {
        ecmBody = sec + 3;
        ecmBodyLen = len - 3;
    }
    if (ecmBodyLen < CasCard::kMinEcmSize || ecmBodyLen > CasCard::kMaxEcmSize) {
        return;
    }

    EcmContext &ctx = EnsureEcmContext(pid);
    if (ctx.lastEcmPayload.size() == ecmBodyLen &&
        std::memcmp(ctx.lastEcmPayload.data(), ecmBody, ecmBodyLen) == 0) {
        return;
    }

    ctx.lastEcmPayload.assign(ecmBody, ecmBody + ecmBodyLen);
    const uint8_t *ks = m_card.GetKsFromEcm(ecmBody, ecmBodyLen);
    if (ks != nullptr) {
        ctx.decoder.SetScrambleKey(ks);
        ctx.hasValidKey = true;
        ++m_stats.ecmCount;
    } else {
        ctx.decoder.ClearScrambleKey();
        ctx.hasValidKey = false;
        ++m_stats.ecmErrorCount;
    }
}

void TSDescrambler::OnEMMSection(uint16_t, const uint8_t *sec, size_t len) {
    if (!m_enableEmm || len < 10 || sec[0] != 0x84U) {
        return;
    }
    const bool isExtended = (sec[1] & 0x80U) != 0;
    size_t pos = 0;
    size_t end = 0;
    if (isExtended) {
        if (len < 12 || (sec[5] & 0x01U) == 0 || CalcCRC32MPEG2(sec, len) != 0) {
            return;
        }
        pos = 8;
        end = len - 4;
    } else {
        pos = 3;
        end = len;
    }
    const uint8_t *cardID = m_card.GetCardInfo().cardID;
    while (pos + 7 <= end) {
        const size_t payloadLen = sec[pos + 6];
        const size_t msgLen = 7 + payloadLen;
        if (pos + msgLen > end) {
            break;
        }
        if (std::memcmp(sec + pos, cardID, 6) == 0) {
            if (m_card.SendEmmSection(sec + pos, msgLen)) {
                ++m_stats.emmCount;
            }
        }
        pos += msgLen;
    }
}

} // namespace TvCasMac
