// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once

#include "CasCardMac.hpp"
#include "Multi2DecoderMac.hpp"

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <vector>

namespace TvCasMac {

struct DescramblerStats {
    uint64_t inputPackets = 0;
    uint64_t descrambledPackets = 0;
    uint64_t undescrambledPackets = 0;
    uint64_t ecmCount = 0;
    uint64_t ecmErrorCount = 0;
    uint64_t emmCount = 0;
};

class TSDescrambler {
public:
    static constexpr size_t kTSPacketSize = 188;

    TSDescrambler() = default;

    bool OpenCard(std::unique_ptr<CardReader> reader, const std::string &readerName = "");
    void CloseCard();
    bool IsCardOpen() const;

    void Reset();
    void SetEnableEmmProcess(bool enable) noexcept { m_enableEmm = enable; }
    bool IsEnableEmmProcess() const noexcept { return m_enableEmm; }

    CasCardInfo GetCardInfo() const;
    std::string GetCardIDText() const;
    std::string GetReaderName() const;
    std::string GetLastError() const;
    DescramblerStats GetStats() const;

    // Processes an array of 188-byte TS packets in-place.
    void DescramblePackets(uint8_t *data, size_t size);

private:
    struct SectionAssembler {
        std::vector<uint8_t> buf;
        size_t expectedLength = 0;
        bool collecting = false;
        void Reset() { buf.clear(); expectedLength = 0; collecting = false; }
    };

    struct EcmContext {
        SectionAssembler assembler;
        Multi2Decoder decoder;
        std::vector<uint8_t> lastEcmPayload;
        bool hasValidKey = false;
    };

    void ProcessSinglePacket(uint8_t *pkt);
    void FeedSection(SectionAssembler &asmbl, const uint8_t *pkt,
                     void (TSDescrambler::*onSection)(uint16_t pid, const uint8_t *sec, size_t len));
    void OnPATSection(uint16_t pid, const uint8_t *sec, size_t len);
    void OnCATSection(uint16_t pid, const uint8_t *sec, size_t len);
    void OnPMTSection(uint16_t pid, const uint8_t *sec, size_t len);
    void OnECMSection(uint16_t pid, const uint8_t *sec, size_t len);
    void OnEMMSection(uint16_t pid, const uint8_t *sec, size_t len);
    EcmContext &EnsureEcmContext(uint16_t ecmPid);

    static uint32_t CalcCRC32MPEG2(const uint8_t *data, size_t len) noexcept;
    static uint16_t FindCADescriptorEcmPID(const uint8_t *desc, size_t descLen, uint16_t caSystemID) noexcept;

    mutable std::mutex m_lock;
    CasCard m_card;
    bool m_enableEmm = false;
    DescramblerStats m_stats;

    SectionAssembler m_patAsm;
    SectionAssembler m_catAsm;
    std::map<uint16_t, SectionAssembler> m_pmtAssemblers;
    std::map<uint16_t, SectionAssembler> m_emmAssemblers;
    std::map<uint16_t, EcmContext> m_ecmContexts;
    std::map<uint16_t, uint16_t> m_esPidToEcmPid;
};

} // namespace TvCasMac
