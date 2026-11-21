// SPDX-License-Identifier: GPL-2.0-or-later
#import <Foundation/Foundation.h>

#include "CardReaderMac.hpp"
#include "CasCardMac.hpp"
#include "Multi2DecoderMac.hpp"
#include "TSDescramblerMac.hpp"
#import "TVTestCasBridge.h"

#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

using namespace TvCasMac;

static int gFailures = 0;

#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            std::fprintf(stderr, "FAIL [%s:%d]: %s\n", __FILE__, __LINE__,     \
                         (msg));                                               \
            ++gFailures;                                                       \
        }                                                                      \
    } while (0)

namespace {

static const uint8_t kTestSystemKey[32] = {
    0x36, 0x31, 0x04, 0x66, 0x4b, 0x17, 0xea, 0x5c,
    0x32, 0xdf, 0x9c, 0xf5, 0xc4, 0xc3, 0x6c, 0x1b,
    0xec, 0x99, 0x39, 0x21, 0x68, 0x9d, 0x4b, 0xb7,
    0xb7, 0x4e, 0x40, 0x84, 0x0d, 0x2e, 0x7d, 0x98,
};

static const uint8_t kTestInitialCbc[8] = {
    0xfe, 0x27, 0x19, 0x99, 0x19, 0x69, 0x09, 0x11,
};

static const uint8_t kTestScrambleKey[16] = {
    // Odd (8 bytes)
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    // Even (8 bytes)
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x23,
};

// Mock B-CAS card reader implementing ARIB STD-B25 APDUs:
// - 0x90 0x30 (Initial Setting)
// - 0x90 0x32 (Card ID Info)
// - 0x90 0x34 (ECM)
// - 0x90 0x36 (EMM)
class MockBCasReader final : public CardReader {
public:
    bool refuseNextEcm = false;
    int ecmTxCount = 0;
    int emmTxCount = 0;

    bool Open(const std::string &readerName = "") override {
        m_name = readerName.empty() ? "Mock B-CAS Reader" : readerName;
        m_open = true;
        return true;
    }
    void Close() override { m_open = false; }
    bool IsOpen() const override { return m_open; }
    std::string GetReaderName() const override { return m_name; }
    std::string GetLastError() const override { return ""; }

    bool Transmit(const uint8_t *sendData, size_t sendSize,
                  uint8_t *recvData, size_t *recvSize) override {
        if (!m_open || !sendData || sendSize < 4 || !recvData || !recvSize) {
            return false;
        }
        const uint8_t cla = sendData[0];
        const uint8_t ins = sendData[1];
        if (cla != 0x90) {
            return false;
        }

        if (ins == 0x30) {
            // Initial Setting response: 57 bytes + SW1 SW2 = 59 bytes
            std::vector<uint8_t> resp(59, 0x00);
            resp[0] = 0x00;
            resp[1] = 0x37; // unit length
            resp[2] = 0x00;
            resp[3] = 0x00;
            resp[4] = 0x21; // Return code: 0x2100 = OK
            resp[5] = 0x00;
            resp[6] = 0x00; // CA_system_ID = 0x0005 (ARIB)
            resp[7] = 0x05;
            // Card ID (6 bytes): 0x00 0x00 0x01 0x02 0x03 0x04 -> 0000 0016 9090 60
            resp[8] = 0x00;
            resp[9] = 0x00;
            resp[10] = 0x01;
            resp[11] = 0x02;
            resp[12] = 0x03;
            resp[13] = 0x04;
            resp[14] = 0x01; // Card type
            resp[15] = 0x00; // Message partition length
            std::memcpy(resp.data() + 16, kTestSystemKey, 32);
            std::memcpy(resp.data() + 48, kTestInitialCbc, 8);
            resp[56] = 0x00;
            resp[57] = 0x90;
            resp[58] = 0x00;
            if (*recvSize < resp.size()) return false;
            std::memcpy(recvData, resp.data(), resp.size());
            *recvSize = resp.size();
            return true;
        }

        if (ins == 0x32) {
            // Card ID info
            std::vector<uint8_t> resp(19, 0x00);
            resp[4] = 0x21;
            resp[5] = 0x00;
            resp[6] = 0x01; // count
            resp[7] = 'M';  // manufacturer ID
            resp[8] = 0x04; // card version
            // 6-byte card ID at [9..14]
            resp[9] = 0x00;
            resp[10] = 0x00;
            resp[11] = 0x01;
            resp[12] = 0x02;
            resp[13] = 0x03;
            resp[14] = 0x04;
            resp[15] = 0x12; // check code
            resp[16] = 0x34;
            resp[17] = 0x90;
            resp[18] = 0x00;
            if (*recvSize < resp.size()) return false;
            std::memcpy(recvData, resp.data(), resp.size());
            *recvSize = resp.size();
            return true;
        }

        if (ins == 0x34) {
            ++ecmTxCount;
            std::vector<uint8_t> resp(25, 0x00);
            if (refuseNextEcm) {
                resp[4] = 0xA1; // Not contracted / error
                resp[5] = 0x02;
            } else {
                resp[4] = 0x08; // OK (0x0800)
                resp[5] = 0x00;
                std::memcpy(resp.data() + 6, kTestScrambleKey, 16);
            }
            resp[23] = 0x90;
            resp[24] = 0x00;
            if (*recvSize < resp.size()) return false;
            std::memcpy(recvData, resp.data(), resp.size());
            *recvSize = resp.size();
            return true;
        }

        if (ins == 0x36) {
            ++emmTxCount;
            uint8_t resp[8] = {0x00, 0x04, 0x00, 0x00, 0x21, 0x00, 0x90, 0x00};
            if (*recvSize < sizeof(resp)) return false;
            std::memcpy(recvData, resp, sizeof(resp));
            *recvSize = sizeof(resp);
            return true;
        }

        return false;
    }

private:
    bool m_open = false;
    std::string m_name;
};

static uint32_t CalcCRC32(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) {
        crc ^= static_cast<uint32_t>(data[i]) << 24;
        for (int b = 0; b < 8; ++b) {
            crc = (crc & 0x80000000u) ? ((crc << 1) ^ 0x04C11DB7u) : (crc << 1);
        }
    }
    return crc;
}

static std::vector<uint8_t> MakeSectionPacket(uint16_t pid, uint8_t cc,
                                              const std::vector<uint8_t> &sectionWithCrc) {
    std::vector<uint8_t> pkt(188, 0xFF);
    pkt[0] = 0x47;
    pkt[1] = static_cast<uint8_t>(0x40 | ((pid >> 8) & 0x1F)); // PUSI = 1
    pkt[2] = static_cast<uint8_t>(pid & 0xFF);
    pkt[3] = static_cast<uint8_t>(0x10 | (cc & 0x0F)); // payload only
    pkt[4] = 0x00; // pointer_field
    std::memcpy(pkt.data() + 5, sectionWithCrc.data(), sectionWithCrc.size());
    return pkt;
}

static void AppendCRC(std::vector<uint8_t> &sec) {
    const uint32_t crc = CalcCRC32(sec.data(), sec.size());
    sec.push_back(static_cast<uint8_t>((crc >> 24) & 0xFF));
    sec.push_back(static_cast<uint8_t>((crc >> 16) & 0xFF));
    sec.push_back(static_cast<uint8_t>((crc >> 8) & 0xFF));
    sec.push_back(static_cast<uint8_t>(crc & 0xFF));
}

} // namespace

// Objective-C mock transport matching TVCasSmartCardTransport (like MacBonDriverSmartCard)
@interface MockSmartCardTransport : NSObject <TVCasSmartCardTransport>
@property (nonatomic, assign, getter=isCardOpen) BOOL cardOpen;
@end

@implementation MockSmartCardTransport {
    MockBCasReader _reader;
}

- (NSString *)cardReaderName {
    return @"XIT-SQR100 Mock Built-in B-CAS";
}

- (BOOL)openSmartCardWithError:(NSError * _Nullable * _Nullable)error {
    (void)error;
    self.cardOpen = _reader.Open("XIT-SQR100 Mock Built-in B-CAS");
    return self.cardOpen;
}

- (void)closeSmartCard {
    _reader.Close();
    self.cardOpen = NO;
}

- (nullable NSData *)transmitAPDU:(NSData *)commandAPDU
                            error:(NSError * _Nullable * _Nullable)error {
    uint8_t recv[512] = {};
    size_t recvLen = sizeof(recv);
    if (!_reader.Transmit(static_cast<const uint8_t *>(commandAPDU.bytes),
                          commandAPDU.length, recv, &recvLen)) {
        if (error) {
            *error = [NSError errorWithDomain:@"MockSmartCard" code:1 userInfo:nil];
        }
        return nil;
    }
    return [NSData dataWithBytes:recv length:recvLen];
}

@end

static void TestMulti2RoundTrip() {
    Multi2Decoder dec;
    CHECK(dec.Initialize(kTestSystemKey, kTestInitialCbc), "Multi2 Initialize");
    CHECK(dec.SetScrambleKey(kTestScrambleKey), "Multi2 SetScrambleKey");

    const size_t lengths[] = {184, 181, 16, 13, 8, 7, 1};
    const uint8_t modes[] = {2, 3}; // Even, Odd

    for (uint8_t mode : modes) {
        for (size_t len : lengths) {
            std::vector<uint8_t> plain(len);
            for (size_t i = 0; i < len; ++i) {
                plain[i] = static_cast<uint8_t>((i * 37 + mode * 13 + 7) & 0xFF);
            }
            std::vector<uint8_t> buf = plain;
            CHECK(dec.Encode(buf.data(), buf.size(), mode), "Multi2 Encode");
            if (len >= 1) {
                CHECK(buf != plain, "Multi2 ciphertext differs from plaintext");
            }
            CHECK(dec.Decode(buf.data(), buf.size(), mode), "Multi2 Decode");
            CHECK(buf == plain, "Multi2 round-trip matches plaintext");
        }
    }

    // Unscrambled mode (0) is a no-op
    std::vector<uint8_t> plain(184, 0x5A);
    std::vector<uint8_t> buf = plain;
    CHECK(dec.Decode(buf.data(), buf.size(), 0), "Multi2 Decode mode 0");
    CHECK(buf == plain, "Multi2 mode 0 leaves buffer unchanged");
}

static void TestCasCardProtocol() {
    auto rawReader = std::make_unique<MockBCasReader>();
    MockBCasReader *readerPtr = rawReader.get();

    CasCard card;
    CHECK(card.Open(std::move(rawReader)), "CasCard Open");
    CHECK(card.IsOpen(), "CasCard IsOpen");
    CHECK(card.GetCardInfo().caSystemID == 0x0005, "CA_system_ID == 0x0005");
    CHECK(card.GetCardInfo().cardManufacturerID == 'M', "Card manufacturer ID");
    CHECK(card.GetCardInfo().cardVersion == 0x04, "Card version");
    CHECK(card.GetCardInfo().checkCode == 0x1234, "Check code");

    const std::string formattedId = card.FormatCardID();
    CHECK(formattedId.size() == 24, "Formatted Card ID has 20 digits + 4 spaces");

    std::vector<uint8_t> ecm(36, 0x42);
    const uint8_t *ks1 = card.GetKsFromEcm(ecm.data(), ecm.size());
    CHECK(ks1 != nullptr, "First ECM succeeds");
    CHECK(ks1 && std::memcmp(ks1, kTestScrambleKey, 16) == 0, "Ks matches");
    CHECK(readerPtr->ecmTxCount == 1, "ECM sent once");

    // Identical ECM should hit cache without re-transmitting
    const uint8_t *ks2 = card.GetKsFromEcm(ecm.data(), ecm.size());
    CHECK(ks2 != nullptr, "Cached ECM succeeds");
    CHECK(readerPtr->ecmTxCount == 1, "Cached ECM did not re-transmit");

    // Different ECM with refusal
    ecm[0] = 0x43;
    readerPtr->refuseNextEcm = true;
    const uint8_t *ks3 = card.GetKsFromEcm(ecm.data(), ecm.size());
    CHECK(ks3 == nullptr, "Refused ECM returns nullptr");
    CHECK(readerPtr->ecmTxCount == 2, "Refused ECM was transmitted");

    // EMM send
    std::vector<uint8_t> emm(40, 0x99);
    CHECK(card.SendEmmSection(emm.data(), emm.size()), "SendEmmSection succeeds");
    CHECK(readerPtr->emmTxCount == 1, "EMM transmitted");

    card.Close();
    CHECK(!card.IsOpen(), "CasCard closed");
}

static void TestTSDescramblerEndToEnd() {
    TSDescrambler descrambler;
    CHECK(descrambler.OpenCard(std::make_unique<MockBCasReader>()), "TSDescrambler OpenCard");

    // 1. PAT (PID 0x0000): program 0x0400 -> PMT PID 0x0100
    std::vector<uint8_t> pat = {
        0x00,                   // table_id = PAT
        0xB0, 0x0D,             // section_length = 13 (9 + 4 CRC)
        0x00, 0x01,             // TSID
        0xC1, 0x00, 0x00,       // version 0, current=1, sec 0, last 0
        0x04, 0x00,             // program_number = 0x0400
        0xE1, 0x00,             // PMT PID = 0x0100
    };
    AppendCRC(pat);
    auto patPkt = MakeSectionPacket(0x0000, 0, pat);

    // 2. PMT (PID 0x0100): program-level CA_descriptor (system 0x0005, ECM PID 0x0200),
    //    elementary video PID 0x0111
    std::vector<uint8_t> pmt = {
        0x02,                   // table_id = PMT
        0xB0, 0x18,             // section_length = 24 (20 + 4 CRC)
        0x04, 0x00,             // program_number = 0x0400
        0xC1, 0x00, 0x00,       // version 0, current=1
        0xE1, 0x11,             // PCR_PID = 0x0111
        0xF0, 0x06,             // program_info_length = 6
        0x09, 0x04, 0x00, 0x05, 0xE2, 0x00, // CA_descriptor: sys 0x0005, ECM PID 0x0200
        0x02,                   // stream_type = MPEG-2 video
        0xE1, 0x11,             // elementary_PID = 0x0111
        0xF0, 0x00,             // ES_info_length = 0
    };
    AppendCRC(pmt);
    auto pmtPkt = MakeSectionPacket(0x0100, 0, pmt);

    // 3. ECM (PID 0x0200): ARIB STD-B25 short section (table_id 0x82, SSI=0, 36B body, no CRC)
    std::vector<uint8_t> ecmSec = {
        0x82,                   // table_id = ECM
        0x70, 0x24,             // SSI = 0, section_length = 36
    };
    for (int i = 0; i < 36; ++i) {
        ecmSec.push_back(static_cast<uint8_t>(0x10 + i));
    }
    auto ecmPkt = MakeSectionPacket(0x0200, 0, ecmSec);

    // 4. Scrambled video packets (PID 0x0111) with Even (2) and Odd (3) keys
    Multi2Decoder enc;
    CHECK(enc.Initialize(kTestSystemKey, kTestInitialCbc), "Encoder init");
    CHECK(enc.SetScrambleKey(kTestScrambleKey), "Encoder key");

    auto makeScrambledEs = [&](uint8_t cc, uint8_t scrCtrl, std::vector<uint8_t> &expectedPayload) {
        std::vector<uint8_t> pkt(188, 0x00);
        pkt[0] = 0x47;
        pkt[1] = 0x01;
        pkt[2] = 0x11; // PID 0x0111
        pkt[3] = static_cast<uint8_t>((scrCtrl << 6) | 0x10 | (cc & 0x0F));
        expectedPayload.resize(184);
        for (size_t i = 0; i < 184; ++i) {
            expectedPayload[i] = static_cast<uint8_t>((i + cc * 29) & 0xFF);
        }
        std::memcpy(pkt.data() + 4, expectedPayload.data(), 184);
        CHECK(enc.Encode(pkt.data() + 4, 184, scrCtrl), "Encrypt ES payload");
        return pkt;
    };

    std::vector<uint8_t> expectedEven, expectedOdd;
    auto esEvenPkt = makeScrambledEs(1, 2, expectedEven);
    auto esOddPkt = makeScrambledEs(2, 3, expectedOdd);

    // Concatenate into a single TS buffer and descramble in-place
    std::vector<uint8_t> stream;
    stream.insert(stream.end(), patPkt.begin(), patPkt.end());
    stream.insert(stream.end(), pmtPkt.begin(), pmtPkt.end());
    stream.insert(stream.end(), ecmPkt.begin(), ecmPkt.end());
    stream.insert(stream.end(), esEvenPkt.begin(), esEvenPkt.end());
    stream.insert(stream.end(), esOddPkt.begin(), esOddPkt.end());

    descrambler.DescramblePackets(stream.data(), stream.size());

    const uint8_t *outEven = stream.data() + 3 * 188;
    const uint8_t *outOdd = stream.data() + 4 * 188;
    CHECK((outEven[3] & 0xC0) == 0, "Even packet scrambling control cleared");
    CHECK((outOdd[3] & 0xC0) == 0, "Odd packet scrambling control cleared");
    CHECK(std::memcmp(outEven + 4, expectedEven.data(), 184) == 0, "Even payload descrambled exactly");
    CHECK(std::memcmp(outOdd + 4, expectedOdd.data(), 184) == 0, "Odd payload descrambled exactly");

    const DescramblerStats st = descrambler.GetStats();
    CHECK(st.inputPackets == 5, "Input packet count == 5");
    CHECK(st.descrambledPackets == 2, "Descrambled packet count == 2");
    CHECK(st.undescrambledPackets == 0, "Undescrambled packet count == 0");
    CHECK(st.ecmCount == 1, "ECM count == 1");
    CHECK(st.ecmErrorCount == 0, "ECM error count == 0");
}

static void TestObjCBridgeAndPCSC() {
    @autoreleasepool {
        // Verify PCSC reader enumeration does not crash (0 or more readers depending on hardware)
        NSArray<NSString *> *readers = [TVTestCasSession availablePCSCReaders];
        CHECK(readers != nil, "availablePCSCReaders returns non-nil array");

        // Test TVTestCasSession with mock MacBonDriverSmartCard transport
        MockSmartCardTransport *transport = [[MockSmartCardTransport alloc] init];
        TVTestCasSession *session = [[TVTestCasSession alloc] init];
        NSError *err = nil;
        BOOL ok = [session openWithSmartCardTransport:transport error:&err];
        CHECK(ok && err == nil, "TVTestCasSession openWithSmartCardTransport");
        CHECK(session.isOpen, "TVTestCasSession isOpen");
        CHECK(session.caSystemID == 0x0005, "TVTestCasSession caSystemID == 0x0005");
        CHECK([session.readerName isEqualToString:@"XIT-SQR100 Mock Built-in B-CAS"],
              "TVTestCasSession readerName matches");
        CHECK(session.cardIDText.length == 24, "TVTestCasSession cardIDText formatted");

        [session close];
        CHECK(!session.isOpen, "TVTestCasSession closed");
    }
}

int main() {
    TestMulti2RoundTrip();
    TestCasCardProtocol();
    TestTSDescramblerEndToEnd();
    TestObjCBridgeAndPCSC();

    if (gFailures == 0) {
        std::printf("TvCasTests: ALL PASSED\n");
        return 0;
    }
    std::fprintf(stderr, "TvCasTests: %d FAILURE(S)\n", gFailures);
    return 1;
}
