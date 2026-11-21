// SPDX-License-Identifier: GPL-2.0-or-later
#import "TVTestCasBridge.h"
#include "TSDescramblerMac.hpp"
#include <cstring>

namespace {

NSError *MakeCasError(NSString *message) {
    return [NSError errorWithDomain:@"jp.tvcas.macos.error"
                               code:1
                           userInfo:@{NSLocalizedDescriptionKey: message ?: @"TvCas error"}];
}

class TransportCardReader final : public TvCasMac::CardReader {
public:
    explicit TransportCardReader(id<TVCasSmartCardTransport> transport)
        : m_transport(transport) {}

    ~TransportCardReader() override { Close(); }

    bool Open(const std::string &) override {
        if (!m_transport) {
            m_lastError = "スマートカードトランスポートがありません";
            return false;
        }
        if (!m_transport.isCardOpen) {
            NSError *err = nil;
            if (![m_transport openSmartCardWithError:&err]) {
                m_lastError = err.localizedDescription.UTF8String ?: "内蔵スマートカードを開けませんでした";
                return false;
            }
            m_openedByUs = true;
        }
        m_open = true;
        m_lastError.clear();
        return true;
    }

    void Close() override {
        if (m_openedByUs && m_transport) {
            [m_transport closeSmartCard];
        }
        m_openedByUs = false;
        m_open = false;
    }

    bool IsOpen() const override {
        return m_open && m_transport && m_transport.isCardOpen;
    }

    std::string GetReaderName() const override {
        NSString *name = m_transport.cardReaderName;
        return name.length ? std::string(name.UTF8String) : "MacBonDriver Built-in Reader";
    }

    std::string GetLastError() const override { return m_lastError; }

    bool Transmit(const uint8_t *sendData, size_t sendSize,
                  uint8_t *recvData, size_t *recvSize) override {
        if (!IsOpen() || !sendData || !recvData || !recvSize) {
            m_lastError = "スマートカードが開かれていません";
            return false;
        }
        NSData *cmd = [NSData dataWithBytes:sendData length:sendSize];
        NSError *err = nil;
        NSData *resp = [m_transport transmitAPDU:cmd error:&err];
        if (!resp || resp.length == 0) {
            m_lastError = err.localizedDescription.UTF8String ?: "APDU 送信に失敗しました";
            return false;
        }
        if (resp.length > *recvSize) {
            m_lastError = "受信バッファが不足しています";
            return false;
        }
        std::memcpy(recvData, resp.bytes, resp.length);
        *recvSize = resp.length;
        return true;
    }

private:
    id<TVCasSmartCardTransport> m_transport;
    bool m_openedByUs = false;
    bool m_open = false;
    std::string m_lastError;
};

} // namespace

@implementation TVTestCasSession {
    TvCasMac::TSDescrambler _descrambler;
}

+ (NSArray<NSString *> *)availablePCSCReaders {
    auto list = TvCasMac::CardReader::EnumeratePCSCReaders();
    NSMutableArray<NSString *> *out = [NSMutableArray arrayWithCapacity:list.size()];
    for (const auto &name : list) {
        NSString *ns = [NSString stringWithUTF8String:name.c_str()];
        if (ns.length) [out addObject:ns];
    }
    return out;
}

- (BOOL)isOpen { return _descrambler.IsCardOpen(); }

- (NSString *)readerName {
    auto s = _descrambler.GetReaderName();
    return [NSString stringWithUTF8String:s.c_str()] ?: @"";
}

- (NSString *)cardIDText {
    auto s = _descrambler.GetCardIDText();
    return [NSString stringWithUTF8String:s.c_str()] ?: @"";
}

- (uint16_t)caSystemID { return _descrambler.GetCardInfo().caSystemID; }
- (uint8_t)cardType { return _descrambler.GetCardInfo().cardType; }

- (BOOL)enableEMMProcess { return _descrambler.IsEnableEmmProcess(); }
- (void)setEnableEMMProcess:(BOOL)enableEMMProcess {
    _descrambler.SetEnableEmmProcess(enableEMMProcess);
}

- (uint64_t)descrambledPackets { return _descrambler.GetStats().descrambledPackets; }
- (uint64_t)undescrambledPackets { return _descrambler.GetStats().undescrambledPackets; }
- (uint64_t)ecmCount { return _descrambler.GetStats().ecmCount; }
- (uint64_t)ecmErrorCount { return _descrambler.GetStats().ecmErrorCount; }
- (uint64_t)emmCount { return _descrambler.GetStats().emmCount; }

- (BOOL)openWithSmartCardTransport:(id)transport error:(NSError **)error {
    if (!transport ||
        ![transport respondsToSelector:@selector(openSmartCardWithError:)] ||
        ![transport respondsToSelector:@selector(transmitAPDU:error:)]) {
        if (error) *error = MakeCasError(@"有効な MacBonDriverSmartCard インターフェースではありません。");
        return NO;
    }
    auto reader = std::make_unique<TransportCardReader>((id<TVCasSmartCardTransport>)transport);
    if (!_descrambler.OpenCard(std::move(reader))) {
        if (error) {
            auto msg = _descrambler.GetLastError();
            *error = MakeCasError(msg.empty() ? @"B-CAS カードの初期化に失敗しました。"
                                              : [NSString stringWithUTF8String:msg.c_str()]);
        }
        return NO;
    }
    return YES;
}

- (BOOL)openWithPCSCReaderName:(nullable NSString *)readerName error:(NSError **)error {
    auto reader = TvCasMac::CardReader::CreatePCSCReader();
    std::string target = readerName.length ? std::string(readerName.UTF8String) : "";
    if (!_descrambler.OpenCard(std::move(reader), target)) {
        if (error) {
            auto msg = _descrambler.GetLastError();
            *error = MakeCasError(msg.empty() ? @"PC/SC B-CAS カードの初期化に失敗しました。"
                                              : [NSString stringWithUTF8String:msg.c_str()]);
        }
        return NO;
    }
    return YES;
}

- (void)close { _descrambler.CloseCard(); }
- (void)reset { _descrambler.Reset(); }

- (void)descrambleTSBytes:(uint8_t *)bytes length:(NSUInteger)length {
    _descrambler.DescramblePackets(bytes, static_cast<size_t>(length));
}

@end
