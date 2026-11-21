// SPDX-License-Identifier: GPL-2.0-or-later
#include "CardReaderMac.hpp"

#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>
#include <cstring>
#include <mutex>

namespace TvCasMac {

namespace {

class PCSCCardReader final : public CardReader {
public:
    PCSCCardReader() = default;
    ~PCSCCardReader() override { Close(); }

    bool Open(const std::string &readerName) override {
        std::lock_guard<std::mutex> lock(m_lock);
        CloseLocked();

        LONG rc = SCardEstablishContext(SCARD_SCOPE_USER, nullptr, nullptr, &m_context);
        if (rc != SCARD_S_SUCCESS) {
            m_lastError = "SCardEstablishContext failed";
            return false;
        }

        std::vector<std::string> readers = EnumerateLocked(m_context);
        if (readers.empty()) {
            m_lastError = "PC/SC スマートカードリーダーが見つかりません";
            CloseLocked();
            return false;
        }

        std::string target = readerName;
        if (target.empty()) {
            target = readers.front();
        }

        DWORD activeProtocol = 0;
        rc = SCardConnect(m_context,
                          target.c_str(),
                          SCARD_SHARE_SHARED,
                          SCARD_PROTOCOL_T1,
                          &m_card,
                          &activeProtocol);
        if (rc != SCARD_S_SUCCESS) {
            m_lastError = "B-CAS カードへの接続に失敗しました (" + target + ")";
            CloseLocked();
            return false;
        }

        m_activeProtocol = activeProtocol;
        m_readerName = target;
        m_open = true;
        m_lastError.clear();
        return true;
    }

    void Close() override {
        std::lock_guard<std::mutex> lock(m_lock);
        CloseLocked();
    }

    bool IsOpen() const override {
        std::lock_guard<std::mutex> lock(m_lock);
        return m_open;
    }

    std::string GetReaderName() const override {
        std::lock_guard<std::mutex> lock(m_lock);
        return m_readerName;
    }

    std::string GetLastError() const override {
        std::lock_guard<std::mutex> lock(m_lock);
        return m_lastError;
    }

    bool Transmit(const uint8_t *sendData, size_t sendSize,
                  uint8_t *recvData, size_t *recvSize) override {
        std::lock_guard<std::mutex> lock(m_lock);
        if (!m_open || !sendData || !recvData || !recvSize) {
            m_lastError = "カードが開かれていません";
            return false;
        }

        const SCARD_IO_REQUEST *pioSendPci =
            (m_activeProtocol == SCARD_PROTOCOL_T0) ? SCARD_PCI_T0 : SCARD_PCI_T1;
        DWORD dwRecv = static_cast<DWORD>(*recvSize);
        LONG rc = SCardTransmit(m_card,
                                pioSendPci,
                                sendData,
                                static_cast<DWORD>(sendSize),
                                nullptr,
                                recvData,
                                &dwRecv);
        if (rc != SCARD_S_SUCCESS) {
            m_lastError = "SCardTransmit failed";
            return false;
        }
        *recvSize = static_cast<size_t>(dwRecv);
        return true;
    }

    static std::vector<std::string> EnumerateLocked(SCARDCONTEXT ctx) {
        std::vector<std::string> list;
        DWORD len = 0;
        if (SCardListReaders(ctx, nullptr, nullptr, &len) != SCARD_S_SUCCESS || len <= 1) {
            return list;
        }
        std::vector<char> buf(len);
        if (SCardListReaders(ctx, nullptr, buf.data(), &len) != SCARD_S_SUCCESS) {
            return list;
        }
        const char *p = buf.data();
        while (p < buf.data() + len && *p != '\0') {
            list.emplace_back(p);
            p += std::strlen(p) + 1;
        }
        return list;
    }

private:
    void CloseLocked() {
        if (m_open) {
            SCardDisconnect(m_card, SCARD_LEAVE_CARD);
            m_card = 0;
            m_open = false;
        }
        if (m_context != 0) {
            SCardReleaseContext(m_context);
            m_context = 0;
        }
        m_readerName.clear();
    }

    mutable std::mutex m_lock;
    SCARDCONTEXT m_context = 0;
    SCARDHANDLE m_card = 0;
    DWORD m_activeProtocol = 0;
    bool m_open = false;
    std::string m_readerName;
    std::string m_lastError;
};

} // namespace

std::vector<std::string> CardReader::EnumeratePCSCReaders() {
    SCARDCONTEXT ctx = 0;
    if (SCardEstablishContext(SCARD_SCOPE_USER, nullptr, nullptr, &ctx) != SCARD_S_SUCCESS) {
        return {};
    }
    auto list = PCSCCardReader::EnumerateLocked(ctx);
    SCardReleaseContext(ctx);
    return list;
}

std::unique_ptr<CardReader> CardReader::CreatePCSCReader() {
    return std::make_unique<PCSCCardReader>();
}

} // namespace TvCasMac
