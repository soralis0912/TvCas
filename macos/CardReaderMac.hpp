// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace TvCasMac {

class CardReader {
public:
    virtual ~CardReader() = default;

    virtual bool Open(const std::string &readerName = "") = 0;
    virtual void Close() = 0;
    virtual bool IsOpen() const = 0;
    virtual std::string GetReaderName() const = 0;
    virtual std::string GetLastError() const = 0;

    virtual bool Transmit(const uint8_t *sendData, size_t sendSize,
                          uint8_t *recvData, size_t *recvSize) = 0;

    static std::vector<std::string> EnumeratePCSCReaders();
    static std::unique_ptr<CardReader> CreatePCSCReader();
};

} // namespace TvCasMac
