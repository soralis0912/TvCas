# TvCas for macOS (ARIB STD-B25 MULTI2 & B-CAS)

Native macOS port of TvCas (`libtvcas_b25.a`) providing ARIB STD-B25 MULTI2 descrambling and B-CAS card communication for `TVTest` on macOS.

## Features

- **MULTI2 Decoder** (`Multi2DecoderMac.{hpp,cpp}`): Portable C++20 4-round ARIB STD-B25 MULTI2 CBC + OFB descrambler (and symmetric encoder for self-tests).
- **Card Readers** (`CardReaderMac.{hpp,mm}`, `TVTestCasBridge.{h,mm}`):
  - **Built-in Tuner Reader (`MacBonDriverSmartCard`)**: Directly talks to built-in B-CAS slots exposed by `MacBonDriver` bundles (e.g., PIXELA XIT-SQR100 via `MBD_SQR100.bundle`) without requiring a separate PC/SC driver.
  - **USB PC/SC Readers (`PCSC.framework`)**: Supports standard macOS CCID/PC/SC smart card readers via `<PCSC/winscard.h>`.
- **B-CAS APDU Protocol** (`CasCardMac.{hpp,cpp}`): Full ARIB STD-B25 APDU implementation (`0x90 0x30` Initial Setting, `0x90 0x32` Card ID Info, `0x90 0x34` ECM with last-ECM caching, `0x90 0x36` EMM, 20-digit Card ID formatter).
- **MPEG-TS Descrambler** (`TSDescramblerMac.{hpp,cpp}`): In-place 188-byte TS packet descrambler with PAT/PMT/CAT/ECM/EMM section assemblers, `CA_descriptor (0x09)` matching, per-ECM-PID decoders, and statistics counters.

## Build & Test

```sh
cmake -S TvCas/macos -B TvCas/macos/build -DCMAKE_BUILD_TYPE=Release
cmake --build TvCas/macos/build --parallel
./TvCas/macos/build/TvCasTests
```
