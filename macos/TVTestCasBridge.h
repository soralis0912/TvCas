// SPDX-License-Identifier: GPL-2.0-or-later
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Protocol matching MacBonDriverSmartCard APDU surface without forcing a hard header cycle.
@protocol TVCasSmartCardTransport <NSObject>
@property (nonatomic, readonly, copy, nullable) NSString *cardReaderName;
@property (nonatomic, readonly, getter=isCardOpen) BOOL cardOpen;
- (BOOL)openSmartCardWithError:(NSError * _Nullable * _Nullable)error;
- (void)closeSmartCard;
- (nullable NSData *)transmitAPDU:(NSData *)commandAPDU
                            error:(NSError * _Nullable * _Nullable)error;
@end

@interface TVTestCasSession : NSObject
@property (nonatomic, readonly, getter=isOpen) BOOL open;
@property (nonatomic, readonly, copy) NSString *readerName;
@property (nonatomic, readonly, copy) NSString *cardIDText;
@property (nonatomic, readonly) uint16_t caSystemID;
@property (nonatomic, readonly) uint8_t cardType;
@property (nonatomic) BOOL enableEMMProcess;

@property (nonatomic, readonly) uint64_t descrambledPackets;
@property (nonatomic, readonly) uint64_t undescrambledPackets;
@property (nonatomic, readonly) uint64_t ecmCount;
@property (nonatomic, readonly) uint64_t ecmErrorCount;
@property (nonatomic, readonly) uint64_t emmCount;

+ (NSArray<NSString *> *)availablePCSCReaders;

// Opens a built-in MacBonDriver smart card reader (e.g. XIT-SQR100 via MBD_SQR100.bundle).
- (BOOL)openWithSmartCardTransport:(id)transport error:(NSError **)error;

// Opens a macOS PCSC.framework USB smart card reader (pass nil/empty for first available reader).
- (BOOL)openWithPCSCReaderName:(nullable NSString *)readerName error:(NSError **)error;

- (void)close;
- (void)reset;

// Descrambles 188-byte MPEG-TS packets in-place.
- (void)descrambleTSBytes:(uint8_t *)bytes length:(NSUInteger)length;
@end

NS_ASSUME_NONNULL_END
