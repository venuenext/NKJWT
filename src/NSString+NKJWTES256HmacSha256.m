//
//
//  ,--.  ,--.,--. ,--.     ,--.,--.   ,--.,--------.
//  |  ,'.|  ||  .'   /     |  ||  |   |  |'--.  .--'
//  |  |' '  ||  .   ' ,--. |  ||  |.'.|  |   |  |
//  |  | `   ||  |\   \|  '-'  /|   ,'.   |   |  |
//  `--'  `--'`--' '--' `-----' '--'   '--'   `--'
//
//

#import "NSString+NKJWTES256HmacSha256.h"
#import "NSString+NKJWTBase64.h"
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>
#import "GMEllipticCurveCrypto.h"
#import "GMEllipticCurveCrypto+hash.h"

@implementation NSString (NKJWTES256HmacSha256)

- (BOOL)NKJWTValidateES256withPublicKey:(NSString *)key forData:(NSData *)data
{
    GMEllipticCurveCrypto* crypto = [GMEllipticCurveCrypto cryptoForCurve:GMEllipticCurveSecp256r1];
    crypto.publicKey = [self dataFromHexString:key];
    
    NSData *signature = [[NSData alloc] initWithBase64EncodedString:[self restoreOriginalBase64FromCleanup] options:0];
    
    return [crypto hashSHA256AndVerifySignature:signature forData:data];
    
//    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
//    CC_SHA256([data bytes], (int)[data length], hash);
//    
//    NSLog(@"hash: %@", [[NSData dataWithBytes:hash length:sizeof(hash)] base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength]);
//    
//    return [crypto verifySignature:signature forHash:[NSData dataWithBytes:hash length:sizeof(hash)]];
    //    return [[NSData alloc] initWithBytes:cHMAC length:sizeof(cHMAC)];
}

//
//  NSData+HexString.m
//  libsecurity_transform
//
//  Copyright (c) 2011 Apple, Inc. All rights reserved.
//

- (NSData *)dataFromHexString:(NSString *)hex
{
    char buf[3];
    buf[2] = '\0';
    NSAssert(0 == [hex length] % 2, @"Hex strings should have an even number of digits (%@)", hex);
    unsigned char *bytes = malloc([hex length]/2);
    unsigned char *bp = bytes;
    for (CFIndex i = 0; i < [hex length]; i += 2) {
        buf[0] = [hex characterAtIndex:i];
        buf[1] = [hex characterAtIndex:i+1];
        char *b2 = NULL;
        *bp++ = strtol(buf, &b2, 16);
        NSAssert(b2 == buf + 2, @"String should be all hex digits: %@ (bad digit around %d)", hex, i);
    }
    
    return [NSData dataWithBytesNoCopy:bytes length:[hex length]/2 freeWhenDone:YES];
}

@end
