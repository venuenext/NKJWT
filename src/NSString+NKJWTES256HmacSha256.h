//
//
//  ,--.  ,--.,--. ,--.     ,--.,--.   ,--.,--------.
//  |  ,'.|  ||  .'   /     |  ||  |   |  |'--.  .--'
//  |  |' '  ||  .   ' ,--. |  ||  |.'.|  |   |  |
//  |  | `   ||  |\   \|  '-'  /|   ,'.   |   |  |
//  `--'  `--'`--' '--' `-----' '--'   '--'   `--'
//

#import <Foundation/Foundation.h>

@interface NSString (NKJWTES256HmacSha256)

- (BOOL)NKJWTValidateES256withPublicKey:(NSString *)key forData:(NSData *)data;

@end
