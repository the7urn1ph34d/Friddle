
#import "NativeProcessor.h"

@implementation NativeProcessor

+ (NSString *)process:(NSString *)input mode:(NSInteger)mode falsePositiveMode:(BOOL)falsePositiveMode {
    const char *inC = [input UTF8String];
    const char *outC = nativeProcess(inC, (int)mode, (bool)falsePositiveMode);
    NSString *result = [NSString stringWithUTF8String:outC ?: ""];
    return result;
}

@end
