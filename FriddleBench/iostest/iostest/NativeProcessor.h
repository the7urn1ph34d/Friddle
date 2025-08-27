
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface NativeProcessor : NSObject

+ (NSString *)process:(NSString *)input mode:(NSInteger)mode falsePositiveMode:(BOOL)falsePositiveMode;

@end

#ifdef __cplusplus
extern "C" {
#endif
const char *nativeProcess(const char *input, int mode, bool falsePositiveMode);
#ifdef __cplusplus
}
#endif

NS_ASSUME_NONNULL_END
