//
//  QosManager.h
//  testws
//
//  Created by Pursue丶 on 2022/4/2.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface QosManager : NSObject

+ (instancetype)sharedInstance;

- (void)addEvent:(NSDictionary *)eventDic;

@end

NS_ASSUME_NONNULL_END
