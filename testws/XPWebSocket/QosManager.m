//
//  QosManager.m
//  testws
//
//  Created by Pursue丶 on 2022/4/2.
//

#import "QosManager.h"

@interface QosManager ()

@property (nonatomic, strong) dispatch_queue_t operationQueue;

@property (nonatomic, strong) NSFileHandle *fileHandle;

@end

@implementation QosManager
+ (instancetype)sharedInstance {
    static QosManager *sharedInstance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedInstance = [[QosManager alloc] init];
    });
    return sharedInstance;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        self.operationQueue = dispatch_queue_create("qos.event.statistics", DISPATCH_QUEUE_SERIAL);
        
        NSString *localPath = [[NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES) lastObject] stringByAppendingPathComponent:@"qos"];
        BOOL isExist = [[NSFileManager defaultManager] fileExistsAtPath:localPath];
        if (!isExist) {
            BOOL isCreated = [[NSFileManager defaultManager] createFileAtPath:localPath contents:nil attributes:nil];
            if (!isCreated) {
                return nil;
            }
        }
        self.fileHandle = [NSFileHandle fileHandleForUpdatingAtPath:localPath];
    }
    return self;
}

- (void)addEvent:(NSDictionary *)eventDic {
    if (!eventDic.count) {
        NSLog(@"eventDic is empty.");
        return;
    }
    
    dispatch_async(self.operationQueue, ^{
        NSError *error;
        NSData *jsonData = [NSJSONSerialization dataWithJSONObject:eventDic options:NSJSONWritingPrettyPrinted error:&error];
        if (error) {
            NSLog(@"json serialization failed. error: %@", error);
            return;
        }
        [self.fileHandle seekToEndOfFile];
        [self.fileHandle writeData:jsonData error:&error];
        if (error) {
            NSLog(@"file handle write data failed. error: %@", error);
        }
    });
}

@end
