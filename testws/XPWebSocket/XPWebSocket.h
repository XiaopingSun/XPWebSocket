//
//  XPWebSocket.h
//  testws
//
//  Created by Pursue丶 on 2022/4/1.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSUInteger, XPWebSocketConnectionState) {
    XPWebSocketConnectionStateIdle,
    XPWebSocketConnectionStateConnecting,
    XPWebSocketConnectionStateConnected,
    XPWebSocketConnectionStateReconnecting,
    XPWebSocketConnectionStateReconnected
};

@class XPWebSocket;

@protocol XPWebSocketDelegate <NSObject>

@required

/*!
 * @abstract 收到消息回调
 *
 * @param webSocket XPWebSocket 实例
 * @param message 消息字符串
 */
- (void)webSocket:(XPWebSocket *)webSocket didReceiveMessage:(NSString *)message;

@optional

/*!
 * @abstract 连接状态回调
 *
 * @param webSocket XPWebSocket 实例
 * @param state 状态
 */
- (void)webSocket:(XPWebSocket *)webSocket connectionStateDidChange:(XPWebSocketConnectionState)state;

/*!
 * @abstract 异常回调
 *
 * @param webSocket XPWebSocket 实例
 * @param error 异常信息
 */
- (void)webSocket:(XPWebSocket *)webSocket didFailWithError:(NSError *)error;

/*!
 * @abstract 连接关闭回调  一般是 websocket 协议层面的主动或被动关闭
 *
 * @param webSocket XPWebSocket 实例
 * @param code websocket 状态码
 * @param reason 关闭原因
 * @param wasClean 是否已清空缓存区
 */
- (void)webSocket:(XPWebSocket *)webSocket didCloseWithCode:(NSInteger)code reason:(NSString *)reason wasClean:(BOOL)wasClean;

@end

@interface XPWebSocket : NSObject

/*!
 * @abstract URL 地址列表
 */
@property (nonatomic, strong, readonly) NSArray<NSURL *> *urlList;

/*!
 * @abstract 每个 URL 重试次数
 */
@property (nonatomic, assign, readonly) NSUInteger retryTimes;

/*!
 * @abstract 每次尝试连接的超时时间
 */
@property (nonatomic, assign, readonly) NSTimeInterval timeoutInterval;

/*!
 * @abstract 是否使用 HappyDNS 做 dns 解析
 */
@property (nonatomic, assign, readonly, getter=isUseHappyDns) BOOL useHappyDns;

/*!
 * @abstract 当前状态
 */
@property (nonatomic, assign, readonly) XPWebSocketConnectionState state;

/*!
 * @abstract delegate
 */
@property (nonatomic, weak) id<XPWebSocketDelegate> delegate;

- (instancetype)init NS_UNAVAILABLE;

/*!
 * @abstract 已发布 track 列表
 *
 * @param urlList URL 地址列表
 */
- (instancetype)initWithUrlList:(NSArray<NSURL *> *)urlList;

/*!
 * @abstract 已发布 track 列表
 *
 * @param urlList URL 地址列表
 * @param isUseHappyDns 是否使用 HappyDNS 做 dns 解析
 */
- (instancetype)initWithUrlList:(NSArray<NSURL *> *)urlList useHappyDns:(BOOL)isUseHappyDns;

/*!
 * @abstract 已发布 track 列表
 *
 * @param urlList URL 地址列表
 * @param retryTimes 每个 URL 重试次数
 * @param timeoutInterval 每次尝试连接的超时时间
 * @param isUseHappyDns 是否使用 HappyDNS 做 dns 解析
 */
- (instancetype)initWithUrlList:(NSArray<NSURL *> *)urlList retryTimes:(NSUInteger)retryTimes timeoutInterval:(NSTimeInterval)timeoutInterval useHappyDns:(BOOL)isUseHappyDns;

/*!
 * @abstract 打开连接
 */
- (void)open;

/*!
 * @abstract 关闭连接
 */
- (void)close;

@end

NS_ASSUME_NONNULL_END
