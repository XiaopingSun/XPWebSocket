//
//  XPWebSocket.m
//  testws
//
//  Created by Pursue丶 on 2022/4/1.
//

#import "XPWebSocket.h"
#import "SRWebSocket.h"
#import <HappyDNS/HappyDNS.h>
#import "QosManager.h"

#define kAliDNSResolveIP   @"223.5.5.5"
#define kTencentDNSResolveIP    @"119.29.29.29"
#define kQNHappyDNSResolveTimeout 3.0
#define kDefaultRetryTimes 3
#define kDefaultConnectionTimeout 5.0
#define kDefaultRetryInterval 1

NSString *srStates[] = {
    @"SR_IDLE",
    @"SR_DNS_RESOLVING",
    @"SR_TCP_CONNECTING",
    @"SR_HANDSHAKING",
    @"SR_OPEN",
    @"SR_CLOSING",
    @"SR_CLOSED",
};

@interface XPWebSocket () <SRWebSocketDelegate>

@property (nonatomic, assign, readwrite) XPWebSocketConnectionState state;

@property (nonatomic, strong) SRWebSocket *webSocket;

@property (nonatomic, assign) SRReadyState srReadyState;

@property (nonatomic, strong) QNDnsManager *dnsManager;

@property (nonatomic, strong) dispatch_queue_t operationQueue;

@property (nonatomic, assign) NSUInteger currentUrlIndex;

@property (nonatomic, assign) NSUInteger retryTimesRemain;

@property (nonatomic, assign) long long currentTime;

@property (nonatomic, assign) BOOL isHappyDnsWork;

@property (nonatomic, assign) BOOL isClosing;

@end

@implementation XPWebSocket

- (instancetype)initWithUrlList:(NSArray<NSURL *> *)urlList {
    return [[XPWebSocket alloc] initWithUrlList:urlList useHappyDns:NO];
}

- (instancetype)initWithUrlList:(NSArray<NSURL *> *)urlList useHappyDns:(BOOL)isUseHappyDns {
    return [[XPWebSocket alloc] initWithUrlList:urlList retryTimes:kDefaultRetryTimes timeoutInterval:kDefaultConnectionTimeout useHappyDns:isUseHappyDns];
}

- (instancetype)initWithUrlList:(NSArray<NSURL *> *)urlList retryTimes:(NSUInteger)retryTimes timeoutInterval:(NSTimeInterval)timeoutInterval useHappyDns:(BOOL)isUseHappyDns {
    NSAssert(urlList.count, @"urlList has no url");
    self = [super init];
    if (self) {
        _urlList = urlList;
        _retryTimes = retryTimes;
        _timeoutInterval = timeoutInterval > 0 ? timeoutInterval : kDefaultConnectionTimeout;
        _useHappyDns = isUseHappyDns;
        _operationQueue = dispatch_queue_create("xpwebsocket.operation.queue", DISPATCH_QUEUE_SERIAL);
        
        if (isUseHappyDns) {
            // 阿里
            id<QNResolverDelegate> r1 = [[QNResolver alloc] initWithAddress:kAliDNSResolveIP timeout:kQNHappyDNSResolveTimeout];
            // 腾讯
            id<QNResolverDelegate> r2 = [[QNResolver alloc] initWithAddress:kTencentDNSResolveIP timeout:kQNHappyDNSResolveTimeout];
            // 系统
            id<QNResolverDelegate> r3 = [QNResolver systemResolver];
            _dnsManager = [[QNDnsManager alloc] init:@[r1, r2, r3] networkInfo:[QNNetworkInfo normal]];
        }
    }
    return self;
}

- (void)open {
    dispatch_async(self.operationQueue, ^{
        self.isClosing = NO;
        self.currentUrlIndex = 0;
        self.retryTimesRemain = self.retryTimes;
        [self innerOpen];
    });
}

- (void)close {
    dispatch_async(self.operationQueue, ^{
        self.isClosing = YES;
        [self.webSocket close];
    });
}

- (void)innerOpen {
    _srReadyState = SR_IDLE;
    _isHappyDnsWork = NO;
    _currentTime = [self currentTimestamp];
    NSURL *url = _urlList[_currentUrlIndex];
    NSURLRequest *urlRequest = [[NSURLRequest alloc] initWithURL:url cachePolicy:NSURLRequestUseProtocolCachePolicy timeoutInterval:_timeoutInterval];
    NSLog(@"SRWebSocket innerOpen: url %@", url.absoluteString);
    _webSocket = [[SRWebSocket alloc] initWithURLRequest:urlRequest protocols:nil dnsManager:_dnsManager];
    _webSocket.delegate = self;
    [_webSocket open];
}

- (void)retry {
    NSLog(@"SRWebSocket retry: _currentUrlIndex %ld _retryTimesRemain %ld", _currentUrlIndex, _retryTimesRemain);
    if (_isClosing) {
        return;
    }
    
    if (_retryTimesRemain == 0) {
        if (_currentUrlIndex == _urlList.count - 1) {
            return;
        } else {
            _currentUrlIndex++;
        }
        _retryTimesRemain = _retryTimes;
    } else {
        _retryTimesRemain--;
    }

    _webSocket.delegate = nil;
    _webSocket = nil;
    [self innerOpen];
}

- (long long)currentTimestamp {
    return (long long)(1000 * [[NSDate date] timeIntervalSince1970]);
}

#pragma mark - SRWebSocketDelegate
- (void)webSocket:(SRWebSocket *)webSocket didReceiveMessage:(id)message {
    NSLog(@"SRWebSocket didReceiveMessage%@", (NSString *)message);
    if (self.delegate && [self.delegate respondsToSelector:@selector(webSocket:didReceiveMessage:)]) {
        [self.delegate webSocket:self didReceiveMessage:(NSString *)message];
    }
}

- (void)webSocket:(SRWebSocket *)websocket readyStateDidChange:(SRReadyState)state {
    dispatch_async(self.operationQueue, ^{
        NSLog(@"SRWebSocket readyStateDidChange:%@", srStates[state]);
        self.srReadyState = state;
        long long currentTime = [self currentTimestamp];
        long long duration = currentTime - self.currentTime;
        self.currentTime = currentTime;
        
        if (state == SR_DNS_RESOLVING) {
            self.isHappyDnsWork = YES;
            if (self.state < XPWebSocketConnectionStateConnecting) {
                self.state = XPWebSocketConnectionStateConnecting;
                if (self.delegate && [self.delegate respondsToSelector:@selector(webSocket:connectionStateDidChange:)]) {
                    [self.delegate webSocket:self connectionStateDidChange:XPWebSocketConnectionStateConnecting];
                }
            } else if ((self.state > XPWebSocketConnectionStateConnecting && self.state < XPWebSocketConnectionStateReconnecting) || self.state == XPWebSocketConnectionStateReconnected) {
                self.state = XPWebSocketConnectionStateReconnecting;
                if (self.delegate && [self.delegate respondsToSelector:@selector(webSocket:connectionStateDidChange:)]) {
                    [self.delegate webSocket:self connectionStateDidChange:XPWebSocketConnectionStateReconnecting];
                }
            }
        } else if (state == SR_TCP_CONNECTING) {
            if (self.state < XPWebSocketConnectionStateConnecting) {
                self.state = XPWebSocketConnectionStateConnecting;
                if (self.delegate && [self.delegate respondsToSelector:@selector(webSocket:connectionStateDidChange:)]) {
                    [self.delegate webSocket:self connectionStateDidChange:XPWebSocketConnectionStateConnecting];
                }
            } else if ((self.state > XPWebSocketConnectionStateConnecting && self.state < XPWebSocketConnectionStateReconnecting) || self.state == XPWebSocketConnectionStateReconnected) {
                self.state = XPWebSocketConnectionStateReconnecting;
                if (self.delegate && [self.delegate respondsToSelector:@selector(webSocket:connectionStateDidChange:)]) {
                    [self.delegate webSocket:self connectionStateDidChange:XPWebSocketConnectionStateReconnecting];
                }
            }
            if (self.isHappyDnsWork) {
                NSDictionary *event = @{
                    @"event_name": @"happy_dns_resolve_done",
                    @"url": self.webSocket.url.absoluteString ? self.webSocket.url.absoluteString : @"",
                    @"ip": self.webSocket.ip ? self.webSocket.ip : @"",
                    @"duration": @(duration)
                };
                [[QosManager sharedInstance] addEvent:event];
            }
        } else if (state == SR_HANDSHAKING) {
            NSDictionary *event = @{
                @"event_name": @"tcp_connect_done",
                @"url": self.webSocket.url.absoluteString ? self.webSocket.url.absoluteString : @"",
                @"ip": self.webSocket.ip ? self.webSocket.ip : @"",
                @"duration": @(duration)
            };
            [[QosManager sharedInstance] addEvent:event];
        } else if (state == SR_OPEN) {
            if (self.state < XPWebSocketConnectionStateConnected) {
                self.state = XPWebSocketConnectionStateConnected;
                if (self.delegate && [self.delegate respondsToSelector:@selector(webSocket:connectionStateDidChange:)]) {
                    [self.delegate webSocket:self connectionStateDidChange:XPWebSocketConnectionStateConnected];
                }
            } else {
                self.state = XPWebSocketConnectionStateReconnected;
                if (self.delegate && [self.delegate respondsToSelector:@selector(webSocket:connectionStateDidChange:)]) {
                    [self.delegate webSocket:self connectionStateDidChange:XPWebSocketConnectionStateReconnected];
                }
            }
            NSDictionary *event = @{
                @"event_name": @"handshake_done",
                @"url": self.webSocket.url.absoluteString ? self.webSocket.url.absoluteString : @"",
                @"ip": self.webSocket.ip ? self.webSocket.ip : @"",
                @"duration": @(duration)
            };
            [[QosManager sharedInstance] addEvent:event];
        }
    });
}

- (void)webSocket:(SRWebSocket *)webSocket didFailWithError:(NSError *)error {
    dispatch_async(self.operationQueue, ^{
        NSLog(@"SRWebSocket didFailWithError:%@   state:%@", error, srStates[self.srReadyState]);
        long long duration = [self currentTimestamp] - self.currentTime;
        switch (self.srReadyState) {
            case SR_IDLE:
                break;
                
            case SR_DNS_RESOLVING:
            {
                NSDictionary *event = @{
                    @"event_name": @"happy_dns_resolve_failed",
                    @"url": self.webSocket.url.absoluteString ? self.webSocket.url.absoluteString : @"",
                    @"ip": self.webSocket.ip ? self.webSocket.ip : @"",
                    @"duration": @(duration),
                    @"code": @(error.code),
                    @"reason": error.localizedDescription ? error.localizedDescription : @""
                };
                [[QosManager sharedInstance] addEvent:event];
            }
                break;
                
            case SR_TCP_CONNECTING:
            {
                NSDictionary *event = @{
                    @"event_name": @"tcp_connect_failed",
                    @"url": self.webSocket.url.absoluteString ? self.webSocket.url.absoluteString : @"",
                    @"ip": self.webSocket.ip ? self.webSocket.ip : @"",
                    @"duration": @(duration),
                    @"code": @(error.code),
                    @"reason": error.localizedDescription ? error.localizedDescription : @""
                };
                [[QosManager sharedInstance] addEvent:event];
            }
                break;
                
            case SR_HANDSHAKING:
            {
                NSDictionary *event = @{
                    @"event_name": @"handshake_failed",
                    @"url": self.webSocket.url.absoluteString ? self.webSocket.url.absoluteString : @"",
                    @"ip": self.webSocket.ip ? self.webSocket.ip : @"",
                    @"duration": @(duration),
                    @"code": @(error.code),
                    @"reason": error.localizedDescription ? error.localizedDescription : @""
                };
                [[QosManager sharedInstance] addEvent:event];
            }
                break;
            case SR_OPEN:
            {
                NSDictionary *event = @{
                    @"event_name": @"websocket_failed",
                    @"url": self.webSocket.url.absoluteString ? self.webSocket.url.absoluteString : @"",
                    @"ip": self.webSocket.ip ? self.webSocket.ip : @"",
                    @"code": @(error.code),
                    @"reason": error.localizedDescription ? error.localizedDescription : @""
                };
                [[QosManager sharedInstance] addEvent:event];
            }
                break;
                
            default:
                break;
        }
        
        if (self.retryTimesRemain == 0 && self.currentUrlIndex == self.urlList.count - 1) {
            if (self.delegate && [self.delegate respondsToSelector:@selector(webSocket:didFailWithError:)]) {
                [self.delegate webSocket:self didFailWithError:error];
            }
            if (self.delegate && [self.delegate respondsToSelector:@selector(webSocket:connectionStateDidChange:)]) {
                [self.delegate webSocket:self connectionStateDidChange:XPWebSocketConnectionStateIdle];
            }
            self.webSocket.delegate = nil;
            self.webSocket = nil;
        } else {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                [self retry];
            });
        }
    });
}

- (void)webSocket:(SRWebSocket *)webSocket didCloseWithCode:(NSInteger)code reason:(NSString *)reason wasClean:(BOOL)wasClean {
    dispatch_async(self.operationQueue, ^{
        NSLog(@"SRWebSocket didCloseWithCode:%ld   state:%@   reason:%@", code, srStates[self.srReadyState], reason);
        NSDictionary *event = @{
            @"event_name": @"websocket_close",
            @"url": self.webSocket.url.absoluteString ? self.webSocket.url.absoluteString : @"",
            @"ip": self.webSocket.ip ? self.webSocket.ip : @"",
            @"code": @(code),
            @"reason": reason ? reason : @"",
        };
        [[QosManager sharedInstance] addEvent:event];
        
        // 两端主动断开连接，不做重连，直接回调给上层
        if (code == SRStatusCodeGoingAway || (self.retryTimesRemain == 0 && self.currentUrlIndex == self.urlList.count - 1)) {
            if (self.delegate && [self.delegate respondsToSelector:@selector(webSocket:didCloseWithCode:reason:wasClean:)]) {
                [self.delegate webSocket:self didCloseWithCode:code reason:reason wasClean:wasClean];
            }
            if (self.delegate && [self.delegate respondsToSelector:@selector(webSocket:connectionStateDidChange:)]) {
                [self.delegate webSocket:self connectionStateDidChange:XPWebSocketConnectionStateIdle];
            }
            self.webSocket.delegate = nil;
            self.webSocket = nil;
        } else {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kDefaultRetryInterval * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                [self retry];
            });
        }
    });
}

- (void)webSocket:(SRWebSocket *)webSocket didReceivePong:(NSData *)pongPayload {}

- (BOOL)webSocketShouldConvertTextFrameToString:(SRWebSocket *)webSocket {
    return YES;
}

@end
