//
//   Copyright 2012 Square Inc.
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.
//


#import "SRWebSocket.h"


#if TARGET_OS_IPHONE
#define HAS_ICU
#endif

#ifdef HAS_ICU
#import <unicode/utf8.h>
#endif

#if TARGET_OS_IPHONE
#import <Endian.h>
#else
#import <CoreServices/CoreServices.h>
#endif

#import <CommonCrypto/CommonDigest.h>
#import <Security/SecRandom.h>

#if OS_OBJECT_USE_OBJC_RETAIN_RELEASE
#define sr_dispatch_retain(x)
#define sr_dispatch_release(x)
#define maybe_bridge(x) ((__bridge void *) x)
#else
#define sr_dispatch_retain(x) dispatch_retain(x)
#define sr_dispatch_release(x) dispatch_release(x)
#define maybe_bridge(x) (x)
#endif

#if !__has_feature(objc_arc) 
#error SocketRocket must be compiled with ARC enabled
#endif


typedef enum  {
    SROpCodeTextFrame = 0x1,
    SROpCodeBinaryFrame = 0x2,
    // 3-7 reserved.
    SROpCodeConnectionClose = 0x8,
    SROpCodePing = 0x9,
    SROpCodePong = 0xA,
    // B-F reserved.
} SROpCode;

typedef struct {
    BOOL fin;
//  BOOL rsv1;
//  BOOL rsv2;
//  BOOL rsv3;
    uint8_t opcode;
    BOOL masked;
    uint64_t payload_length;
} frame_header;

static NSString *const SRWebSocketAppendToSecKeyString = @"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

static inline int32_t validate_dispatch_data_partial_string(NSData *data);
static inline void SRFastLog(NSString *format, ...);

@interface NSData (SRWebSocket)

- (NSString *)stringBySHA1ThenBase64Encoding;

@end


@interface NSString (SRWebSocket)

- (NSString *)stringBySHA1ThenBase64Encoding;

@end


@interface NSURL (SRWebSocket)

// The origin isn't really applicable for a native application.
// So instead, just map ws -> http and wss -> https.
- (NSString *)SR_origin;

@end


@interface _SRRunLoopThread : NSThread

@property (nonatomic, readonly) NSRunLoop *runLoop;

@end


static NSString *newSHA1String(const char *bytes, size_t length) {
    uint8_t md[CC_SHA1_DIGEST_LENGTH];

    assert(length >= 0);
    assert(length <= UINT32_MAX);
    CC_SHA1(bytes, (CC_LONG)length, md);
    
    NSData *data = [NSData dataWithBytes:md length:CC_SHA1_DIGEST_LENGTH];
    
    if ([data respondsToSelector:@selector(base64EncodedStringWithOptions:)]) {
        return [data base64EncodedStringWithOptions:0];
    }

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    return [data base64Encoding];
#pragma clang diagnostic pop
}

//fast judge domain or ip, not verify ip right.
static BOOL isNotIp(NSString* domain){
    NSUInteger l = domain.length;
    if (l >15 || l < 7) {
        return YES;
    }
    const char* str = domain.UTF8String;
    if (str == nil) {
        return YES;
    }
    
    for (const char* p = str; p < str+l; p++) {
        if ((*p < '0' || *p > '9') && *p != '.') {
            return YES;
        }
    }
    return NO;
}

@implementation NSData (SRWebSocket)

- (NSString *)stringBySHA1ThenBase64Encoding;
{
    return newSHA1String(self.bytes, self.length);
}

@end


@implementation NSString (SRWebSocket)

- (NSString *)stringBySHA1ThenBase64Encoding;
{
    return newSHA1String(self.UTF8String, self.length);
}

@end

NSString *const SRWebSocketErrorDomain = @"SRWebSocketErrorDomain";
NSString *const SRHTTPResponseErrorKey = @"HTTPResponseStatusCode";

// Returns number of bytes consumed. Returning 0 means you didn't match.
// Sends bytes to callback handler;
typedef size_t (^stream_scanner)(NSData *collected_data);

typedef void (^data_callback)(SRWebSocket *webSocket,  NSData *data);

@interface SRIOConsumer : NSObject {
    stream_scanner _scanner;
    data_callback _handler;
    size_t _bytesNeeded;
    BOOL _readToCurrentFrame;
    BOOL _unmaskBytes;
}
@property (nonatomic, copy, readonly) stream_scanner consumer;           // 消费者 scan 匹配符的函数
@property (nonatomic, copy, readonly) data_callback handler;                // 消费者获取匹配数据的回调
@property (nonatomic, assign) size_t bytesNeeded;                               // 消费者需要的固定字节数
@property (nonatomic, assign, readonly) BOOL readToCurrentFrame;       // 消费者是否是需要读数据帧的 payload
@property (nonatomic, assign, readonly) BOOL unmaskBytes;                 // 消费者如果是读 payload   payload 数据是否需要解 Mask

@end

// This class is not thread-safe, and is expected to always be run on the same queue.
@interface SRIOConsumerPool : NSObject

- (id)initWithBufferCapacity:(NSUInteger)poolSize;

- (SRIOConsumer *)consumerWithScanner:(stream_scanner)scanner handler:(data_callback)handler bytesNeeded:(size_t)bytesNeeded readToCurrentFrame:(BOOL)readToCurrentFrame unmaskBytes:(BOOL)unmaskBytes;
- (void)returnConsumer:(SRIOConsumer *)consumer;

@end

@interface SRWebSocket ()  <NSStreamDelegate>

@property (nonatomic) SRReadyState readyState;

@property (nonatomic) NSOperationQueue *delegateOperationQueue;
@property (nonatomic) dispatch_queue_t delegateDispatchQueue;

// Specifies whether SSL trust chain should NOT be evaluated.
// By default this flag is set to NO, meaning only secure SSL connections are allowed.
// For DEBUG builds this flag is ignored, and SSL connections are allowed regardless
// of the certificate trust configuration
// 是否允许未授信 ssl 证书
@property (nonatomic, readwrite) BOOL allowsUntrustedSSLCertificates;

@end


@implementation SRWebSocket {
    NSInteger _webSocketVersion;
    
    NSOperationQueue *_delegateOperationQueue;
    
    // 用来处理上层回调事件的队列
    dispatch_queue_t _delegateDispatchQueue;
    
    // 用来控制读写任务的队列
    dispatch_queue_t _workQueue;
    
    // 数据消费者队列
    NSMutableArray *_consumers;

    // 输入输出流
    NSInputStream *_inputStream;
    NSOutputStream *_outputStream;
   
    // 用于读取数据的缓存
    NSMutableData *_readBuffer;
    
    // 已读缓存的偏移量
    NSUInteger _readBufferOffset;
 
    // 用于写入数据的缓存
    NSMutableData *_outputBuffer;
    
    // 已写缓存的偏移量
    NSUInteger _outputBufferOffset;

    // 当前读取帧的 opcode
    uint8_t _currentFrameOpcode;
    
    // 当前 opcode 下 所有数据帧的数量
    size_t _currentFrameCount;
    
    // 当前 opcode 的数据帧数量
    size_t _readOpCount;
    
    // 文本帧的偏移（用于记录已扫描验证 UTF-8 的字符位置）
    uint32_t _currentStringScanPosition;
    
    // 当前 opcode 下的 payload 缓存  一般只存放文本帧和二进制帧的 payload
    NSMutableData *_currentFrameData;
    
    // ws 关闭原因
    NSString *_closeReason;
    
    // Sec-WebSocket-Key 用于 ws 握手校验
    NSString *_secKey;
    NSString *_basicAuthorizationString;
    
    BOOL _pinnedCertFound;
    
    // 读取的当前帧中包含的 Masking-Key
    uint8_t _currentReadMaskKey[4];
    
    // Masking-Key 偏移量
    size_t _currentReadMaskOffset;

    // 消费者是否都已停止   该字段未使用
    BOOL _consumerStopped;
    
    // 是否在当前缓冲区数据完成写入后关闭链接
    BOOL _closeWhenFinishedWriting;
    
    // 是否走到 failWithError
    BOOL _failed;

    // 是否是 ssl 加密连接
    BOOL _secure;
    
    // ws 请求的 NSURLRequest 实例
    NSURLRequest *_urlRequest;

    // 连接是否已关闭
    BOOL _sentClose;
    
    // 没用到
    BOOL _didFail;
    
    // 标识是否释放了输入输出流
    BOOL _cleanupScheduled;
    
    // 关闭链接 code
    int _closeCode;
    
    // 是否正在读取可读缓存区
    BOOL _isPumping;
    
    // runloop 缓存池
    NSMutableSet *_scheduledRunloops;
    
    // We use this to retain ourselves.
    __strong SRWebSocket *_selfRetain;
    
    // ws 子协议
    NSArray *_requestedProtocols;
    
    // 消费者缓存池
    SRIOConsumerPool *_consumerPool;
    
    // happydns解析
    QNDnsManager *_dnsManager;
}

@synthesize delegate = _delegate;
@synthesize url = _url;                            // ws 服务端地址
@synthesize readyState = _readyState;
@synthesize protocol = _protocol;            // 当前链接的 ws 子协议
@synthesize ip = _ip;                             // 解析的 ip 地址

static __strong NSData *CRLFCRLF;

+ (void)initialize;
{
    CRLFCRLF = [[NSData alloc] initWithBytes:"\r\n\r\n" length:4];
}

- (id)initWithURLRequest:(NSURLRequest *)request protocols:(NSArray *)protocols allowsUntrustedSSLCertificates:(BOOL)allowsUntrustedSSLCertificates dnsManager:(QNDnsManager *)dnsManager;
{
    self = [super init];
    if (self) {
        assert(request.URL);
        _url = request.URL;
        _urlRequest = request;
        _allowsUntrustedSSLCertificates = allowsUntrustedSSLCertificates;
        _requestedProtocols = [protocols copy];
        _dnsManager = dnsManager;
        _readyState = SR_IDLE;
        
        [self _SR_commonInit];
    }
    
    return self;
}

- (id)initWithURLRequest:(NSURLRequest *)request protocols:(NSArray *)protocols dnsManager:(QNDnsManager *)dnsManager;
{
    return [self initWithURLRequest:request protocols:protocols allowsUntrustedSSLCertificates:NO dnsManager:dnsManager];
}

- (id)initWithURLRequest:(NSURLRequest *)request dnsManager:(QNDnsManager *)dnsManager;
{
    return [self initWithURLRequest:request protocols:nil dnsManager:dnsManager];
}

- (id)initWithURL:(NSURL *)url dnsManager:(QNDnsManager *)dnsManager;
{
    return [self initWithURL:url protocols:nil dnsManager:dnsManager];
}

- (id)initWithURL:(NSURL *)url protocols:(NSArray *)protocols dnsManager:(QNDnsManager *)dnsManager;
{
    NSMutableURLRequest *request = [[NSMutableURLRequest alloc] initWithURL:url];    
    return [self initWithURLRequest:request protocols:protocols dnsManager:dnsManager];
}

- (id)initWithURL:(NSURL *)url protocols:(NSArray *)protocols allowsUntrustedSSLCertificates:(BOOL)allowsUntrustedSSLCertificates dnsManager:(QNDnsManager *)dnsManager;
{
    NSMutableURLRequest *request = [[NSMutableURLRequest alloc] initWithURL:url];
    return [self initWithURLRequest:request protocols:protocols allowsUntrustedSSLCertificates:allowsUntrustedSSLCertificates dnsManager:dnsManager];
}

- (void)_SR_commonInit;
{
    NSString *scheme = _url.scheme.lowercaseString;
    // 如果协议不是 ws、http、wss、https，assert
    assert([scheme isEqualToString:@"ws"] || [scheme isEqualToString:@"http"] || [scheme isEqualToString:@"wss"] || [scheme isEqualToString:@"https"]);
    
    // 判断是否是安全连接
    if ([scheme isEqualToString:@"wss"] || [scheme isEqualToString:@"https"]) {
        _secure = YES;
    }
    
    // 消费者是否都已停止   该字段未使用
    _consumerStopped = YES;
    
    // 标识客户端使用的 webSocket 版本
    _webSocketVersion = 13;
    
    // 初始化读写控制队列  串行
    _workQueue = dispatch_queue_create(NULL, DISPATCH_QUEUE_SERIAL);
    
    // Going to set a specific on the queue so we can validate we're on the work queue
    dispatch_queue_set_specific(_workQueue, (__bridge void *)self, maybe_bridge(_workQueue), NULL);
    
    // 获取回调队列  主线程
    _delegateDispatchQueue = dispatch_get_main_queue();
    sr_dispatch_retain(_delegateDispatchQueue);
    
    // 初始化读写缓存
    _readBuffer = [[NSMutableData alloc] init];
    _outputBuffer = [[NSMutableData alloc] init];
    
    // 初始化当前 opcode 下的 payload 缓存  一般只存放文本帧和二进制帧的 payload  拼接成完整消息后回调出去
    _currentFrameData = [[NSMutableData alloc] init];

    // 初始化消费者工作队列
    _consumers = [[NSMutableArray alloc] init];
    
    // 初始化消费者缓存池
    _consumerPool = [[SRIOConsumerPool alloc] init];
    
    // 初始化 runloop 缓存池
    _scheduledRunloops = [[NSMutableSet alloc] init];
}

- (void)assertOnWorkQueue;
{
    assert(dispatch_get_specific((__bridge void *)self) == maybe_bridge(_workQueue));
}

- (void)dealloc
{
    _inputStream.delegate = nil;
    _outputStream.delegate = nil;

    [_inputStream close];
    [_outputStream close];
    
    if (_workQueue) {
        sr_dispatch_release(_workQueue);
        _workQueue = NULL;
    }
    
    if (_receivedHTTPHeaders) {
        CFRelease(_receivedHTTPHeaders);
        _receivedHTTPHeaders = NULL;
    }
    
    if (_delegateDispatchQueue) {
        sr_dispatch_release(_delegateDispatchQueue);
        _delegateDispatchQueue = NULL;
    }
}

#ifndef NDEBUG

- (void)setReadyState:(SRReadyState)aReadyState;
{
    assert(aReadyState > _readyState);
    _readyState = aReadyState;
}

#endif

- (void)open;
{
    // 判断是否有 url
    assert(_url);
    
    // 一个实例一个生命周期只能调用 open 一次
    NSAssert(_readyState < SR_OPEN, @"Cannot call -(void)open on SRWebSocket more than once");

    // retain self 防止被释放造成野指针异常
    _selfRetain = self;

    // 如果 _urlRequest 设置了超时时间，sr 内部是用 GCD 的 after 去计算超时时间，如果超过了 _urlRequest.timeoutInterval 之后 self.readyState 依然是 未连接成功 就会主动断开
    if (_urlRequest.timeoutInterval > 0)
    {
        dispatch_time_t popTime = dispatch_time(DISPATCH_TIME_NOW, _urlRequest.timeoutInterval * NSEC_PER_SEC);
        dispatch_after(popTime, dispatch_get_main_queue(), ^(void){
            if (self.readyState < SR_OPEN)
                [self failWithError:[NSError errorWithDomain:@"com.squareup.SocketRocket" code:504 userInfo:@{NSLocalizedDescriptionKey: @"Timeout Connecting to Server"}]];
        });
    }
    
    // dns解析
    if (_dnsManager && isNotIp(_url.host)) {
        // 更新状态 - dns 解析
        _readyState = SR_DNS_RESOLVING;
        [self _performDelegateBlock:^{
            if (self.delegate && [self.delegate respondsToSelector:@selector(webSocket:readyStateDidChange:)]) {
                [self.delegate webSocket:self readyStateDidChange:SR_DNS_RESOLVING];
            }
        }];
        
        NSArray<NSString *> *ips = [_dnsManager query:_url.host];
        if (ips != nil || ips.count != 0) {
            _ip = ips[0];
        } else{
            _ip = @"";
        }
        if (self.readyState >= SR_CLOSING) {
            return;
        }
    }
    
    // 初始化输入输出流
    [self _initializeStreams];

    // 打开链接
    [self openConnection];
}

// Calls block on delegate queue
- (void)_performDelegateBlock:(dispatch_block_t)block;
{
    if (_delegateOperationQueue) {
        [_delegateOperationQueue addOperationWithBlock:block];
    } else {
        assert(_delegateDispatchQueue);
        dispatch_async(_delegateDispatchQueue, block);
    }
}

// 设置回调线程
- (void)setDelegateDispatchQueue:(dispatch_queue_t)queue;
{
    if (queue) {
        sr_dispatch_retain(queue);
    }
    
    if (_delegateDispatchQueue) {
        sr_dispatch_release(_delegateDispatchQueue);
    }
    
    _delegateDispatchQueue = queue;
}

// 校验 ws 握手中 request 的 Sec-WebSocket-Key 和 response 的 Sec-WebSocket-Accept 是否匹配
- (BOOL)_checkHandshake:(CFHTTPMessageRef)httpMessage;
{
    // 获取服务端返回的 Sec-WebSocket-Accept 字段
    NSString *acceptHeader = CFBridgingRelease(CFHTTPMessageCopyHeaderFieldValue(httpMessage, CFSTR("Sec-WebSocket-Accept")));

    // 如果没有  返回 NO
    if (acceptHeader == nil) {
        return NO;
    }
    
    // 将 Sec-WebSocket-Key 拼接协议规定的固定字符串
    NSString *concattedString = [_secKey stringByAppendingString:SRWebSocketAppendToSecKeyString];
    
    // 将上述拼接后的字符串做 Sha1 加密
    NSString *expectedAccept = [concattedString stringBySHA1ThenBase64Encoding];
    
    // 将加密后的字符串与服务端返回的 Sec-WebSocket-Accept 作比较
    return [acceptHeader isEqualToString:expectedAccept];
}

- (void)_HTTPHeadersDidFinish;
{
    // 从 response header 中读取 response code
    NSInteger responseCode = CFHTTPMessageGetResponseStatusCode(_receivedHTTPHeaders);
    
    // code 大于 400   断开链接返回
    if (responseCode >= 400) {
        SRFastLog(@"Request failed with response code %d", responseCode);
        [self failWithError:[NSError errorWithDomain:SRWebSocketErrorDomain code:2132 userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"received bad response code from server %ld", (long)responseCode], SRHTTPResponseErrorKey:@(responseCode)}]];
        return;
    }
    
    // 校验 Sec-WebSocket-Key 和 Sec-WebSocket-Accept 是否匹配  如果不匹配  断开链接返回
    if(![self _checkHandshake:_receivedHTTPHeaders]) {
        [self failWithError:[NSError errorWithDomain:SRWebSocketErrorDomain code:2133 userInfo:[NSDictionary dictionaryWithObject:[NSString stringWithFormat:@"Invalid Sec-WebSocket-Accept response"] forKey:NSLocalizedDescriptionKey]]];
        return;
    }
    
    // 获取服务端返回的子协议
    NSString *negotiatedProtocol = CFBridgingRelease(CFHTTPMessageCopyHeaderFieldValue(_receivedHTTPHeaders, CFSTR("Sec-WebSocket-Protocol")));
    if (negotiatedProtocol) {
        // Make sure we requested the protocol
        if ([_requestedProtocols indexOfObject:negotiatedProtocol] == NSNotFound) {
            [self failWithError:[NSError errorWithDomain:SRWebSocketErrorDomain code:2133 userInfo:[NSDictionary dictionaryWithObject:[NSString stringWithFormat:@"Server specified Sec-WebSocket-Protocol that wasn't requested"] forKey:NSLocalizedDescriptionKey]]];
            return;
        }
        _protocol = negotiatedProtocol;
    }
    
    // 更改状态
    self.readyState = SR_OPEN;
    
    // 这里 didFail 好像没啥用  一定会走 _readFrameNew  开始读取新的一帧
    if (!_didFail) {
        [self _readFrameNew];
    }

    // 更新状态 - 已连接
    [self _performDelegateBlock:^{
        if ([self.delegate respondsToSelector:@selector(webSocket:readyStateDidChange:)]) {
            [self.delegate webSocket:self readyStateDidChange:SR_OPEN];
        };
    }];
}


- (void)_readHTTPHeader;
{
    // 初始化 http message 容器
    if (_receivedHTTPHeaders == NULL) {
        _receivedHTTPHeaders = CFHTTPMessageCreateEmpty(NULL, NO);
    }
                     
    // 尝试读取 http header，这里虽然方法名看起来是阻塞调用，但实际只是创建一个 http header 的消费者，消费者将下边的这个 callback 函数缓存起来，并将消费者缓存在消费者队列中，在之后的每次轮询过程中如果匹配到满足该消费者需要的数据，则会回调下边的 callback
    [self _readUntilHeaderCompleteWithCallback:^(SRWebSocket *self,  NSData *data) {
        // 将匹配的数据读到 _receivedHTTPHeaders 中
        CFHTTPMessageAppendBytes(_receivedHTTPHeaders, (const UInt8 *)data.bytes, data.length);
        // 判断 header 是否完整
        if (CFHTTPMessageIsHeaderComplete(_receivedHTTPHeaders)) {
            // 如果 header 成功读取  进行 header 解析
            SRFastLog(@"Finished reading headers %@", CFBridgingRelease(CFHTTPMessageCopyAllHeaderFields(_receivedHTTPHeaders)));
            [self _HTTPHeadersDidFinish];
        } else {
            // 如果没读取完成   接着读取
            [self _readHTTPHeader];
        }
    }];
}

- (void)didConnect;
{
    SRFastLog(@"Connected");
    // 更新状态 - ws 握手
    _readyState = SR_HANDSHAKING;
    [self _performDelegateBlock:^{
        if (self.delegate && [self.delegate respondsToSelector:@selector(webSocket:readyStateDidChange:)]) {
            [self.delegate webSocket:self readyStateDidChange:SR_HANDSHAKING];
        }
    }];
    
    // 创建 get 请求
    CFHTTPMessageRef request = CFHTTPMessageCreateRequest(NULL, CFSTR("GET"), (__bridge CFURLRef)_url, kCFHTTPVersion1_1);
    
    // Set host first so it defaults
    CFHTTPMessageSetHeaderFieldValue(request, CFSTR("Host"), (__bridge CFStringRef)(_url.port ? [NSString stringWithFormat:@"%@:%@", _url.host, _url.port] : _url.host));
        
    // 生成 16 位随机数
    NSMutableData *keyBytes = [[NSMutableData alloc] initWithLength:16];
    SecRandomCopyBytes(kSecRandomDefault, keyBytes.length, keyBytes.mutableBytes);
    
    // base64 编码
    if ([keyBytes respondsToSelector:@selector(base64EncodedStringWithOptions:)]) {
        _secKey = [keyBytes base64EncodedStringWithOptions:0];
    } else {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        _secKey = [keyBytes base64Encoding];
#pragma clang diagnostic pop
    }
    
    // 判断编码后是否为 24 位
    assert([_secKey length] == 24);

    // 设置我们传入的 cookies
    NSDictionary * cookies = [NSHTTPCookie requestHeaderFieldsWithCookies:[self requestCookies]];
    for (NSString * cookieKey in cookies) {
        NSString * cookieValue = [cookies objectForKey:cookieKey];
        if ([cookieKey length] && [cookieValue length]) {
            CFHTTPMessageSetHeaderFieldValue(request, (__bridge CFStringRef)cookieKey, (__bridge CFStringRef)cookieValue);
        }
    }
 
    // 设置认证字段
    if (_url.user.length && _url.password.length) {
        NSData *userAndPassword = [[NSString stringWithFormat:@"%@:%@", _url.user, _url.password] dataUsingEncoding:NSUTF8StringEncoding];
        NSString *userAndPasswordBase64Encoded;
        if ([keyBytes respondsToSelector:@selector(base64EncodedStringWithOptions:)]) {
            userAndPasswordBase64Encoded = [userAndPassword base64EncodedStringWithOptions:0];
        } else {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
            userAndPasswordBase64Encoded = [userAndPassword base64Encoding];
#pragma clang diagnostic pop
        }
        _basicAuthorizationString = [NSString stringWithFormat:@"Basic %@", userAndPasswordBase64Encoded];
        CFHTTPMessageSetHeaderFieldValue(request, CFSTR("Authorization"), (__bridge CFStringRef)_basicAuthorizationString);
    }

    // 设置 websocket 握手必要字段
    CFHTTPMessageSetHeaderFieldValue(request, CFSTR("Upgrade"), CFSTR("websocket"));
    CFHTTPMessageSetHeaderFieldValue(request, CFSTR("Connection"), CFSTR("Upgrade"));
    CFHTTPMessageSetHeaderFieldValue(request, CFSTR("Sec-WebSocket-Key"), (__bridge CFStringRef)_secKey);
    CFHTTPMessageSetHeaderFieldValue(request, CFSTR("Sec-WebSocket-Version"), (__bridge CFStringRef)[NSString stringWithFormat:@"%ld", (long)_webSocketVersion]);
    CFHTTPMessageSetHeaderFieldValue(request, CFSTR("Origin"), (__bridge CFStringRef)_url.SR_origin);
    
    // 子协议 可选
    if (_requestedProtocols) {
        CFHTTPMessageSetHeaderFieldValue(request, CFSTR("Sec-WebSocket-Protocol"), (__bridge CFStringRef)[_requestedProtocols componentsJoinedByString:@", "]);
    }

    // 设置 headers
    [_urlRequest.allHTTPHeaderFields enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
        CFHTTPMessageSetHeaderFieldValue(request, (__bridge CFStringRef)key, (__bridge CFStringRef)obj);
    }];
    
    // 将握手 http 请求报文转成 oc 对象
    NSData *message = CFBridgingRelease(CFHTTPMessageCopySerializedMessage(request));
    CFRelease(request);

    // 将握手请求报文写入
    [self _writeData:message];
    
    // 读取握手请求的 header 信息
    [self _readHTTPHeader];
    
    NSLog(@"");
}

- (void)_initializeStreams;
{
    // 判断端口号是否超过 32 位 unsigned int 大小
    assert(_url.port.unsignedIntValue <= UINT32_MAX);
    uint32_t port = _url.port.unsignedIntValue;
    
    // 如果端口没传，通过之前判断的 _secure 字段设置端口 80 或 443
    if (port == 0) {
        if (!_secure) {
            port = 80;
        } else {
            port = 443;
        }
    }
    
    // 拿到 url 的 host   如果有 happydns 解析出的 ip   则替换掉host
    NSString *host = _url.host;
    if (_ip && _ip.length != 0) {
        host = _ip;
    }
    
    CFReadStreamRef readStream = NULL;
    CFWriteStreamRef writeStream = NULL;
    
    // 通过 host 和 port 创建输入输出 stream
    CFStreamCreatePairWithSocketToHost(NULL, (__bridge CFStringRef)host, port, &readStream, &writeStream);
    
    // 将 CFReadStreamRef、CFWriteStreamRef 转成 oc 的 NSInputStream 和 NSOutputStream
    _outputStream = CFBridgingRelease(writeStream);
    _inputStream = CFBridgingRelease(readStream);
    
    // 设置输入输出流的代理
    _inputStream.delegate = self;
    _outputStream.delegate = self;
}

- (void)_updateSecureStreamOptions;
{
    // 如果是安全连接
    if (_secure) {
        NSMutableDictionary *SSLOptions = [[NSMutableDictionary alloc] init];
        
        // 设置 ssl 安全级别
        //  Indicates to use TLS or SSL with fallback to lower versions. This is what HTTPS does, for instance.
        [_outputStream setProperty:(__bridge id)kCFStreamSocketSecurityLevelNegotiatedSSL forKey:(__bridge id)kCFStreamPropertySocketSecurityLevel];
        
        // 如果是自签证书，不验证证书链
        // If we're using pinned certs, don't validate the certificate chain
        if ([_urlRequest SR_SSLPinnedCertificates].count) {
            [SSLOptions setValue:@NO forKey:(__bridge id)kCFStreamSSLValidatesCertificateChain];
        }
        
#if DEBUG
        self.allowsUntrustedSSLCertificates = YES;
#endif

        // 如果允许不受信的证书  则不验证证书链
        if (self.allowsUntrustedSSLCertificates) {
            [SSLOptions setValue:@NO forKey:(__bridge id)kCFStreamSSLValidatesCertificateChain];
            SRFastLog(@"Allowing connection to any root cert");
        }
        
        // 如果已经用 ip 替代域名连接  需要在 ssl 校验时指明域名
        if (_ip) {
            [SSLOptions setValue:_url.host forKey:(__bridge id)kCFStreamSSLPeerName];
        }
        
        // 给输出流设置 ssl setting
        [_outputStream setProperty:SSLOptions
                            forKey:(__bridge id)kCFStreamPropertySSLSettings];
    }
    
    // 设置代理
    _inputStream.delegate = self;
    _outputStream.delegate = self;
    
    // 给输入输出流设置服务类型
    [self setupNetworkServiceType:_urlRequest.networkServiceType];
}

// 配置网络服务类型
- (void)setupNetworkServiceType:(NSURLRequestNetworkServiceType)requestNetworkServiceType
{
    NSString *networkServiceType;
    switch (requestNetworkServiceType) {
        case NSURLNetworkServiceTypeDefault:
            break;
        case NSURLNetworkServiceTypeVoIP: {
            networkServiceType = NSStreamNetworkServiceTypeVoIP;
#if TARGET_OS_IPHONE && __IPHONE_9_0
            if (floor(NSFoundationVersionNumber) > NSFoundationVersionNumber_iOS_8_3) {
                static dispatch_once_t predicate;
                dispatch_once(&predicate, ^{
                    NSLog(@"SocketRocket: %@ - this service type is deprecated in favor of using PushKit for VoIP control", networkServiceType);
                });
            }
#endif
            break;
        }
        case NSURLNetworkServiceTypeVideo:
            networkServiceType = NSStreamNetworkServiceTypeVideo;
            break;
        case NSURLNetworkServiceTypeBackground:
            networkServiceType = NSStreamNetworkServiceTypeBackground;
            break;
        case NSURLNetworkServiceTypeVoice:
            networkServiceType = NSStreamNetworkServiceTypeVoice;
            break;
    }
    
    if (networkServiceType != nil) {
        [_inputStream setProperty:networkServiceType forKey:NSStreamNetworkServiceType];
        [_outputStream setProperty:networkServiceType forKey:NSStreamNetworkServiceType];
    }
}

- (void)openConnection;
{
    // 给输入输出流配置安全设置和网络类型
    [self _updateSecureStreamOptions];
    
    // 给输入输出流绑定 runloop
    if (!_scheduledRunloops.count) {
        [self scheduleInRunLoop:[NSRunLoop SR_networkRunLoop] forMode:NSDefaultRunLoopMode];
    }
    
    if (self.readyState >= SR_CLOSING) {
        return;
    }
    
    // 更新状态 - tcp连接中
    _readyState = SR_TCP_CONNECTING;
    [self _performDelegateBlock:^{
        if (self.delegate && [self.delegate respondsToSelector:@selector(webSocket:readyStateDidChange:)]) {
            [self.delegate webSocket:self readyStateDidChange:SR_TCP_CONNECTING];
        }
    }];
    
    // 打开输入输出流   这里会与服务端做 tcp 连接  完成会回调 handleEvent 方法 NSStreamEventOpenCompleted 事件
    [_outputStream open];
    [_inputStream open];
}

// 输入输出流添加 runloop，加入到缓存队列
- (void)scheduleInRunLoop:(NSRunLoop *)aRunLoop forMode:(NSString *)mode;
{
    [_outputStream scheduleInRunLoop:aRunLoop forMode:mode];
    [_inputStream scheduleInRunLoop:aRunLoop forMode:mode];
    
    [_scheduledRunloops addObject:@[aRunLoop, mode]];
}

// 输入输出流移除 runloop，从缓存队列移除
- (void)unscheduleFromRunLoop:(NSRunLoop *)aRunLoop forMode:(NSString *)mode;
{
    [_outputStream removeFromRunLoop:aRunLoop forMode:mode];
    [_inputStream removeFromRunLoop:aRunLoop forMode:mode];
    
    [_scheduledRunloops removeObject:@[aRunLoop, mode]];
}

// 外部手动调用 close 关闭连接
- (void)close;
{
    [self closeWithCode:SRStatusCodeNormal reason:nil];
}

- (void)closeWithCode:(NSInteger)code reason:(NSString *)reason;
{
    assert(code);
    dispatch_async(_workQueue, ^{
        if (self.readyState == SR_CLOSING || self.readyState == SR_CLOSED) {
            return;
        }
        
        BOOL wasConnecting = self.readyState == SR_TCP_CONNECTING;
        
        // 更新状态 - 关闭中
        self.readyState = SR_CLOSING;
        [self _performDelegateBlock:^{
            if (self.delegate && [self.delegate respondsToSelector:@selector(webSocket:readyStateDidChange:)]) {
                [self.delegate webSocket:self readyStateDidChange:SR_CLOSING];
            }
        }];
        
        SRFastLog(@"Closing with code %d reason %@", code, reason);
        
        // 如果是在链接中   直接关掉链接
        if (wasConnecting) {
            [self closeConnection];
            return;
        }

        // 计算 reason 用 UTF8 编码后所占最大字节数
        size_t maxMsgSize = [reason maximumLengthOfBytesUsingEncoding:NSUTF8StringEncoding];
        
        // 创建 payload 缓存   length = code的2字节 + maxMsgSize
        NSMutableData *mutablePayload = [[NSMutableData alloc] initWithLength:sizeof(uint16_t) + maxMsgSize];
        NSData *payload = mutablePayload;
        
        // code 放进去
        ((uint16_t *)mutablePayload.mutableBytes)[0] = EndianU16_BtoN(code);
        
        if (reason) {
            NSRange remainingRange = {0};
            
            NSUInteger usedLength = 0;
            
            // reason 放进去
            BOOL success = [reason getBytes:(char *)mutablePayload.mutableBytes + sizeof(uint16_t) maxLength:payload.length - sizeof(uint16_t) usedLength:&usedLength encoding:NSUTF8StringEncoding options:NSStringEncodingConversionExternalRepresentation range:NSMakeRange(0, reason.length) remainingRange:&remainingRange];
            #pragma unused (success)
            
            assert(success);
            assert(remainingRange.length == 0);

            // 如果实际使用字节数的比预估的少  截掉多余部分
            if (usedLength != maxMsgSize) {
                payload = [payload subdataWithRange:NSMakeRange(0, usedLength + sizeof(uint16_t))];
            }
        }
        
        // 发送 close 帧给服务端
        [self _sendFrameWithOpcode:SROpCodeConnectionClose data:payload];
    });
}

- (void)_closeWithProtocolError:(NSString *)message;
{
    // Need to shunt this on the _callbackQueue first to see if they received any messages 
    [self _performDelegateBlock:^{
        [self closeWithCode:SRStatusCodeProtocolError reason:message];
        dispatch_async(_workQueue, ^{
            [self closeConnection];
        });
    }];
}

- (void)failWithError:(NSError *)error;
{
    dispatch_async(_workQueue, ^{
        if (self.readyState != SR_CLOSED) {
            _failed = YES;
            [self _performDelegateBlock:^{
                if ([self.delegate respondsToSelector:@selector(webSocket:didFailWithError:)]) {
                    [self.delegate webSocket:self didFailWithError:error];
                }
            }];

            // 更新状态 - 已关闭
            self.readyState = SR_CLOSED;
            [self _performDelegateBlock:^{
                if (self.delegate && [self.delegate respondsToSelector:@selector(webSocket:readyStateDidChange:)]) {
                    [self.delegate webSocket:self readyStateDidChange:SR_CLOSED];
                }
            }];

            SRFastLog(@"Failing with error %@", error.localizedDescription);
            
            [self closeConnection];
            [self _scheduleCleanup];
        }
    });
}

- (void)_writeData:(NSData *)data;
{
    // 判断当前是否是在 work 线程
    [self assertOnWorkQueue];

    // 如果连接正在关闭 直接返回
    if (_closeWhenFinishedWriting) {
            return;
    }
    
    // 将握手请求报文 append 到输出缓冲区
    [_outputBuffer appendData:data];
    
    // 将输出缓冲区的数据写入到输出流中
    [self _pumpWriting];
}

- (void)send:(id)data;
{
    NSAssert(self.readyState != SR_TCP_CONNECTING, @"Invalid State: Cannot call send: until connection is open");
    // TODO: maybe not copy this for performance
    data = [data copy];
    dispatch_async(_workQueue, ^{
        if ([data isKindOfClass:[NSString class]]) {
            [self _sendFrameWithOpcode:SROpCodeTextFrame data:[(NSString *)data dataUsingEncoding:NSUTF8StringEncoding]];
        } else if ([data isKindOfClass:[NSData class]]) {
            [self _sendFrameWithOpcode:SROpCodeBinaryFrame data:data];
        } else if (data == nil) {
            [self _sendFrameWithOpcode:SROpCodeTextFrame data:data];
        } else {
            assert(NO);
        }
    });
}

- (void)sendPing:(NSData *)data;
{
    NSAssert(self.readyState == SR_OPEN, @"Invalid State: Cannot call send: until connection is open");
    // TODO: maybe not copy this for performance
    data = [data copy] ?: [NSData data]; // It's okay for a ping to be empty
    dispatch_async(_workQueue, ^{
        [self _sendFrameWithOpcode:SROpCodePing data:data];
    });
}

- (void)handlePing:(NSData *)pingData;
{
    // Need to pingpong this off _callbackQueue first to make sure messages happen in order
    [self _performDelegateBlock:^{
        dispatch_async(_workQueue, ^{
            [self _sendFrameWithOpcode:SROpCodePong data:pingData];
        });
    }];
}

- (void)handlePong:(NSData *)pongData;
{
    SRFastLog(@"Received pong");
    [self _performDelegateBlock:^{
        if ([self.delegate respondsToSelector:@selector(webSocket:didReceivePong:)]) {
            [self.delegate webSocket:self didReceivePong:pongData];
        }
    }];
}

- (void)_handleMessage:(id)message
{
    SRFastLog(@"Received message");
    [self _performDelegateBlock:^{
        [self.delegate webSocket:self didReceiveMessage:message];
    }];
}

// 判断 websocket close code 是否有效  参考：https://chenjianlong.gitbooks.io/rfc-6455-websocket-protocol-in-chinese/content/section7/section7.html
static inline BOOL closeCodeIsValid(int closeCode) {
    if (closeCode < 1000) {
        return NO;
    }
    
    if (closeCode >= 1000 && closeCode <= 1011) {
        if (closeCode == 1004 ||
            closeCode == 1005 ||
            closeCode == 1006) {
            return NO;
        }
        return YES;
    }
    
    if (closeCode >= 3000 && closeCode <= 3999) {
        return YES;
    }
    
    if (closeCode >= 4000 && closeCode <= 4999) {
        return YES;
    }

    return NO;
}

//  Note from RFC:
//
//  If there is a body, the first two
//  bytes of the body MUST be a 2-byte unsigned integer (in network byte
//  order) representing a status code with value /code/ defined in
//  Section 7.4.  Following the 2-byte integer the body MAY contain UTF-8
//  encoded data with value /reason/, the interpretation of which is not
//  defined by this specification.

- (void)handleCloseWithData:(NSData *)data;
{
    size_t dataSize = data.length;
    __block uint16_t closeCode = 0;
    
    SRFastLog(@"Received close frame");
    
    // 判断数据长度
    if (dataSize == 1) {
        // TODO handle error
        [self _closeWithProtocolError:@"Payload for close must be larger than 2 bytes"];
        return;
    } else if (dataSize >= 2) {
        // 尝试读取 close code
        [data getBytes:&closeCode length:sizeof(closeCode)];
        _closeCode = EndianU16_BtoN(closeCode);
        if (!closeCodeIsValid(_closeCode)) {
            [self _closeWithProtocolError:[NSString stringWithFormat:@"Cannot have close code of %d", _closeCode]];
            return;
        }
        if (dataSize > 2) {
            // 尝试读取 close reason
            _closeReason = [[NSString alloc] initWithData:[data subdataWithRange:NSMakeRange(2, dataSize - 2)] encoding:NSUTF8StringEncoding];
            if (!_closeReason) {
                [self _closeWithProtocolError:@"Close reason MUST be valid UTF-8"];
                return;
            }
        }
    } else {
        _closeCode = SRStatusNoStatusReceived;
    }
    
    [self assertOnWorkQueue];
    
    // 发送 close 消息给服务端
    if (self.readyState == SR_OPEN) {
        [self closeWithCode:1000 reason:nil];
    }
    
    // 处理关闭
    dispatch_async(_workQueue, ^{
        [self closeConnection];
    });
}

- (void)closeConnection;
{
    // 判断当前是否在 work 线程
    [self assertOnWorkQueue];
    SRFastLog(@"Trying to disconnect");
    
    // 标识在完成写入后关闭链接
    _closeWhenFinishedWriting = YES;
    
    // 处理输出流
    [self _pumpWriting];
}

- (void)_handleFrameWithData:(NSData *)frameData opCode:(NSInteger)opcode;
{                
    // Check that the current data is valid UTF8
    
    BOOL isControlFrame = (opcode == SROpCodePing || opcode == SROpCodePong || opcode == SROpCodeConnectionClose);
    if (!isControlFrame) {
        // 如果是数据帧  清空上一帧信息
        [self _readFrameNew];
    } else {
        // 如果是控制帧  直接开始读下一个 header
        dispatch_async(_workQueue, ^{
            [self _readFrameContinue];
        });
    }
    
    //frameData will be copied before passing to handlers
    //otherwise there can be misbehaviours when value at the pointer is changed
    switch (opcode) {
        case SROpCodeTextFrame: {
            if ([self.delegate respondsToSelector:@selector(webSocketShouldConvertTextFrameToString:)] && ![self.delegate webSocketShouldConvertTextFrameToString:self]) {
                // 如果不需要转成字符串  直接回调二进制
                [self _handleMessage:[frameData copy]];
            } else {
                // 转成字符串回调上层  如果报错则断开链接返回
                NSString *str = [[NSString alloc] initWithData:frameData encoding:NSUTF8StringEncoding];
                if (str == nil && frameData) {
                    [self closeWithCode:SRStatusCodeInvalidUTF8 reason:@"Text frames must be valid UTF-8"];
                    dispatch_async(_workQueue, ^{
                        [self closeConnection];
                    });
                    return;
                }
                [self _handleMessage:str];
            }
            break;
        }
        case SROpCodeBinaryFrame:
            // 回调二进制
            [self _handleMessage:[frameData copy]];
            break;
        case SROpCodeConnectionClose:
            // 处理 close
            [self handleCloseWithData:[frameData copy]];
            break;
        case SROpCodePing:
            [self handlePing:[frameData copy]];
            break;
        case SROpCodePong:
            [self handlePong:[frameData copy]];
            break;
        default:
            // 如果是其他 opcode 直接关闭链接
            [self _closeWithProtocolError:[NSString stringWithFormat:@"Unknown opcode %ld", (long)opcode]];
            // TODO: Handle invalid opcode
            break;
    }
}

- (void)_handleFrameHeader:(frame_header)frame_header curData:(NSData *)curData;
{
    assert(frame_header.opcode != 0);
    
    if (self.readyState == SR_CLOSED) {
        return;
    }
    
    // 判断是否是控制帧
    BOOL isControlFrame = (frame_header.opcode == SROpCodePing || frame_header.opcode == SROpCodePong || frame_header.opcode == SROpCodeConnectionClose);
    
    // 如果当前是控制帧  fin没有用1来标记是信息的最后一帧  直接关闭链接返回
    if (isControlFrame && !frame_header.fin) {
        [self _closeWithProtocolError:@"Fragmented control frames not allowed"];
        return;
    }
    
    // 如果当前是控制帧  payload_length 是126或127  直接关闭链接返回
    if (isControlFrame && frame_header.payload_length >= 126) {
        [self _closeWithProtocolError:@"Control frames cannot have payloads larger than 126 bytes"];
        return;
    }
    
    // 0x1 文本帧  0x2 二进制帧  更新 _currentFrameOpcode 和 _currentFrameCount
    if (!isControlFrame) {
        _currentFrameOpcode = frame_header.opcode;
        _currentFrameCount += 1;
    }
    
    if (frame_header.payload_length == 0) {
        // payload length 为0
        if (isControlFrame) {
            // 如果是控制帧   直接处理帧数据
            [self _handleFrameWithData:curData opCode:frame_header.opcode];
        } else {
            // 如果不是控制帧
            if (frame_header.fin) {
                // 如果是当前信息的最后一帧  直接处理帧数据
                [self _handleFrameWithData:_currentFrameData opCode:frame_header.opcode];
            } else {
                // TODO add assert that opcode is not a control;
                // 如果不是当前信息的最后一帧  继续读下一个
                [self _readFrameContinue];
            }
        }
    } else {
        // payload length 不为0
        assert(frame_header.payload_length <= SIZE_T_MAX);
        // 创建一个读取 payload 数据的消费者
        [self _addConsumerWithDataLength:(size_t)frame_header.payload_length callback:^(SRWebSocket *self, NSData *newData) {
            if (isControlFrame) {
                [self _handleFrameWithData:newData opCode:frame_header.opcode];
            } else {
                if (frame_header.fin) {
                    [self _handleFrameWithData:self->_currentFrameData opCode:frame_header.opcode];
                } else {
                    // TODO add assert that opcode is not a control;
                    [self _readFrameContinue];
                }
            }
        } readToCurrentFrame:!isControlFrame unmaskBytes:frame_header.masked];
    }
}

/* From RFC:

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-------+-+-------------+-------------------------------+
 |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
 |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
 |N|V|V|V|       |S|             |   (if payload len==126/127)   |
 | |1|2|3|       |K|             |                               |
 +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
 |     Extended payload length continued, if payload len == 127  |
 + - - - - - - - - - - - - - - - +-------------------------------+
 |                               |Masking-key, if MASK set to 1  |
 +-------------------------------+-------------------------------+
 | Masking-key (continued)       |          Payload Data         |
 +-------------------------------- - - - - - - - - - - - - - - - +
 :                     Payload Data continued ...                :
 + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
 |                     Payload Data continued ...                |
 +---------------------------------------------------------------+
 */

/*
    FIN      1bit 表示信息的最后一帧，flag，也就是标记符
    RSV 1-3  1bit each 以后备用的 默认都为 0
    Opcode   4bit 帧类型，稍后细说
    Mask     1bit 掩码，是否加密数据，只适用于客户端发给服务器的消息，客户端给服务器发送消息，这里一定为 1
    Payload  7bit 数据的长度
    Masking-key      1 or 4 bit 掩码Key
    Payload data     (x + y) bytes 数据
    Extension data   x bytes  扩展数据
    Application data y bytes  程序数据
 */

/*
 Opcode 字段代表的意思如下所示：
     %x0：表示一个延续帧。当Opcode为0时，表示本次数据传输采用了数据分片，当前收到的数据帧为其中一个数据分片。
     %x1：表示这是一个文本帧（frame）
     %x2：表示这是一个二进制帧（frame）
     %x3-7：保留的操作代码，用于后续定义的非控制帧。
     %x8：表示连接断开。
     %x9：表示这是一个ping操作。
     %xA：表示这是一个pong操作。
     %xB-F：保留的操作代码，用于后续定义的控制帧。
 */

static const uint8_t SRFinMask          = 0x80;
static const uint8_t SROpCodeMask       = 0x0F;
static const uint8_t SRRsvMask          = 0x70;
static const uint8_t SRMaskMask         = 0x80;
static const uint8_t SRPayloadLenMask   = 0x7F;


- (void)_readFrameContinue;
{
    assert((_currentFrameCount == 0 && _currentFrameOpcode == 0) || (_currentFrameCount > 0 && _currentFrameOpcode > 0));

    // 创建一个只读取前两个字节的消费者
    [self _addConsumerWithDataLength:2 callback:^(SRWebSocket *self, NSData *data) {
        // 初始化帧头部信息
        __block frame_header header = {0};
        
        const uint8_t *headerBuffer = data.bytes;
        assert(data.length >= 2);
        
        // 判断当前数据首字节 2-4 位是否都为 0    不为0则直接关闭连接    SRRsvMask：01110000
        if (headerBuffer[0] & SRRsvMask) {
            [self _closeWithProtocolError:@"Server used RSV bits"];
            return;
        }
        
        // 读取首字节后四位   拿到 opcode     SROpCodeMask：00001111
        uint8_t receivedOpcode = (SROpCodeMask & headerBuffer[0]);
        
        // 根据协议规定   判断是否是控制帧（ping、pong、close）
        BOOL isControlFrame = (receivedOpcode == SROpCodePing || receivedOpcode == SROpCodePong || receivedOpcode == SROpCodeConnectionClose);
        
        // 如果当前是一个非延续的数据帧  并且 _currentFrameCount 大于 0   直接断开链接返回
        if (!isControlFrame && receivedOpcode != 0 && self->_currentFrameCount > 0) {
            [self _closeWithProtocolError:@"all data frames after the initial data frame must have opcode 0"];
            return;
        }
        
        // 如果当前是一个延续的数据帧  并且 _currentFrameCount 等于0   直接断开链接返回
        if (receivedOpcode == 0 && self->_currentFrameCount == 0) {
            [self _closeWithProtocolError:@"cannot continue a message"];
            return;
        }
        
        // 设置 header  这里把延续帧的 opcode 设置成当前帧的数据类型
        header.opcode = receivedOpcode == 0 ? self->_currentFrameOpcode : receivedOpcode;
        header.fin = !!(SRFinMask & headerBuffer[0]);
        header.masked = !!(SRMaskMask & headerBuffer[1]);
        header.payload_length = SRPayloadLenMask & headerBuffer[1];
        
        headerBuffer = NULL;
        
        // 如果解析到 mask 位为1  直接断开链接
        if (header.masked) {
            [self _closeWithProtocolError:@"Client must receive unmasked data"];
        }
        
        // 如果 mask 位为1  帧数据中会包含 4 位的 Masking-key
        size_t extra_bytes_needed = header.masked ? sizeof(_currentReadMaskKey) : 0;
        
        // 如果 payload_length 是 126 或 127   帧数据中会包含 16 位或 64 位的 extended payload length
        if (header.payload_length == 126) {
            extra_bytes_needed += sizeof(uint16_t);
        } else if (header.payload_length == 127) {
            extra_bytes_needed += sizeof(uint64_t);
        }
        
        if (extra_bytes_needed == 0) {
            // 如果 extra_bytes_needed 为0  直接处理 header 读取 payload
            [self _handleFrameHeader:header curData:self->_currentFrameData];
        } else {
            // 如果 extra_bytes_needed 不为0  创建一个读取 extended 字节的消费者
            [self _addConsumerWithDataLength:extra_bytes_needed callback:^(SRWebSocket *self, NSData *data) {
                size_t mapped_size = data.length;
                #pragma unused (mapped_size)
                const void *mapped_buffer = data.bytes;
                size_t offset = 0;
                
                // 先读 extended payload length
                if (header.payload_length == 126) {
                    assert(mapped_size >= sizeof(uint16_t));
                    uint16_t newLen = EndianU16_BtoN(*(uint16_t *)(mapped_buffer));
                    header.payload_length = newLen;
                    offset += sizeof(uint16_t);
                } else if (header.payload_length == 127) {
                    assert(mapped_size >= sizeof(uint64_t));
                    header.payload_length = EndianU64_BtoN(*(uint64_t *)(mapped_buffer));
                    offset += sizeof(uint64_t);
                } else {
                    // 没有 extension_payload_length
                    assert(header.payload_length < 126 && header.payload_length >= 0);
                }
                
                // 再读 Masking-Key
                if (header.masked) {
                    // 这里的 _currentReadMaskOffset 应该是写错了 应该是sizeof(_currentReadMaskKey)
                    assert(mapped_size >= sizeof(_currentReadMaskOffset) + offset);
                    memcpy(self->_currentReadMaskKey, ((uint8_t *)mapped_buffer) + offset, sizeof(self->_currentReadMaskKey));
                }
                
                // 接着处理 header、读取 payload
                [self _handleFrameHeader:header curData:self->_currentFrameData];
            } readToCurrentFrame:NO unmaskBytes:NO];
        }
    } readToCurrentFrame:NO unmaskBytes:NO];
}

- (void)_readFrameNew;
{
    dispatch_async(_workQueue, ^{
        // 清空帧数据
        [_currentFrameData setLength:0];
        _currentFrameOpcode = 0;
        _currentFrameCount = 0;
        _readOpCount = 0;
        _currentStringScanPosition = 0;
        
        [self _readFrameContinue];
    });
}

- (void)_pumpWriting;
{
    // 判断是否在 work 线程
    [self assertOnWorkQueue];
    
    // 判断是否有未写入的数据缓存 并且目前是可写状态
    NSUInteger dataLength = _outputBuffer.length;
    if (dataLength - _outputBufferOffset > 0 && _outputStream.hasSpaceAvailable) {
        // 将当前未写入的数据缓存写入到输出流
        NSInteger bytesWritten = [_outputStream write:_outputBuffer.bytes + _outputBufferOffset maxLength:dataLength - _outputBufferOffset];
        
        // 如果写入失败  主动断开连接
        if (bytesWritten == -1) {
            [self failWithError:[NSError errorWithDomain:SRWebSocketErrorDomain code:2145 userInfo:[NSDictionary dictionaryWithObject:@"Error writing to stream" forKey:NSLocalizedDescriptionKey]]];
             return;
        }
        
        // 更新已写偏移量
        _outputBufferOffset += bytesWritten;
        
        // 如果当前已写的数据超过 4096 并且超过偏移量超过缓存区数据的一半 清空掉已写数据  重置偏移量  避免缓存过大
        if (_outputBufferOffset > 4096 && _outputBufferOffset > (_outputBuffer.length >> 1)) {
            _outputBuffer = [[NSMutableData alloc] initWithBytes:(char *)_outputBuffer.bytes + _outputBufferOffset length:_outputBuffer.length - _outputBufferOffset];
            _outputBufferOffset = 0;
        }
    }
    
    // _closeWhenFinishedWriting 为 yes，并且所有数据都已写入完成，此时关闭连接，回调给上层
    if (_closeWhenFinishedWriting && 
        _outputBuffer.length - _outputBufferOffset == 0 && 
        (_inputStream.streamStatus != NSStreamStatusNotOpen &&
         _inputStream.streamStatus != NSStreamStatusClosed) &&
        !_sentClose) {
        _sentClose = YES;
        
        @synchronized(self) {
            [_outputStream close];
            [_inputStream close];
            
            
            // 清空 runloop 缓存池
            for (NSArray *runLoop in [_scheduledRunloops copy]) {
                [self unscheduleFromRunLoop:[runLoop objectAtIndex:0] forMode:[runLoop objectAtIndex:1]];
            }
        }
        
        // 如果没有 failWithError 需要回调 didCloseWithCode
        if (!_failed) {
            [self _performDelegateBlock:^{
                if ([self.delegate respondsToSelector:@selector(webSocket:didCloseWithCode:reason:wasClean:)]) {
                    [self.delegate webSocket:self didCloseWithCode:_closeCode reason:_closeReason wasClean:YES];
                }
            }];
        }
        
        // 释放输入输出流
        [self _scheduleCleanup];
    }
}

- (void)_addConsumerWithScanner:(stream_scanner)consumer callback:(data_callback)callback;
{
    // 判断是否还在 work 线程
    [self assertOnWorkQueue];
    
    // 这里的 dataLength 是为了给消费者的 dataLength 赋值，http header 是不定长的，所以这里写 0
    [self _addConsumerWithScanner:consumer callback:callback dataLength:0];
}

// 这个消费者构造方法用于解析 ws 的 frame  其他的方法用于解析 http header
- (void)_addConsumerWithDataLength:(size_t)dataLength callback:(data_callback)callback readToCurrentFrame:(BOOL)readToCurrentFrame unmaskBytes:(BOOL)unmaskBytes;
{
    // 判断是否在 work 线程
    [self assertOnWorkQueue];
    assert(dataLength);
    
    // 从消费者缓存池取出消费者  赋值后添加到消费者队列中
    [_consumers addObject:[_consumerPool consumerWithScanner:nil handler:callback bytesNeeded:dataLength readToCurrentFrame:readToCurrentFrame unmaskBytes:unmaskBytes]];
    
    // 尝试读取数据
    [self _pumpScanner];
}

- (void)_addConsumerWithScanner:(stream_scanner)consumer callback:(data_callback)callback dataLength:(size_t)dataLength;
{
    // 判断是否还在 work 线程
    [self assertOnWorkQueue];
    
    // 从消费者缓存池取出消费者  赋值后添加到消费者队列中
    [_consumers addObject:[_consumerPool consumerWithScanner:consumer handler:callback bytesNeeded:dataLength readToCurrentFrame:NO unmaskBytes:NO]];
    
    // 尝试读取数据
    [self _pumpScanner];
}


- (void)_scheduleCleanup
{
    @synchronized(self) {
        if (_cleanupScheduled) {
            return;
        }
        
        _cleanupScheduled = YES;
        
        // Cleanup NSStream delegate's in the same RunLoop used by the streams themselves:
        // This way we'll prevent race conditions between handleEvent and SRWebsocket's dealloc
        NSTimer *timer = [NSTimer timerWithTimeInterval:(0.0f) target:self selector:@selector(_cleanupSelfReference:) userInfo:nil repeats:NO];
        [[NSRunLoop SR_networkRunLoop] addTimer:timer forMode:NSDefaultRunLoopMode];
    }
}

- (void)_cleanupSelfReference:(NSTimer *)timer
{
    @synchronized(self) {
        // Nuke NSStream delegate's
        _inputStream.delegate = nil;
        _outputStream.delegate = nil;
        
        // Remove the streams, right now, from the networkRunLoop
        [_inputStream close];
        [_outputStream close];
    }
    
    // Cleanup selfRetain in the same GCD queue as usual
    dispatch_async(_workQueue, ^{
        _selfRetain = nil;
    });
}


static const char CRLFCRLFBytes[] = {'\r', '\n', '\r', '\n'};

- (void)_readUntilHeaderCompleteWithCallback:(data_callback)dataHandler;
{
    // 传入匹配规则： '\r', '\n', '\r', '\n' ，匹配字符个数，和数据处理的 callback
    [self _readUntilBytes:CRLFCRLFBytes length:sizeof(CRLFCRLFBytes) callback:dataHandler];
}

- (void)_readUntilBytes:(const void *)bytes length:(size_t)length callback:(data_callback)dataHandler;
{
    // TODO optimize so this can continue from where we last searched
    // 这是一个计算 data 出现匹配字符的位置，返回 data 从开始到匹配字符截止的 byte 长度
    stream_scanner consumer = ^size_t(NSData *data) {
        __block size_t found_size = 0;
        __block size_t match_count = 0;
        
        size_t size = data.length;
        const unsigned char *buffer = data.bytes;
        for (size_t i = 0; i < size; i++ ) {
            // 将 data 中的 byte 与匹配字符中的 byte 逐一比对
            if (((const unsigned char *)buffer)[i] == ((const unsigned char *)bytes)[match_count]) {
                // 如果发现当前 byte 匹配  则切换到下一个匹配字符
                match_count += 1;
                // 如果已经是最后一个字符  说明已找到了匹配所有字符的位置  将 found_size 加 1 返回
                if (match_count == length) {
                    found_size = i + 1;
                    break;
                }
            } else {
                // 如果不匹配  将匹配字符索引重置
                match_count = 0;
            }
        }
        return found_size;
    };
    
    // 将计算匹配的数据长度 callback 和数据处理 callback 传入下一个方法
    [self _addConsumerWithScanner:consumer callback:dataHandler];
}


// Returns true if did work
- (BOOL)_innerPumpScanner {
    
    BOOL didWork = NO;
    
    // 如果当前是关闭、正在关闭状态，直接返回 NO，打断读取循环
    if (self.readyState >= SR_CLOSED) {
        return didWork;
    }
    
    // 如果没有消费者，直接返回 NO，打断读取循环
    if (!_consumers.count) {
        return didWork;
    }
    
    size_t curSize = _readBuffer.length - _readBufferOffset;
    // 如果已读偏移量和当前缓冲区里的可读数据长度一致，说明当前没有数据可读，直接返回 NO，打断读取循环
    // http 请求在这里是会直接返回 NO，因为此时可能还没有收到 http response，这也是 _readUntilHeaderCompleteWithCallback 方法并没有阻塞线程的原因
    if (!curSize) {
        return didWork;
    }
    
    // 从消费者队列里取出一个消费者
    SRIOConsumer *consumer = [_consumers objectAtIndex:0];
    size_t bytesNeeded = consumer.bytesNeeded;
    
    // 标识这个消费者需要的数据长度
    size_t foundSize = 0;
    if (consumer.consumer) {
        // 如果这个消费者携带计算匹配数据长度的 callback   就读取当前缓冲区中未读的数据   计算匹配的数据长度
        NSData *tempView = [NSData dataWithBytesNoCopy:(char *)_readBuffer.bytes + _readBufferOffset length:_readBuffer.length - _readBufferOffset freeWhenDone:NO];  
        foundSize = consumer.consumer(tempView);
    } else {
        // 如果不包含这个 callback，说明需要的是固定长度，这里判断 bytesNeeded 是否为0，为0直接 assert
        assert(consumer.bytesNeeded);
        if (curSize >= bytesNeeded) {
            // 待读的数据比所需数据长度长  读取 bytesNeeded 大小
            foundSize = bytesNeeded;
        } else if (consumer.readToCurrentFrame) {
            // 有可能缓存区的可读数据比消费者需要的字节要少  如果是数据帧  先将这部分也读取下来
            foundSize = curSize;
        }
    }
    
    NSData *slice = nil;
    if (consumer.readToCurrentFrame || foundSize) {
        
        // 读取消费者匹配数据
        NSRange sliceRange = NSMakeRange(_readBufferOffset, foundSize);
        slice = [_readBuffer subdataWithRange:sliceRange];
        
        // 更新已读偏移量
        _readBufferOffset += foundSize;
        
        // 已读偏移量大于 4096 并且已读偏移超过缓冲区一半   将偏移量重置  释放部分缓冲区内存
        if (_readBufferOffset > 4096 && _readBufferOffset > (_readBuffer.length >> 1)) {
            _readBuffer = [[NSMutableData alloc] initWithBytes:(char *)_readBuffer.bytes + _readBufferOffset length:_readBuffer.length - _readBufferOffset];
            _readBufferOffset = 0;
        }
        
        // 如果消费者读到的帧头部 Mask 是1
        if (consumer.unmaskBytes) {
            NSMutableData *mutableSlice = [slice mutableCopy];
            
            NSUInteger len = mutableSlice.length;
            uint8_t *bytes = mutableSlice.mutableBytes;
            
            // 用当前帧中的 Masking-Key 对数据做异或运算
            for (NSUInteger i = 0; i < len; i++) {
                bytes[i] = bytes[i] ^ _currentReadMaskKey[_currentReadMaskOffset % sizeof(_currentReadMaskKey)];
                _currentReadMaskOffset += 1;
            }
            
            slice = mutableSlice;
        }
        
        // 如果是文本帧、bit帧或延续帧
        if (consumer.readToCurrentFrame) {
            // slice 拼接到当前 opcode 的 payload 缓存上
            [_currentFrameData appendData:slice];
            
            _readOpCount += 1;
            
            if (_currentFrameOpcode == SROpCodeTextFrame) {
                // Validate UTF8 stuff.
                size_t currentDataSize = _currentFrameData.length;
                if (_currentFrameOpcode == SROpCodeTextFrame && currentDataSize > 0) {
                    // TODO: Optimize the crap out of this.  Don't really have to copy all the data each time
                    
                    size_t scanSize = currentDataSize - _currentStringScanPosition;
                    
                    // 验证新拼接的文本数据是否是有效的 UTF-8
                    NSData *scan_data = [_currentFrameData subdataWithRange:NSMakeRange(_currentStringScanPosition, scanSize)];
                    int32_t valid_utf8_size = validate_dispatch_data_partial_string(scan_data);
                    
                    if (valid_utf8_size == -1) {
                        [self closeWithCode:SRStatusCodeInvalidUTF8 reason:@"Text frames must be valid UTF-8"];
                        dispatch_async(_workQueue, ^{
                            [self closeConnection];
                        });
                        return didWork;
                    } else {
                        _currentStringScanPosition += valid_utf8_size;
                    }
                } 
            }
            
            // 把已读字节从 consumer.bytesNeeded 上减除
            consumer.bytesNeeded -= foundSize;
            
            // 如果 consumer.bytesNeeded 为0  说明该数据帧所有数据都已读取完成  回调处理数据帧
            if (consumer.bytesNeeded == 0) {
                [_consumers removeObjectAtIndex:0];
                consumer.handler(self, nil);
                [_consumerPool returnConsumer:consumer];
                didWork = YES;
            }
        } else if (foundSize) {
            // 匹配的数据已经拿到，将消费者从队列中移除
            [_consumers removeObjectAtIndex:0];
            
            // 回调消费者的数据处理 callback
            consumer.handler(self, slice);
            
            // 将消费者 pop 回缓存池
            [_consumerPool returnConsumer:consumer];
            
            // 接着读取
            didWork = YES;
        }
    }
    return didWork;
}

-(void)_pumpScanner;
{
    // 判断是否在 work 线程
    [self assertOnWorkQueue];
    
    // 如果正在读取  直接返回
    if (!_isPumping) {
        _isPumping = YES;
    } else {
        return;
    }
    
    // 循环读取
    while ([self _innerPumpScanner]) {
        
    }
    
    // 重置读取状态
    _isPumping = NO;
}

//#define NOMASK

static const size_t SRFrameHeaderOverhead = 32;

- (void)_sendFrameWithOpcode:(SROpCode)opcode data:(id)data;
{
    [self assertOnWorkQueue];
    
    if (nil == data) {
        return;
    }
    
    NSAssert([data isKindOfClass:[NSData class]] || [data isKindOfClass:[NSString class]], @"NSString or NSData");
    
    size_t payloadLength = [data isKindOfClass:[NSString class]] ? [(NSString *)data lengthOfBytesUsingEncoding:NSUTF8StringEncoding] : [data length];
        
    // 创建帧缓冲区  payload长度 + 32
    NSMutableData *frame = [[NSMutableData alloc] initWithLength:payloadLength + SRFrameHeaderOverhead];
    if (!frame) {
        [self closeWithCode:SRStatusCodeMessageTooBig reason:@"Message too big"];
        return;
    }
    uint8_t *frame_buffer = (uint8_t *)[frame mutableBytes];
    
    // 设置 fin 和 opcode
    frame_buffer[0] = SRFinMask | opcode;
    
    BOOL useMask = YES;
#ifdef NOMASK
    useMask = NO;
#endif
    
    // 如果使用 mask 则开启
    if (useMask) {
    // set the mask and header
        frame_buffer[1] |= SRMaskMask;
    }
    
    // 前两个固定字节
    size_t frame_buffer_size = 2;
    
    const uint8_t *unmasked_payload = NULL;
    if ([data isKindOfClass:[NSData class]]) {
        unmasked_payload = (uint8_t *)[data bytes];
    } else if ([data isKindOfClass:[NSString class]]) {
        unmasked_payload =  (const uint8_t *)[data UTF8String];
    } else {
        return;
    }
    
    if (payloadLength < 126) {
        // 如果 payloadLength 小于 126  说明没有 extended payload length
        frame_buffer[1] |= payloadLength;
    } else if (payloadLength <= UINT16_MAX) {
        // 如果用 16 位可以表示 payloadLength   则第2个字节设置成 126   第3、4个字节设置 payloadLength
        frame_buffer[1] |= 126;
        *((uint16_t *)(frame_buffer + frame_buffer_size)) = EndianU16_BtoN((uint16_t)payloadLength);
        // 字节数加16
        frame_buffer_size += sizeof(uint16_t);
    } else {
        // 如果超出 16 位的表示范围   则第2个字节设置成127  之后8个字节设置 payloadLength
        frame_buffer[1] |= 127;
        *((uint64_t *)(frame_buffer + frame_buffer_size)) = EndianU64_BtoN((uint64_t)payloadLength);
        // 字节数加64
        frame_buffer_size += sizeof(uint64_t);
    }
        
    if (!useMask) {
        // 如果没有 mask  直接将 payload 数据 copy 到 frame_buffer
        for (size_t i = 0; i < payloadLength; i++) {
            frame_buffer[frame_buffer_size] = unmasked_payload[i];
            frame_buffer_size += 1;
        }
    } else {
        // 如果有mask 移动指针到 payload length 或 extended payload length 后   生成32位随机数
        uint8_t *mask_key = frame_buffer + frame_buffer_size;
        SecRandomCopyBytes(kSecRandomDefault, sizeof(uint32_t), (uint8_t *)mask_key);
        // 字节数加32
        frame_buffer_size += sizeof(uint32_t);
        
        // TODO: could probably optimize this with SIMD
        // 将 payload 数据与 mask_key 做异或运算
        for (size_t i = 0; i < payloadLength; i++) {
            frame_buffer[frame_buffer_size] = unmasked_payload[i] ^ mask_key[i % sizeof(uint32_t)];
            frame_buffer_size += 1;
        }
    }

    assert(frame_buffer_size <= [frame length]);
    frame.length = frame_buffer_size;
    
    // 将数据写入缓存区
    [self _writeData:frame];
}

// 处理输入输出流的事件回调
- (void)stream:(NSStream *)aStream handleEvent:(NSStreamEvent)eventCode;
{
    __weak typeof(self) weakSelf = self;
    
    // 这里处理 pinned cert 的验证
    if (_secure && !_pinnedCertFound && (eventCode == NSStreamEventHasBytesAvailable || eventCode == NSStreamEventHasSpaceAvailable)) {
        
        NSArray *sslCerts = [_urlRequest SR_SSLPinnedCertificates];
        // 如果客户端有传 pinned cert
        if (sslCerts) {
            // 拿到 ssl 握手结果
            SecTrustRef secTrust = (__bridge SecTrustRef)[aStream propertyForKey:(__bridge id)kCFStreamPropertySSLPeerTrust];
            if (secTrust) {
                NSInteger numCerts = SecTrustGetCertificateCount(secTrust);
                // 用解析出的证书与客户端的挨个比对是否一致
                for (NSInteger i = 0; i < numCerts && !_pinnedCertFound; i++) {
                    SecCertificateRef cert = SecTrustGetCertificateAtIndex(secTrust, i);
                    NSData *certData = CFBridgingRelease(SecCertificateCopyData(cert));
                    
                    for (id ref in sslCerts) {
                        SecCertificateRef trustedCert = (__bridge SecCertificateRef)ref;
                        NSData *trustedCertData = CFBridgingRelease(SecCertificateCopyData(trustedCert));
                        
                        if ([trustedCertData isEqualToData:certData]) {
                            // 如果发现有一致则设为 YES
                            _pinnedCertFound = YES;
                            break;
                        }
                    }
                }
            }
            
            // 如果发现没有匹配给上层报错并断开链接，有匹配则继续做握手操作
            if (!_pinnedCertFound) {
                dispatch_async(_workQueue, ^{
                    NSDictionary *userInfo = @{ NSLocalizedDescriptionKey : @"Invalid server cert" };
                    [weakSelf failWithError:[NSError errorWithDomain:@"org.lolrus.SocketRocket" code:23556 userInfo:userInfo]];
                });
                return;
            } else if (aStream == _outputStream) {
                dispatch_async(_workQueue, ^{
                    [self didConnect];
                });
            }
        }
    }

    dispatch_async(_workQueue, ^{
        [weakSelf safeHandleEvent:eventCode stream:aStream];
    });
}

- (void)safeHandleEvent:(NSStreamEvent)eventCode stream:(NSStream *)aStream
{
        switch (eventCode) {
            case NSStreamEventOpenCompleted: {
                // 处理 stream 被成功打开的事件，输入输出分别会调用一次
                SRFastLog(@"NSStreamEventOpenCompleted %@", aStream);
                
                // 如果已经是关闭或正在关闭状态  则返回
                if (self.readyState >= SR_CLOSING) {
                    return;
                }
                
                // 判断读取数据的缓存是否被初始化
                assert(_readBuffer);
                
                // didConnect fires after certificate verification if we're using pinned certificates.
                BOOL usingPinnedCerts = [[_urlRequest SR_SSLPinnedCertificates] count] > 0;
                
                // 如果没有用安全链接、或者没有用 pinned certs 会走这里
                if ((!_secure || !usingPinnedCerts) && self.readyState == SR_TCP_CONNECTING && aStream == _inputStream) {
                    [self didConnect];
                }
                
                // 检查是否有数据可写
                [self _pumpWriting];
                
                // 检查是否有数据可读
                [self _pumpScanner];
                break;
            }
                
            case NSStreamEventErrorOccurred: {
                // 处理输入输出流错误
                SRFastLog(@"NSStreamEventErrorOccurred %@ %@", aStream, [[aStream streamError] copy]);
                /// TODO specify error better!
                [self failWithError:aStream.streamError];
                _readBufferOffset = 0;
                [_readBuffer setLength:0];
                break;
                
            }
                
            case NSStreamEventEndEncountered: {
                // 处理遇到结束符
                // 检查缓存区是否有数据可读
                [self _pumpScanner];
                SRFastLog(@"NSStreamEventEndEncountered %@", aStream);
                if (aStream.streamError) {
                    // 如果有具体报错  调用 failWithError
                    [self failWithError:aStream.streamError];
                } else {
                    // 如果没有报错  主动关闭链接  回调 didCloseWithCode
                    dispatch_async(_workQueue, ^{
                        if (self.readyState != SR_CLOSED) {
                            // 更新状态 - 已关闭
                            self.readyState = SR_CLOSED;
                            [self _performDelegateBlock:^{
                                if (self.delegate && [self.delegate respondsToSelector:@selector(webSocket:readyStateDidChange:)]) {
                                    [self.delegate webSocket:self readyStateDidChange:SR_CLOSED];
                                }
                            }];
                            [self _scheduleCleanup];
                        }
                        
                        if (!_sentClose && !_failed) {
                            _sentClose = YES;
                            // If we get closed in this state it's probably not clean because we should be sending this when we send messages
                            [self _performDelegateBlock:^{
                                if ([self.delegate respondsToSelector:@selector(webSocket:didCloseWithCode:reason:wasClean:)]) {
                                    [self.delegate webSocket:self didCloseWithCode:SRStatusCodeGoingAway reason:@"Stream end encountered" wasClean:NO];
                                }
                            }];
                        }
                    });
                }
                
                break;
            }
                
            case NSStreamEventHasBytesAvailable: {
                // 输入流中有数据可读
                SRFastLog(@"NSStreamEventHasBytesAvailable %@", aStream);
                const int bufferSize = 2048;
                uint8_t buffer[bufferSize];
                
                // 将输入流中的数据读到已读缓存区
                while (_inputStream.hasBytesAvailable) {
                    NSInteger bytes_read = [_inputStream read:buffer maxLength:bufferSize];
                    
                    if (bytes_read > 0) {
                        [_readBuffer appendBytes:buffer length:bytes_read];
                    } else if (bytes_read < 0) {
                        [self failWithError:_inputStream.streamError];
                    }
                    
                    if (bytes_read != bufferSize) {
                        break;
                    }
                };
                
                // 检查已读缓存区是否有数据可读
                [self _pumpScanner];
                break;
            }
                
            case NSStreamEventHasSpaceAvailable: {
                SRFastLog(@"NSStreamEventHasSpaceAvailable %@", aStream);
                // 输出流中有空间可写
                // 检查缓存区是否有数据可写
                [self _pumpWriting];
                break;
            }
                
            default:
                SRFastLog(@"(default)  %@", aStream);
                break;
        }
}

@end


@implementation SRIOConsumer

@synthesize bytesNeeded = _bytesNeeded;
@synthesize consumer = _scanner;
@synthesize handler = _handler;
@synthesize readToCurrentFrame = _readToCurrentFrame;
@synthesize unmaskBytes = _unmaskBytes;

- (void)setupWithScanner:(stream_scanner)scanner handler:(data_callback)handler bytesNeeded:(size_t)bytesNeeded readToCurrentFrame:(BOOL)readToCurrentFrame unmaskBytes:(BOOL)unmaskBytes;
{
    _scanner = [scanner copy];
    _handler = [handler copy];
    _bytesNeeded = bytesNeeded;
    _readToCurrentFrame = readToCurrentFrame;
    _unmaskBytes = unmaskBytes;
    assert(_scanner || _bytesNeeded);
}

@end

@implementation SRIOConsumerPool {
    // 缓存池大小  默认8个
    NSUInteger _poolSize;
    // 缓存队列
    NSMutableArray *_bufferedConsumers;
}

- (id)initWithBufferCapacity:(NSUInteger)poolSize;
{
    self = [super init];
    if (self) {
        _poolSize = poolSize;
        _bufferedConsumers = [[NSMutableArray alloc] initWithCapacity:poolSize];
    }
    return self;
}

- (id)init
{
    return [self initWithBufferCapacity:8];
}

// 从缓存池取出
- (SRIOConsumer *)consumerWithScanner:(stream_scanner)scanner handler:(data_callback)handler bytesNeeded:(size_t)bytesNeeded readToCurrentFrame:(BOOL)readToCurrentFrame unmaskBytes:(BOOL)unmaskBytes;
{
    SRIOConsumer *consumer = nil;
    if (_bufferedConsumers.count) {
        consumer = [_bufferedConsumers lastObject];
        [_bufferedConsumers removeLastObject];
    } else {
        consumer = [[SRIOConsumer alloc] init];
    }
    
    [consumer setupWithScanner:scanner handler:handler bytesNeeded:bytesNeeded readToCurrentFrame:readToCurrentFrame unmaskBytes:unmaskBytes];
    
    return consumer;
}

// 存入缓存池
- (void)returnConsumer:(SRIOConsumer *)consumer;
{
    if (_bufferedConsumers.count < _poolSize) {
        [_bufferedConsumers addObject:consumer];
    }
}

@end


@implementation  NSURLRequest (SRCertificateAdditions)

- (NSArray *)SR_SSLPinnedCertificates;
{
    return [NSURLProtocol propertyForKey:@"SR_SSLPinnedCertificates" inRequest:self];
}

@end

@implementation  NSMutableURLRequest (SRCertificateAdditions)

- (NSArray *)SR_SSLPinnedCertificates;
{
    return [NSURLProtocol propertyForKey:@"SR_SSLPinnedCertificates" inRequest:self];
}

- (void)setSR_SSLPinnedCertificates:(NSArray *)SR_SSLPinnedCertificates;
{
    [NSURLProtocol setProperty:SR_SSLPinnedCertificates forKey:@"SR_SSLPinnedCertificates" inRequest:self];
}

@end

@implementation NSURL (SRWebSocket)

- (NSString *)SR_origin;
{
    NSString *scheme = [self.scheme lowercaseString];
        
    if ([scheme isEqualToString:@"wss"]) {
        scheme = @"https";
    } else if ([scheme isEqualToString:@"ws"]) {
        scheme = @"http";
    }
    
    BOOL portIsDefault = !self.port ||
                         ([scheme isEqualToString:@"http"] && self.port.integerValue == 80) ||
                         ([scheme isEqualToString:@"https"] && self.port.integerValue == 443);
    
    if (!portIsDefault) {
        return [NSString stringWithFormat:@"%@://%@:%@", scheme, self.host, self.port];
    } else {
        return [NSString stringWithFormat:@"%@://%@", scheme, self.host];
    }
}

@end

//#define SR_ENABLE_LOG

static inline void SRFastLog(NSString *format, ...)  {
#ifdef SR_ENABLE_LOG
    __block va_list arg_list;
    va_start (arg_list, format);
    
    NSString *formattedString = [[NSString alloc] initWithFormat:format arguments:arg_list];
    
    va_end(arg_list);
    
    NSLog(@"[SR] %@", formattedString);
#endif
}


#ifdef HAS_ICU

static inline int32_t validate_dispatch_data_partial_string(NSData *data) {
    if ([data length] > INT32_MAX) {
        // INT32_MAX is the limit so long as this Framework is using 32 bit ints everywhere.
        return -1;
    }

    int32_t size = (int32_t)[data length];

    const void * contents = [data bytes];
    const uint8_t *str = (const uint8_t *)contents;
    
    UChar32 codepoint = 1;
    int32_t offset = 0;
    int32_t lastOffset = 0;
    while(offset < size && codepoint > 0)  {
        lastOffset = offset;
        U8_NEXT(str, offset, size, codepoint);
    }
    
    if (codepoint == -1) {
        // Check to see if the last byte is valid or whether it was just continuing
        if (!U8_IS_LEAD(str[lastOffset]) || U8_COUNT_TRAIL_BYTES(str[lastOffset]) + lastOffset < (int32_t)size) {
            
            size = -1;
        } else {
            uint8_t leadByte = str[lastOffset];
            U8_MASK_LEAD_BYTE(leadByte, U8_COUNT_TRAIL_BYTES(leadByte));
            
            for (int i = lastOffset + 1; i < offset; i++) {
                if (U8_IS_SINGLE(str[i]) || U8_IS_LEAD(str[i]) || !U8_IS_TRAIL(str[i])) {
                    size = -1;
                }
            }
            
            if (size != -1) {
                size = lastOffset;
            }
        }
    }
    
    if (size != -1 && ![[NSString alloc] initWithBytesNoCopy:(char *)[data bytes] length:size encoding:NSUTF8StringEncoding freeWhenDone:NO]) {
        size = -1;
    }
    
    return size;
}

#else

// This is a hack, and probably not optimal
static inline int32_t validate_dispatch_data_partial_string(NSData *data) {
    static const int maxCodepointSize = 3;
    
    for (int i = 0; i < maxCodepointSize; i++) {
        NSString *str = [[NSString alloc] initWithBytesNoCopy:(char *)data.bytes length:data.length - i encoding:NSUTF8StringEncoding freeWhenDone:NO];
        if (str) {
            return (int32_t)data.length - i;
        }
    }
    
    return -1;
}

#endif

static _SRRunLoopThread *networkThread = nil;
static NSRunLoop *networkRunLoop = nil;

@implementation NSRunLoop (SRWebSocket)

// 创建一个常驻线程 和一个 runloop  用于输入输出流
+ (NSRunLoop *)SR_networkRunLoop {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        networkThread = [[_SRRunLoopThread alloc] init];
        networkThread.name = @"com.squareup.SocketRocket.NetworkThread";
        [networkThread start];
        networkRunLoop = networkThread.runLoop;
    });
    
    return networkRunLoop;
}

@end


@implementation _SRRunLoopThread {
    dispatch_group_t _waitGroup;
}

@synthesize runLoop = _runLoop;

- (void)dealloc
{
    sr_dispatch_release(_waitGroup);
}

- (id)init
{
    self = [super init];
    if (self) {
        _waitGroup = dispatch_group_create();
        dispatch_group_enter(_waitGroup);
    }
    return self;
}

- (void)main;
{
    @autoreleasepool {
        // 这里用了一个 dispatch_group_t 保证在返回 runloop 前已经创建完成
        _runLoop = [NSRunLoop currentRunLoop];
        dispatch_group_leave(_waitGroup);
        
        // Add an empty run loop source to prevent runloop from spinning.
        CFRunLoopSourceContext sourceCtx = {
            .version = 0,
            .info = NULL,
            .retain = NULL,
            .release = NULL,
            .copyDescription = NULL,
            .equal = NULL,
            .hash = NULL,
            .schedule = NULL,
            .cancel = NULL,
            .perform = NULL
        };
        CFRunLoopSourceRef source = CFRunLoopSourceCreate(NULL, 0, &sourceCtx);
        CFRunLoopAddSource(CFRunLoopGetCurrent(), source, kCFRunLoopDefaultMode);
        CFRelease(source);
        
        while ([_runLoop runMode:NSDefaultRunLoopMode beforeDate:[NSDate distantFuture]]) {
            
        }
        assert(NO);
    }
}

- (NSRunLoop *)runLoop;
{
    dispatch_group_wait(_waitGroup, DISPATCH_TIME_FOREVER);
    return _runLoop;
}

@end
