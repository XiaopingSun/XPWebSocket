# XPWebSocket
A WebSocket Repo Base On SRWebSocket

## 简介

在 SRWebSocket 基础上增加了 DNS 预解析、webSocket 行为打点、重连逻辑。

## 使用方法

```objc
@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
    
    NSArray *urlList = @[
        [NSURL URLWithString:@""],
        [NSURL URLWithString:@""],
    ];
    _webSocket = [[XPWebSocket alloc] initWithUrlList:urlList retryTimes:3 timeoutInterval:5 useHappyDns:YES];
    _webSocket.delegate = self;
}

- (IBAction)open:(UIButton *)sender {
    [_webSocket open];
}

- (IBAction)close:(UIButton *)sender {
    [_webSocket close];
}

#pragma mark - XPWebSocketDelegate
- (void)webSocket:(XPWebSocket *)webSocket didReceiveMessage:(NSString *)message {
    NSLog(@"XPWebSocket didReceiveMessage: %@", message);
}

- (void)webSocket:(XPWebSocket *)webSocket connectionStateDidChange:(XPWebSocketConnectionState)state {
    NSLog(@"XPWebSocket connectionStateDidChange: %@", states[state]);
}

- (void)webSocket:(XPWebSocket *)webSocket didFailWithError:(NSError *)error {
    NSLog(@"XPWebSocket didFailWithError: %@", error);
}

- (void)webSocket:(XPWebSocket *)webSocket didCloseWithCode:(NSInteger)code reason:(NSString *)reason wasClean:(BOOL)wasClean {
    NSLog(@"XPWebSocket didCloseWithCode: %ld  reason: %@  wasClean: %d", code, reason, wasClean);
}

@end
```

