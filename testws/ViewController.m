//
//  ViewController.m
//  testws
//
//  Created by Pursue丶 on 2022/3/23.
//

#import "ViewController.h"
#import "XPWebSocket.h"

NSString *states[] = {
    @"XPWebSocketConnectionStateIdle",
    @"XPWebSocketConnectionStateConnecting",
    @"XPWebSocketConnectionStateConnected",
    @"XPWebSocketConnectionStateReconnecting",
    @"XPWebSocketConnectionStateReconnected"
};

@interface ViewController () <XPWebSocketDelegate>
@property (nonatomic, strong) XPWebSocket *webSocket;
@end

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
