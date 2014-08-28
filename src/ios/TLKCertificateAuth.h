//
//  TLKCertificateAuth.h
//  TLKCertificateAuth
//
//  Created by Emil Marashliev on 8/26/14.
//
//

#import <Cordova/CDVPlugin.h>
#import <Cordova/CDVViewController.h>


@interface TLKCertificateAuth : CDVPlugin

- (void)setPathAndPassword:(CDVInvokedUrlCommand *)command;

@end
