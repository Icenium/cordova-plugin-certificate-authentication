//
//  TLKCertificateAuth.m
//  TLKCertificateAuth
//
//  Created by Emil Marashliev on 8/26/14.
//
//

#import "TLKCertificateAuth.h"
#import "CustomHTTPProtocol.h"

@interface TLKCertificateAuth () <CustomHTTPProtocolDelegate>

@property (nonatomic, strong) NSString *filePath;
@property (nonatomic, strong) NSString *filePassword;

@end

@implementation TLKCertificateAuth


- (void)pluginInitialize
{
    CDVViewController *cordovaViewController = (CDVViewController *)self.viewController;
    if (cordovaViewController.settings[@"tlkcertificateauthfilename"] != nil &&
        cordovaViewController.settings[@"tlkcertificateauthfilepassword"] != nil) {
        
        self.filePath = [self filePathFrom:cordovaViewController.settings[@"tlkcertificateauthfilename"]];
        self.filePassword = cordovaViewController.settings[@"tlkcertificateauthfilepassword"];
    }
    [NSURLProtocol registerClass:[CustomHTTPProtocol class]];
    [CustomHTTPProtocol setDelegate:self];
}


- (void)setPathAndPassword:(CDVInvokedUrlCommand *)command
{
    CDVPluginResult* pluginResult = nil;
    NSArray *arguments = command.arguments;
    
    if (arguments[0] != nil && arguments[1] != nil) {
        self.filePath = [[NSURL URLWithString:arguments[0]] path];
        self.filePassword = arguments[1];
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
    } else {
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:@"Arg was null"];
    }
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}


#pragma mark - CustomHTTPProtocolDelegate Methods
- (BOOL)customHTTPProtocol:(CustomHTTPProtocol *)protocol canAuthenticateAgainstProtectionSpace:(NSURLProtectionSpace *)protectionSpace
{
    return self.filePath != nil && self.filePassword != nil;
}

- (void)customHTTPProtocol:(CustomHTTPProtocol *)protocol didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
{
   
    NSURLCredential *   credential;
    
    assert(protocol != nil);
    assert(challenge != nil);
    
    credential = nil;
    
    // Handle ServerTrust and Client Certificate challenges
    
    NSData *p12data = [NSData dataWithContentsOfFile:self.filePath];
    
    SecIdentityRef identity = NULL;
    SecCertificateRef certificate = NULL;
    
    [self extractIdentity:CFDataCreate(NULL, [p12data bytes], [p12data length]) identity:&identity];
    assert(identity != NULL);
    SecIdentityCopyCertificate (identity, &certificate);
    
    const void *certs[] = {certificate};
    CFArrayRef certArray = CFArrayCreate(kCFAllocatorDefault, certs, 1, NULL);
    
    credential = [NSURLCredential credentialWithIdentity:identity certificates:(__bridge NSArray *)(certArray) persistence:NSURLCredentialPersistencePermanent];
    
    [protocol resolveAuthenticationChallenge:challenge withCredential:credential];
}


- (OSStatus)extractIdentity:(CFDataRef)inP12Data identity:(SecIdentityRef*)identity
{
    OSStatus securityError = errSecSuccess;
    
    CFStringRef password = (__bridge CFStringRef)self.filePassword;
    const void *keys[] = { kSecImportExportPassphrase };
    const void *values[] = { password };
    
    CFDictionaryRef options = CFDictionaryCreate(NULL, keys, values, 1, NULL, NULL);
    
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    securityError = SecPKCS12Import(inP12Data, options, &items);
    
    if (securityError == 0) {
        CFDictionaryRef ident = CFArrayGetValueAtIndex(items,0);
        const void *tempIdentity = NULL;
        tempIdentity = CFDictionaryGetValue(ident, kSecImportItemIdentity);
        *identity = (SecIdentityRef)tempIdentity;
        
    }
    
    if (options) {
        CFRelease(options);
    }
    
    return securityError;
}

#pragma mark - Helper Methods
- (NSString *)filePathFrom:(NSString *)fileName
{
    NSArray *nameElements = [fileName componentsSeparatedByString:@"."];
    NSString *path = [[NSBundle mainBundle]pathForResource:nameElements[0] ofType:nameElements[1]];
    return path;
}

@end
