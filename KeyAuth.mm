#include <string>
#include <UIKit/UIKit.h>
#include <Foundation/Foundation.h>
#include <Security/Security.h>
#include <dispatch/dispatch.h>

std::string getHWID() {
    return std::string([[[UIDevice currentDevice] identifierForVendor].UUIDString UTF8String]);
}

void performPOST(const std::string& postData, void(^completion)(std::string resp, std::string error)) {
    NSURL *url = [NSURL URLWithString:@"https://keyauth.cc/api/1.2/"];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    [req setHTTPMethod:@"POST"];
    [req setHTTPBody:[NSData dataWithBytes:postData.c_str() length:postData.length()]];
    [req setValue:@"application/x-www-form-urlencoded" forHTTPHeaderField:@"Content-Type"];
    [req setTimeoutInterval:15.0];
    
    [[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (error) {
                completion("", [error.localizedDescription UTF8String]);
                return;
            }
            std::string resp = data ? std::string((char*)[data bytes], [data length]) : "";
            completion(resp, "");
        });
    }].resume;
}

class KeyAuth {
public:
    std::string name = "azuriteadmin";
    std::string ownerid = "8z9qsAXGks";
    std::string secret = "fea6acbf1b1ef751775c6e12882d8dc1ffb5f264707b7428375e37ed11186697";
    std::string version = "1.0";
    std::string sessionid;

    void checkKey(const std::string& key, void(^callback)(bool valid, std::string message)) {
        std::string post = "type=license&key=" + key + "&sessionid=" + sessionid +
                           "&name=" + name + "&ownerid=" + ownerid + "&secret=" + secret +
                           "&hwid=" + getHWID();

        performPOST(post, ^(std::string resp, std::string err) {
            if (!err.empty()) {
                callback(false, "Network Error: " + err);
                return;
            }
            if (resp.find("\"success\":true") != std::string::npos) {
                callback(true, "");
            } else {
                callback(false, resp.empty() ? "No response from server" : resp);
            }
        });
    }
};

// ================== KEYCHAIN ==================
std::string loadKeyFromKeychain() {
    NSDictionary *query = @{(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                            (__bridge id)kSecAttrService: @"AzuriteKeyAuth",
                            (__bridge id)kSecAttrAccount: @"license",
                            (__bridge id)kSecReturnData: @YES,
                            (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne};
    CFDataRef data = NULL;
    if (SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef*)&data) == errSecSuccess && data) {
        NSString *str = [[NSString alloc] initWithData:(__bridge NSData*)data encoding:NSUTF8StringEncoding];
        CFRelease(data);
        return std::string([str UTF8String]);
    }
    return "";
}

bool saveKeyToKeychain(const std::string& key) {
    NSDictionary *del = @{(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                          (__bridge id)kSecAttrService: @"AzuriteKeyAuth",
                          (__bridge id)kSecAttrAccount: @"license"};
    SecItemDelete((__bridge CFDictionaryRef)del);
    
    NSData *data = [NSData dataWithBytes:key.c_str() length:key.length()];
    NSDictionary *add = @{(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                          (__bridge id)kSecAttrService: @"AzuriteKeyAuth",
                          (__bridge id)kSecAttrAccount: @"license",
                          (__bridge id)kSecValueData: data,
                          (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleAfterFirstUnlock};
    return SecItemAdd((__bridge CFDictionaryRef)add, NULL) == errSecSuccess;
}

void deleteKeyFromKeychain() {
    NSDictionary *query = @{(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                            (__bridge id)kSecAttrService: @"AzuriteKeyAuth",
                            (__bridge id)kSecAttrAccount: @"license"};
    SecItemDelete((__bridge CFDictionaryRef)query);
}

// ================== UI ==================
UIViewController* getTopVC() {
    UIViewController *vc = [[UIApplication sharedApplication] keyWindow].rootViewController;
    while (vc.presentedViewController) vc = vc.presentedViewController;
    return vc;
}

void showKeyPrompt(const std::string& error = "") {
    dispatch_async(dispatch_get_main_queue(), ^{
        NSString *title = error.empty() ? @"Azurite KeyAuth" : @"Key Error";
        NSString *msg = error.empty() ? @"Masukkan license key anda" : [NSString stringWithUTF8String:error.c_str()];
        
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:title message:msg preferredStyle:UIAlertControllerStyleAlert];
        [alert addTextFieldWithConfigurationHandler:^(UITextField *tf) { tf.placeholder = @"Paste key sini"; }];
        
        [alert addAction:[UIAlertAction actionWithTitle:@"Submit" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            std::string k = [[[alert.textFields[0] text] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] UTF8String];
            if (k.empty()) { showKeyPrompt(); return; }
            
            UIAlertController *loading = [UIAlertController alertControllerWithTitle:@"Connecting to KeyAuth..." message:nil preferredStyle:UIAlertControllerStyleAlert];
            [getTopVC() presentViewController:loading animated:YES completion:nil];
            
            // Init dulu
            std::string initPost = "type=init&ver=1.0&name=azuriteadmin&ownerid=8z9qsAXGks&secret=fea6acbf1b1ef751775c6e12882d8dc1ffb5f264707b7428375e37ed11186697";
            performPOST(initPost, ^(std::string resp, std::string err) {
                if (!err.empty() || resp.find("\"success\":true") == std::string::npos) {
                    [loading dismissViewControllerAnimated:YES completion:^{
                        showKeyPrompt(err.empty() ? "Cannot connect to KeyAuth server" : err);
                    }];
                    return;
                }
                
                // Ambil sessionid
                size_t pos = resp.find("\"sessionid\":\"");
                if (pos != std::string::npos) {
                    pos += 14;
                    size_t end = resp.find("\"", pos);
                    if (end != std::string::npos) {
                        KeyAuth auth;
                        auth.sessionid = resp.substr(pos, end - pos);
                        auth.checkKey(k, ^(bool valid, std::string message) {
                            [loading dismissViewControllerAnimated:YES completion:^{
                                if (valid) {
                                    saveKeyToKeychain(k);
                                } else {
                                    showKeyPrompt(message);
                                }
                            }];
                        });
                    }
                }
            });
        }]];
        
        [alert addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:^(UIAlertAction *) { exit(0); }]];
        [getTopVC() presentViewController:alert animated:YES completion:nil];
    });
}

// ================== AUTO START ==================
__attribute__((constructor))
static void initKeyAuth() {
    [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidFinishLaunchingNotification
                                                      object:nil queue:nil usingBlock:^(NSNotification *note) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 6 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
            std::string saved = loadKeyFromKeychain();
            if (!saved.empty()) {
                // Check saved key
                std::string initPost = "type=init&ver=1.0&name=azuriteadmin&ownerid=8z9qsAXGks&secret=fea6acbf1b1ef751775c6e12882d8dc1ffb5f264707b7428375e37ed11186697";
                performPOST(initPost, ^(std::string resp, std::string err) {
                    if (err.empty() && resp.find("\"success\":true") != std::string::npos) {
                        size_t pos = resp.find("\"sessionid\":\"");
                        if (pos != std::string::npos) {
                            pos += 14;
                            size_t end = resp.find("\"", pos);
                            if (end != std::string::npos) {
                                KeyAuth auth;
                                auth.sessionid = resp.substr(pos, end - pos);
                                auth.checkKey(saved, ^(bool valid, std::string msg) {
                                    if (!valid) {
                                        deleteKeyFromKeychain();
                                        showKeyPrompt(msg);
                                    }
                                });
                            }
                        }
                    }
                });
                return;
            }
            showKeyPrompt();
        });
    }];
}
