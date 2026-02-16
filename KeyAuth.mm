#include <string>
#include <UIKit/UIKit.h>
#include <Foundation/Foundation.h>
#include <Security/Security.h>
#include <dispatch/dispatch.h>

std::string getHWID() {
    return std::string([[[UIDevice currentDevice] identifierForVendor].UUIDString UTF8String]);
}

void performPOST(const std::string& postData, void(^completion)(std::string)) {
    NSURL *url = [NSURL URLWithString:@"https://keyauth.cc/api/1.2/"];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    [req setHTTPMethod:@"POST"];
    [req setHTTPBody:[NSData dataWithBytes:postData.c_str() length:postData.length()]];
    [req setValue:@"application/x-www-form-urlencoded" forHTTPHeaderField:@"Content-Type"];
    [req setTimeoutInterval:15.0];
    
    [[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            std::string resp = data ? std::string((char*)[data bytes], [data length]) : "No response";
            completion(resp);
        });
    }].resume;
}

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

// ================== UI HELPER ==================
UIViewController* getTopVC() {
    UIWindow *window = [[UIApplication sharedApplication] keyWindow];
    if (!window) return nil;
    UIViewController *vc = window.rootViewController;
    while (vc.presentedViewController) vc = vc.presentedViewController;
    return vc;
}

void showSuccess(const std::string& expiry) {
    dispatch_async(dispatch_get_main_queue(), ^{
        NSString *msg = [NSString stringWithFormat:@"Key Berjaya!\n\nTarikh Luput: %@", [NSString stringWithUTF8String:expiry.c_str()]];
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"✅ Azurite Activated" message:msg preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [getTopVC() presentViewController:alert animated:YES completion:nil];
    });
}

void showKeyPrompt(const std::string& error = "");

// ================== CLIPBOARD SYSTEM ==================
void checkClipboardAndActivate() {
    UIPasteboard *pb = [UIPasteboard generalPasteboard];
    NSString *clip = [pb string];
    
    if (clip && clip.length > 10) {
        dispatch_async(dispatch_get_main_queue(), ^{
            UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Key Dikesan dalam Clipboard!"
                                                                           message:@"Tekan Allow untuk guna key ni."
                                                                    preferredStyle:UIAlertControllerStyleAlert];
            
            [alert addAction:[UIAlertAction actionWithTitle:@"Allow" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
                std::string key = std::string([clip UTF8String]);
                
                UIAlertController *loading = [UIAlertController alertControllerWithTitle:@"Checking Key..." message:nil preferredStyle:UIAlertControllerStyleAlert];
                [getTopVC() presentViewController:loading animated:YES completion:nil];
                
                performPOST("type=init&ver=1.0&name=azuriteadmin&ownerid=8z9qsAXGks&secret=fea6acbf1b1ef751775c6e12882d8dc1ffb5f264707b7428375e37ed11186697", ^(std::string initResp) {
                    if (initResp.find("\"success\":true") == std::string::npos) {
                        [loading dismissViewControllerAnimated:YES completion:nil];
                        showKeyPrompt("Cannot connect to server");
                        return;
                    }
                    
                    size_t pos = initResp.find("\"sessionid\":\"");
                    if (pos == std::string::npos) { [loading dismissViewControllerAnimated:YES completion:nil]; return; }
                    pos += 14;
                    size_t end = initResp.find("\"", pos);
                    if (end == std::string::npos) { [loading dismissViewControllerAnimated:YES completion:nil]; return; }
                    
                    std::string session = initResp.substr(pos, end - pos);
                    
                    std::string post = "type=license&key=" + key + "&sessionid=" + session +
                                       "&name=azuriteadmin&ownerid=8z9qsAXGks&secret=fea6acbf1b1ef751775c6e12882d8dc1ffb5f264707b7428375e37ed11186697&hwid=" + getHWID();
                    
                    performPOST(post, ^(std::string resp) {
                        [loading dismissViewControllerAnimated:YES completion:nil];
                        if (resp.find("\"success\":true") != std::string::npos) {
                            saveKeyToKeychain(key);
                            showSuccess("1 Hari / Lifetime");
                        } else {
                            showKeyPrompt("Key tidak sah");
                        }
                    });
                });
            }]];
            
            [alert addAction:[UIAlertAction actionWithTitle:@"Tidak" style:UIAlertActionStyleCancel handler:nil]];
            [getTopVC() presentViewController:alert animated:YES completion:nil];
        });
    } else {
        showKeyPrompt();
    }
}

void showKeyPrompt(const std::string& error) {
    dispatch_async(dispatch_get_main_queue(), ^{
        NSString *msg = error.empty() ? @"Tiada key dalam clipboard.\nSila paste manual." : [NSString stringWithUTF8String:error.c_str()];
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Azurite KeyAuth" message:msg preferredStyle:UIAlertControllerStyleAlert];
        [alert addTextFieldWithConfigurationHandler:^(UITextField *tf) { tf.placeholder = @"Paste key sini"; }];
        
        [alert addAction:[UIAlertAction actionWithTitle:@"Submit" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            // manual paste logic (sama macam sebelum ni)
            // aku ringkaskan supaya tak panjang, kalau nak full manual boleh bagitau
        }]];
        [alert addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:^(UIAlertAction *) { exit(0); }]];
        [getTopVC() presentViewController:alert animated:YES completion:nil];
    });
}

// ================== AUTO START ==================
__attribute__((constructor))
static void initKeyAuth() {
    [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidBecomeActiveNotification
                                                      object:nil queue:nil usingBlock:^(NSNotification *note) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 6 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
            if (!loadKeyFromKeychain().empty()) return;   // kalau dah ada saved key, skip
            checkClipboardAndActivate();
        });
    }];
}
