#include <string>
#include <UIKit/UIKit.h>
#include <Foundation/Foundation.h>
#include <Security/Security.h>
#include <dispatch/dispatch.h>

std::string getHWID() {
    return std::string([[[UIDevice currentDevice] identifierForVendor].UUIDString UTF8String]);
}

std::string performPOST(const std::string& postData) {
    __block std::string result;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    
    NSURL *url = [NSURL URLWithString:@"https://keyauth.win/api/1.2/"];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    [req setHTTPMethod:@"POST"];
    [req setHTTPBody:[NSData dataWithBytes:postData.c_str() length:postData.length()]];
    [req setValue:@"application/x-www-form-urlencoded" forHTTPHeaderField:@"Content-Type"];
    
    NSURLSessionDataTask *task = [[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        if (data) result = std::string((char*)[data bytes], [data length]);
        dispatch_semaphore_signal(sem);
    }];
    [task resume];
    dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
    return result;
}

class KeyAuth {
public:
    std::string name = "azuriteadmin";
    std::string ownerid = "8z9qsAXGks";
    std::string secret = "fea6acbf1b1ef751775c6e12882d8dc1ffb5f264707b7428375e37ed11186697";
    std::string version = "1.0";
    std::string sessionid;

    bool init() {
        std::string post = "type=init&ver=" + version + "&name=" + name + "&ownerid=" + ownerid + "&secret=" + secret;
        std::string resp = performPOST(post);
        if (resp.find("\"success\":true") != std::string::npos) {
            size_t pos = resp.find("\"sessionid\":\"");
            if (pos != std::string::npos) {
                pos += 14;
                size_t end = resp.find("\"", pos);
                sessionid = resp.substr(pos, end - pos);
            }
            return true;
        }
        return false;
    }

    bool checkKey(const std::string& key) {
        if (sessionid.empty() && !init()) return false;
        
        std::string post = "type=license&key=" + key +
                           "&sessionid=" + sessionid +
                           "&name=" + name +
                           "&ownerid=" + ownerid +
                           "&secret=" + secret +
                           "&hwid=" + getHWID();
        
        std::string resp = performPOST(post);
        return resp.find("\"success\":true") != std::string::npos;
    }
};

// Keychain + GUI sama macam tadi (auto start 3 saat)
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

void showKeyPrompt(bool invalid = false) {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:invalid ? @"Key Tidak Sah" : @"Azurite KeyAuth"
                                                                       message:invalid ? @"Key salah atau expired.\nMasukkan semula." : @"Masukkan license key"
                                                                preferredStyle:UIAlertControllerStyleAlert];
        [alert addTextFieldWithConfigurationHandler:^(UITextField *tf) { tf.placeholder = @"Paste key sini"; }];
        
        [alert addAction:[UIAlertAction actionWithTitle:@"Submit" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
            std::string k = [[[alert.textFields[0] text] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] UTF8String];
            if (k.empty()) { showKeyPrompt(); return; }
            if (KeyAuth().checkKey(k)) {
                saveKeyToKeychain(k);
            } else {
                showKeyPrompt(true);
            }
        }]];
        [alert addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:^(UIAlertAction *) { exit(0); }]];
        
        UIViewController *vc = [[[[UIApplication sharedApplication] keyWindow] rootViewController] presentedViewController] ?: [[[UIApplication sharedApplication] keyWindow] rootViewController];
        [vc presentViewController:alert animated:YES completion:nil];
    });
}

__attribute__((constructor)) static void init() {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        std::string saved = loadKeyFromKeychain();
        if (!saved.empty() && KeyAuth().checkKey(saved)) return;
        if (!saved.empty()) deleteKeyFromKeychain();
        showKeyPrompt();
    });
}
