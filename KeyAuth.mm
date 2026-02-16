#include <string>
#include <UIKit/UIKit.h>
#include <Foundation/Foundation.h>
#include <Security/Security.h>
#include <dispatch/dispatch.h>

std::string getHWID() {
    return std::string([[[UIDevice currentDevice] identifierForVendor].UUIDString UTF8String]);
}

// Network async (tak block)
void performPOST(const std::string& postData, void(^completion)(std::string)) {
    NSURL *url = [NSURL URLWithString:@"https://keyauth.win/api/1.2/"];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    [req setHTTPMethod:@"POST"];
    [req setHTTPBody:[NSData dataWithBytes:postData.c_str() length:postData.length()]];
    [req setValue:@"application/x-www-form-urlencoded" forHTTPHeaderField:@"Content-Type"];
    
    [[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        std::string resp = data ? std::string((char*)[data bytes], [data length]) : "";
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(resp);
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
    std::string lastError;

    void init(void(^callback)(bool)) {
        std::string post = "type=init&ver=" + version + "&name=" + name + "&ownerid=" + ownerid + "&secret=" + secret;
        performPOST(post, ^(std::string resp) {
            if (resp.find("\"success\":true") != std::string::npos) {
                size_t pos = resp.find("\"sessionid\":\"");
                if (pos != std::string::npos) {
                    pos += 14;
                    size_t end = resp.find("\"", pos);
                    if (end != std::string::npos) sessionid = resp.substr(pos, end - pos);
                }
                callback(true);
            } else {
                lastError = "Init gagal (network?)";
                callback(false);
            }
        });
    }

    void checkKey(const std::string& key, void(^callback)(bool, std::string)) {
        if (sessionid.empty()) {
            init(^(bool ok) {
                if (ok) checkKey(key, callback);
                else callback(false, lastError);
            });
            return;
        }

        std::string post = "type=license&key=" + key + "&sessionid=" + sessionid +
                           "&name=" + name + "&ownerid=" + ownerid + "&secret=" + secret +
                           "&hwid=" + getHWID();

        performPOST(post, ^(std::string resp) {
            if (resp.find("\"success\":true") != std::string::npos) {
                callback(true, "");
            } else {
                size_t pos = resp.find("\"message\":\"");
                std::string msg = "Key tidak sah";
                if (pos != std::string::npos) {
                    pos += 11;
                    size_t end = resp.find("\"", pos);
                    if (end != std::string::npos) msg = resp.substr(pos, end - pos);
                }
                callback(false, msg);
            }
        });
    }
};

// Keychain functions
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

// Safe root VC
UIViewController* getTopVC() {
    UIViewController *vc = [[UIApplication sharedApplication] keyWindow].rootViewController;
    while (vc.presentedViewController) vc = vc.presentedViewController;
    return vc;
}

void showKeyPrompt(const std::string& error = "") {
    dispatch_async(dispatch_get_main_queue(), ^{
        NSString *title = error.empty() ? @"Azurite KeyAuth" : @"Key Tidak Sah";
        NSString *msg = error.empty() ? @"Masukkan license key anda" : [NSString stringWithUTF8String:error.c_str()];
        
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:title message:msg preferredStyle:UIAlertControllerStyleAlert];
        [alert addTextFieldWithConfigurationHandler:^(UITextField *tf) { tf.placeholder = @"Paste key sini"; }];
        
        [alert addAction:[UIAlertAction actionWithTitle:@"Submit" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            std::string k = [[[alert.textFields[0] text] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] UTF8String];
            if (k.empty()) { showKeyPrompt(); return; }
            
            UIAlertController *loading = [UIAlertController alertControllerWithTitle:@"Checking..." message:nil preferredStyle:UIAlertControllerStyleAlert];
            [getTopVC() presentViewController:loading animated:YES completion:nil];
            
            KeyAuth().checkKey(k, ^(bool valid, std::string err) {
                [loading dismissViewControllerAnimated:YES completion:^{
                    if (valid) {
                        saveKeyToKeychain(k);
                    } else {
                        showKeyPrompt(err);
                    }
                }];
            });
        }]];
        
        [alert addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:^(UIAlertAction *) { exit(0); }]];
        
        [getTopVC() presentViewController:alert animated:YES completion:nil];
    });
}

// Start function
void startKeyAuth() {
    std::string saved = loadKeyFromKeychain();
    if (!saved.empty()) {
        KeyAuth().checkKey(saved, ^(bool valid, std::string err) {
            if (valid) return;
            deleteKeyFromKeychain();
            showKeyPrompt(err);
        });
        return;
    }
    showKeyPrompt();
}

// Paling penting: tunggu app fully launch
__attribute__((constructor))
static void init() {
    [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidFinishLaunchingNotification
                                                      object:nil
                                                       queue:nil
                                                  usingBlock:^(NSNotification *note) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 4 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
            startKeyAuth();
        });
    }];
}
