#include <string>
#include <UIKit/UIKit.h>
#include <Foundation/Foundation.h>
#include <Security/Security.h>
#include <dispatch/dispatch.h>

std::string getHWID() {
    return std::string([[[UIDevice currentDevice] identifierForVendor].UUIDString UTF8String]);
}

void performPOST(const std::string& postData, void(^completion)(std::string)) {
    NSURL *url = [NSURL URLWithString:@"https://keyauth.win/api/1.2/"];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    [req setHTTPMethod:@"POST"];
    [req setHTTPBody:[NSData dataWithBytes:postData.c_str() length:postData.length()]];
    [req setValue:@"application/x-www-form-urlencoded" forHTTPHeaderField:@"Content-Type"];
    
    [[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        std::string resp = data ? std::string((char*)[data bytes], [data length]) : "No response (network error)";
        dispatch_async(dispatch_get_main_queue(), ^{ completion(resp); });
    }].resume;
}

class KeyAuth {
public:
    std::string name = "azuriteadmin";
    std::string ownerid = "8z9qsAXGks";
    std::string secret = "fea6acbf1b1ef751775c6e12882d8dc1ffb5f264707b7428375e37ed11186697";
    std::string version = "1.0";
    std::string sessionid;

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
                callback(false);
            }
        });
    }

    void checkKey(const std::string& key, void(^callback)(bool, std::string)) {
        if (sessionid.empty()) {
            init(^(bool ok) { if (ok) checkKey(key, callback); else callback(false, "Init failed"); });
            return;
        }

        std::string post = "type=license&key=" + key + "&sessionid=" + sessionid +
                           "&name=" + name + "&ownerid=" + ownerid + "&secret=" + secret +
                           "&hwid=" + getHWID();

        performPOST(post, ^(std::string resp) {
            if (resp.find("\"success\":true") != std::string::npos) {
                callback(true, "");
            } else {
                callback(false, resp);  // ← FULL RESPONSE DARI SERVER
            }
        });
    }
};

// Keychain + getTopVC + showKeyPrompt (sama macam code sebelum ni, copy je dari yang lama)

std::string loadKeyFromKeychain() { /* copy dari code sebelum ni */ }
bool saveKeyToKeychain(const std::string& key) { /* copy */ }
void deleteKeyFromKeychain() { /* copy */ }

UIViewController* getTopVC() { /* copy */ }

void showKeyPrompt(const std::string& error = "") {
    dispatch_async(dispatch_get_main_queue(), ^{
        NSString *title = error.empty() ? @"Azurite KeyAuth" : @"Key Ditolak";
        NSString *msg = error.empty() ? @"Masukkan license key" : [NSString stringWithUTF8String:error.c_str()];
        
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:title message:msg preferredStyle:UIAlertControllerStyleAlert];
        [alert addTextFieldWithConfigurationHandler:^(UITextField *tf) { tf.placeholder = @"Paste key sini"; }];
        
        [alert addAction:[UIAlertAction actionWithTitle:@"Submit" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            std::string k = [[[alert.textFields[0] text] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] UTF8String];
            if (k.empty()) { showKeyPrompt(); return; }
            
            UIAlertController *loading = [UIAlertController alertControllerWithTitle:@"Checking Key..." message:nil preferredStyle:UIAlertControllerStyleAlert];
            [getTopVC() presentViewController:loading animated:YES completion:nil];
            
            KeyAuth().checkKey(k, ^(bool valid, std::string err) {
                [loading dismissViewControllerAnimated:YES completion:^{
                    if (valid) {
                        saveKeyToKeychain(k);
                    } else {
                        showKeyPrompt(err);  // tunjuk full JSON
                    }
                }];
            });
        }]];
        
        [alert addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:^(UIAlertAction *) { exit(0); }]];
        [getTopVC() presentViewController:alert animated:YES completion:nil];
    });
}

__attribute__((constructor))
static void init() {
    [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidFinishLaunchingNotification
                                                      object:nil queue:nil usingBlock:^(NSNotification *note) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
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
        });
    }];
}
