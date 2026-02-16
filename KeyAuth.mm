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

std::string extractExpiry(const std::string& json) {
    size_t pos = json.find("\"expiry\":\"");
    if (pos == std::string::npos) pos = json.find("\"expires\":\"");
    if (pos != std::string::npos) {
        pos += 10;
        size_t end = json.find("\"", pos);
        if (end != std::string::npos) {
            std::string date = json.substr(pos, end - pos);
            // Buat cantik (contoh: 2025-02-17 14:30:00 → 17 Feb 2025)
            if (date.length() >= 10) {
                return date.substr(8,2) + " " + 
                       (date.substr(5,2) == "01" ? "Jan" : date.substr(5,2) == "02" ? "Feb" : 
                        date.substr(5,2) == "03" ? "Mac" : date.substr(5,2) == "04" ? "Apr" : 
                        date.substr(5,2) == "05" ? "Mei" : date.substr(5,2) == "06" ? "Jun" : 
                        date.substr(5,2) == "07" ? "Jul" : date.substr(5,2) == "08" ? "Ogos" : 
                        date.substr(5,2) == "09" ? "Sep" : date.substr(5,2) == "10" ? "Okt" : 
                        date.substr(5,2) == "11" ? "Nov" : "Dis") + " " + date.substr(0,4);
            }
            return date;
        }
    }
    return "Lifetime";
}

// Keychain (sama)
std::string loadKeyFromKeychain() { /* sama macam sebelum ni */ }
bool saveKeyToKeychain(const std::string& key) { /* sama */ }
void deleteKeyFromKeychain() { /* sama */ }

UIViewController* getTopVC() { /* sama */ }

// ================== MAIN ==================
void showSuccess(const std::string& expiry) {
    dispatch_async(dispatch_get_main_queue(), ^{
        NSString *msg = [NSString stringWithFormat:@"Key Berjaya!\n\nExpired: %@", [NSString stringWithUTF8String:expiry.c_str()]];
        
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"✅ Azurite Activated"
                                                                       message:msg
                                                                preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [getTopVC() presentViewController:alert animated:YES completion:nil];
    });
}

void showKeyPrompt(const std::string& error = "") {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Azurite KeyAuth"
                                                                       message:error.empty() ? @"Masukkan license key" : [NSString stringWithUTF8String:error.c_str()]
                                                                preferredStyle:UIAlertControllerStyleAlert];
        [alert addTextFieldWithConfigurationHandler:^(UITextField *tf) { tf.placeholder = @"Paste key sini"; }];
        
        [alert addAction:[UIAlertAction actionWithTitle:@"Submit" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            std::string k = [[[alert.textFields[0] text] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] UTF8String];
            if (k.empty()) { showKeyPrompt(); return; }
            
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
                
                std::string licensePost = "type=license&key=" + k + "&sessionid=" + session + 
                                         "&name=azuriteadmin&ownerid=8z9qsAXGks&secret=fea6acbf1b1ef751775c6e12882d8dc1ffb5f264707b7428375e37ed11186697&hwid=" + getHWID();
                
                performPOST(licensePost, ^(std::string resp) {
                    [loading dismissViewControllerAnimated:YES completion:nil];
                    [alert dismissViewControllerAnimated:YES completion:^{
                        if (resp.find("\"success\":true") != std::string::npos) {
                            std::string expiry = extractExpiry(resp);
                            saveKeyToKeychain(k);
                            showSuccess(expiry);
                        } else {
                            showKeyPrompt(resp);
                        }
                    }];
                });
            });
        }]];
        
        [alert addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:^(UIAlertAction *) { exit(0); }]];
        [getTopVC() presentViewController:alert animated:YES completion:nil];
    });
}

// Auto start
__attribute__((constructor))
static void initKeyAuth() {
    [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidFinishLaunchingNotification
                                                      object:nil queue:nil usingBlock:^(NSNotification *note) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 6 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
            std::string saved = loadKeyFromKeychain();
            if (!saved.empty()) {
                // Check saved key (sama logic)
                performPOST("type=init&ver=1.0&name=azuriteadmin&ownerid=8z9qsAXGks&secret=fea6acbf1b1ef751775c6e12882d8dc1ffb5f264707b7428375e37ed11186697", ^(std::string initResp) {
                    if (initResp.find("\"success\":true") == std::string::npos) return;
                    size_t pos = initResp.find("\"sessionid\":\"");
                    if (pos != std::string::npos) {
                        pos += 14;
                        size_t end = initResp.find("\"", pos);
                        if (end != std::string::npos) {
                            std::string session = initResp.substr(pos, end - pos);
                            std::string licensePost = "type=license&key=" + saved + "&sessionid=" + session + "&name=azuriteadmin&ownerid=8z9qsAXGks&secret=fea6acbf1b1ef751775c6e12882d8dc1ffb5f264707b7428375e37ed11186697&hwid=" + getHWID();
                            performPOST(licensePost, ^(std::string resp) {
                                if (resp.find("\"success\":true") == std::string::npos) {
                                    deleteKeyFromKeychain();
                                    showKeyPrompt("Key expired");
                                }
                            });
                        }
                    }
                });
                return;
            }
            showKeyPrompt();
        });
    }];
}
