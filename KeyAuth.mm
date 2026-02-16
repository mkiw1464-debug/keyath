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
std::string loadKeyFromKeychain() { /* sama */ }
bool saveKeyToKeychain(const std::string& key) { /* sama */ }
void deleteKeyFromKeychain() { /* sama */ }

UIViewController* getTopVC() { /* sama */ }

// ================== SUCCESS POPUP ==================
void showSuccess(const std::string& expiry) {
    dispatch_async(dispatch_get_main_queue(), ^{
        NSString *msg = [NSString stringWithFormat:@"Key Berjaya!\n\nTarikh Luput: %@", [NSString stringWithUTF8String:expiry.c_str()]];
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"✅ Azurite Activated" message:msg preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [getTopVC() presentViewController:alert animated:YES completion:nil];
    });
}

// ================== CLIPBOARD SMART SYSTEM ==================
void checkClipboardAndActivate() {
    UIPasteboard *pb = [UIPasteboard generalPasteboard];
    NSString *clip = [pb string];
    
    if (clip && clip.length > 15) {  // nampak macam key
        dispatch_async(dispatch_get_main_queue(), ^{
            UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Key Dikesan!"
                                                                           message:@"Kami jumpa key dalam clipboard anda.\nAllow untuk paste & activate?"
                                                                    preferredStyle:UIAlertControllerStyleAlert];
            
            [alert addAction:[UIAlertAction actionWithTitle:@"Allow" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
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
                            showSuccess("Lifetime / 1 Hari");   // boleh improve nanti
                        } else {
                            showKeyPrompt("Key tidak sah");
                        }
                    });
                });
            }]];
            
            [alert addAction:[UIAlertAction actionWithTitle:@"Tidak" style:UIAlertActionStyleCancel handler:^(UIAlertAction *action) {
                showKeyPrompt();  // fallback ke manual
            }]];
            
            [getTopVC() presentViewController:alert animated:YES completion:nil];
        });
    } else {
        showKeyPrompt(); // tak ada key dalam clipboard → manual
    }
}

void showKeyPrompt(const std::string& error = "") {
    // (sama macam manual prompt sebelum ni, aku tak copy panjang)
    // kalau kau nak, bagitau aku, aku tambah
}

// ================== AUTO START ==================
__attribute__((constructor))
static void initKeyAuth() {
    [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidBecomeActiveNotification
                                                      object:nil queue:nil usingBlock:^(NSNotification *note) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
            std::string saved = loadKeyFromKeychain();
            if (!saved.empty()) {
                // check saved key (skip kalau ok)
                // ... (logic sama macam sebelum ni)
                return;
            }
            checkClipboardAndActivate();
        });
    }];
}
