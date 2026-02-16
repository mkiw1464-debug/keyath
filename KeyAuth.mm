#include <string>
#include <UIKit/UIKit.h>
#include <Foundation/Foundation.h>
#include <Security/Security.h>
#include <dispatch/dispatch.h>

std::string getHWID() {
    return std::string([[[UIDevice currentDevice] identifierForVendor].UUIDString UTF8String]);
}

void performPOST(const std::string& postData, void(^completion)(std::string resp)) {
    NSURL *url = [NSURL URLWithString:@"https://keyauth.win/api/1.2/"];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    [req setHTTPMethod:@"POST"];
    [req setHTTPBody:[NSData dataWithBytes:postData.c_str() length:postData.length()]];
    [req setValue:@"application/x-www-form-urlencoded" forHTTPHeaderField:@"Content-Type"];
    
    NSURLSessionDataTask *task = [[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        std::string result = "";
        if (data) result = std::string((char*)[data bytes], [data length]);
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(result);
        });
    }];
    [task resume];
}

class KeyAuth {
public:
    std::string name = "azuriteadmin";
    std::string ownerid = "8z9qsAXGks";
    std::string secret = "fea6acbf1b1ef751775c6e12882d8dc1ffb5f264707b7428375e37ed11186697";
    std::string version = "1.0";
    std::string sessionid;
    std::string lastError;

    void init(void(^callback)(bool success)) {
        std::string post = "type=init&ver=" + version + "&name=" + name + "&ownerid=" + ownerid + "&secret=" + secret;
        performPOST(post, ^(std::string resp) {
            if (resp.find("\"success\":true") != std::string::npos) {
                size_t pos = resp.find("\"sessionid\":\"");
                if (pos != std::string::npos) {
                    pos += 14;
                    size_t end = resp.find("\"", pos);
                    sessionid = resp.substr(pos, end - pos);
                }
                callback(true);
            } else {
                lastError = "Init failed";
                callback(false);
            }
        });
    }

    void checkKey(const std::string& key, void(^callback)(bool valid, std::string error)) {
        if (sessionid.empty()) {
            init(^(bool ok) {
                if (ok) checkKey(key, callback);
                else callback(false, "Failed to connect to server");
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
                std::string msg = "Invalid key";
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

// Keychain (sama)
std::string loadKeyFromKeychain() { /* copy dari code lama */ }
bool saveKeyToKeychain(const std::string& key) { /* copy dari code lama */ }
void deleteKeyFromKeychain() { /* copy dari code lama */ }

// GUI
void showKeyPrompt(const std::string& errorMsg = "") {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:errorMsg.empty() ? @"Azurite KeyAuth" : @"Key Tidak Sah"
                                                                       message:errorMsg.empty() ? @"Masukkan license key" : [NSString stringWithUTF8String:errorMsg.c_str()]
                                                                preferredStyle:UIAlertControllerStyleAlert];
        
        [alert addTextFieldWithConfigurationHandler:^(UITextField *tf) { tf.placeholder = @"Paste key sini"; }];
        
        UIAlertAction *submit = [UIAlertAction actionWithTitle:@"Submit" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
            std::string k = [[[alert.textFields[0] text] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] UTF8String];
            if (k.empty()) { showKeyPrompt(); return; }
            
            // Loading
            UIAlertController *loading = [UIAlertController alertControllerWithTitle:@"Checking Key..." message:nil preferredStyle:UIAlertControllerStyleAlert];
            [topViewController() presentViewController:loading animated:YES completion:nil];
            
            KeyAuth().checkKey(k, ^(bool valid, std::string err) {
                [loading dismissViewControllerAnimated:YES completion:^{
                    if (valid) {
                        saveKeyToKeychain(k);
                    } else {
                        showKeyPrompt(err);
                    }
                }];
            });
        }];
        
        [alert addAction:submit];
        [alert addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:^(UIAlertAction *) { exit(0); }]];
        
        [topViewController() presentViewController:alert animated:YES completion:nil];
    });
}

// Auto start
__attribute__((constructor))
static void initKeyAuth() {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 6 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        std::string saved = loadKeyFromKeychain();
        if (!saved.empty()) {
            KeyAuth auth;
            auth.checkKey(saved, ^(bool valid, std::string err) {
                if (valid) return;
                deleteKeyFromKeychain();
                showKeyPrompt(err);
            });
            return;
        }
        showKeyPrompt();
    });
}
