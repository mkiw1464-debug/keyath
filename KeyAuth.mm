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

std::string extractMessage(const std::string& resp) {
    size_t pos = resp.find("\"message\":\"");
    if (pos != std::string::npos) {
        pos += 11;
        size_t end = resp.find("\"", pos);
        if (end != std::string::npos) {
            return resp.substr(pos, end - pos);
        }
    }
    return "Unknown error from KeyAuth";
}

class KeyAuth {
public:
    std::string name = "azuriteadmin";
    std::string ownerid = "8z9qsAXGks";
    std::string secret = "fea6acbf1b1ef751775c6e12882d8dc1ffb5f264707b7428375e37ed11186697";
    std::string version = "1.0";
    std::string sessionid;
    std::string lastError;

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
        if (sessionid.empty() && !init()) {
            lastError = "Failed to init session";
            return false;
        }
        
        std::string post = "type=license&key=" + key +
                           "&sessionid=" + sessionid +
                           "&name=" + name +
                           "&ownerid=" + ownerid +
                           "&secret=" + secret +
                           "&hwid=" + getHWID();
        
        std::string resp = performPOST(post);
        if (resp.find("\"success\":true") != std::string::npos) {
            return true;
        } else {
            lastError = extractMessage(resp);
            NSLog(@"KeyAuth Debug: %s", resp.c_str()); // untuk log kalau ada
            return false;
        }
    }
};

// Keychain functions (sama macam sebelum ni)
std::string loadKeyFromKeychain() { /* sama */ }
bool saveKeyToKeychain(const std::string& key) { /* sama */ }
void deleteKeyFromKeychain() { /* sama */ }

// GUI dengan error message tepat
void showKeyPrompt(const std::string& errorMsg = "") {
    dispatch_async(dispatch_get_main_queue(), ^{
        NSString *title = errorMsg.empty() ? @"Azurite KeyAuth" : @"Key Tidak Sah";
        NSString *message = errorMsg.empty() ? @"Masukkan license key anda" : [NSString stringWithUTF8String:errorMsg.c_str()];
        
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:title
                                                                       message:message
                                                                preferredStyle:UIAlertControllerStyleAlert];
        
        [alert addTextFieldWithConfigurationHandler:^(UITextField *tf) {
            tf.placeholder = @"Paste key sini";
        }];
        
        [alert addAction:[UIAlertAction actionWithTitle:@"Submit" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            UITextField *tf = alert.textFields.firstObject;
            std::string k = [[[tf.text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] stringByReplacingOccurrencesOfString:@" " withString:@""] UTF8String];
            
            if (k.empty()) {
                showKeyPrompt();
                return;
            }
            
            KeyAuth auth;
            if (auth.checkKey(k)) {
                saveKeyToKeychain(k);
                // Key OK
            } else {
                showKeyPrompt(auth.lastError);
            }
        }]];
        
        [alert addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:^(UIAlertAction *) { exit(0); }]];
        
        UIViewController *vc = [[[[UIApplication sharedApplication] keyWindow] rootViewController] presentedViewController] ?: [[[UIApplication sharedApplication] keyWindow] rootViewController];
        [vc presentViewController:alert animated:YES completion:nil];
    });
}

// Auto start
__attribute__((constructor)) static void init() {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        std::string saved = loadKeyFromKeychain();
        if (!saved.empty()) {
            KeyAuth auth;
            if (auth.checkKey(saved)) return;
            deleteKeyFromKeychain();
        }
        showKeyPrompt();
    });
}
