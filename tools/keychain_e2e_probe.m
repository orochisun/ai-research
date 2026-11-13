// Same App Sandbox process measures baseline, requests tokens, consumes them, and rechecks.
#include "keychain_probe_common.h"
#include <dlfcn.h>
int main(int argc,const char **argv){@autoreleasepool{
    NSError *error=nil;
    NSDictionary *input=[NSJSONSerialization JSONObjectWithData:[[NSFileHandle fileHandleWithStandardInput] readDataToEndOfFile] options:0 error:&error];
    NSArray *paths=input[@"paths"];
    if(![paths isKindOfClass:[NSArray class]]){fprintf(stderr,"expected paths-only JSON\n");return 2;}
    for(id path in paths)if(![path isKindOfClass:[NSString class]]||![path hasPrefix:@"/"]){fprintf(stderr,"invalid path\n");return 2;}
    int sandboxed=sandbox_check(getpid(),NULL,0);
    NSMutableDictionary *result=[@{@"pid":@(getpid()),@"uid":@(getuid()),@"euid":@(geteuid()),@"sandbox_check_null":@(sandboxed),@"scope":@"same App Sandbox process: baseline -> XPC request -> token consumption -> access checks; open+close only, no content read or written",@"request":@{@"service":@"com.apple.security.XPCKeychainSandboxCheck",@"transport":@"xpc_connection_create",@"message":@{@"op":@"GrantKeychainPaths"}},@"pre_request":Checks(paths)} mutableCopy];
    if(sandboxed!=1){result[@"status"]=@"sandbox_not_active";}
    else {
        if(argc>1 && strcmp(argv[1],"--register-bundle")==0){
            void (*addBundle)(const char*,uint64_t)=dlsym(RTLD_DEFAULT,"xpc_add_bundle");
            result[@"bundle_registration"]=@{@"symbol_available":@(addBundle!=NULL),@"path":@"/System/Library/Frameworks/Security.framework/Versions/A/XPCServices/XPCKeychainSandboxCheck.xpc",@"flags":@2};
            if(addBundle)addBundle("/System/Library/Frameworks/Security.framework/Versions/A/XPCServices/XPCKeychainSandboxCheck.xpc",2);
        }
        dispatch_semaphore_t done=dispatch_semaphore_create(0);
        xpc_connection_t c=xpc_connection_create("com.apple.security.XPCKeychainSandboxCheck",dispatch_get_global_queue(0,0));
        xpc_connection_set_event_handler(c, ^(xpc_object_t event) {});
        xpc_connection_resume(c);
        xpc_object_t request=xpc_dictionary_create(NULL,NULL,0);
        xpc_dictionary_set_string(request,"op","GrantKeychainPaths");
        __block NSDictionary *received=nil;
        xpc_connection_send_message_with_reply(c,request,dispatch_get_global_queue(0,0),^(xpc_object_t reply){
            received=@{@"service_pid":@(xpc_connection_get_pid(c)),@"is_dictionary":@(xpc_get_type(reply)==XPC_TYPE_DICTIONARY),@"value":JSONValue(reply)};
            dispatch_semaphore_signal(done);
        });
        long timed=dispatch_semaphore_wait(done,dispatch_time(DISPATCH_TIME_NOW,8*NSEC_PER_SEC));
        if(timed)result[@"status"]=@"request_timeout";
        else if(![received[@"is_dictionary"] boolValue]){result[@"status"]=@"connection_error";result[@"error"]=received[@"value"];}
        else {
            result[@"service_pid"]=received[@"service_pid"];NSDictionary *reply=received[@"value"];result[@"reply"]=reply;
            NSArray *tokens=reply[@"extensions"];
            if(![tokens isKindOfClass:[NSArray class]]||![reply[@"all-paths"] isKindOfClass:[NSDictionary class]])result[@"status"]=@"unexpected_reply";
            else {
                NSMutableOrderedSet *all=[NSMutableOrderedSet orderedSetWithArray:paths];
                for(id group in [reply[@"all-paths"] allValues])if([group isKindOfClass:[NSArray class]])for(id path in group)if([path isKindOfClass:[NSString class]])[all addObject:path];
                if([reply[@"keychain-home"] isKindOfClass:[NSString class]])[all addObject:[reply[@"keychain-home"] stringByAppendingPathComponent:@"Library/Preferences/com.apple.security.plist"]];
                result[@"before"]=Checks(all.array);
                int64_t (*consume)(const char*)=dlsym(RTLD_DEFAULT,"sandbox_extension_consume");
                int (*releaseExtension)(int64_t)=dlsym(RTLD_DEFAULT,"sandbox_extension_release");
                NSMutableArray *attempts=[NSMutableArray array];
                for(id token in tokens){
                    if(![token isKindOfClass:[NSString class]])continue;
                    errno=0;int64_t h=consume?consume([token UTF8String]):-1;int err=errno;
                    [attempts addObject:@{@"handle":@(h),@"errno":@(err),@"path":[[token componentsSeparatedByString:@";"] lastObject]}];
                }
                result[@"consume_symbol_available"]=@(consume!=NULL);result[@"consume"]=attempts;
                result[@"after"]=Checks(all.array);
                NSMutableArray *release=[NSMutableArray array];
                for(NSDictionary *attempt in attempts)if([attempt[@"handle"] longLongValue]>=0&&releaseExtension){errno=0;int rc=releaseExtension([attempt[@"handle"] longLongValue]);[release addObject:@{@"handle":attempt[@"handle"],@"return_code":@(rc),@"errno":@(errno)}];}
                result[@"release"]=release;result[@"after_release"]=Checks(all.array);result[@"status"]=@"reply_and_comparison";
            }
        }
        xpc_connection_cancel(c);
    }
    NSData *data=[NSJSONSerialization dataWithJSONObject:result options:NSJSONWritingPrettyPrinted error:&error];
    if(!data){fprintf(stderr,"JSON serialization failed\n");return 2;}fwrite(data.bytes,1,data.length,stdout);puts("");return 0;
}}
