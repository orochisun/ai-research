// Preserve the actual XPC reply, including extension tokens. No keychain contents are read.
#import <Foundation/Foundation.h>
#include <xpc/xpc.h>
#include <unistd.h>
#include "keychain_probe_common.h"
int main(void) { @autoreleasepool {
    dispatch_semaphore_t done=dispatch_semaphore_create(0);
    xpc_connection_t c=xpc_connection_create("com.apple.security.XPCKeychainSandboxCheck",dispatch_get_global_queue(0,0));
    if(!c) return 2;
    xpc_connection_set_event_handler(c, ^(xpc_object_t event) {});
    xpc_connection_resume(c);
    xpc_object_t request=xpc_dictionary_create(NULL,NULL,0);
    xpc_dictionary_set_string(request,"op","GrantKeychainPaths");
    xpc_connection_send_message_with_reply(c,request,dispatch_get_global_queue(0,0),^(xpc_object_t reply){
        NSMutableDictionary *result=[NSMutableDictionary dictionaryWithDictionary:@{@"caller_pid":@(getpid()),@"caller_uid":@(getuid()),@"service_pid":@(xpc_connection_get_pid(c))}];
        if(xpc_get_type(reply)==XPC_TYPE_DICTIONARY){
            result[@"status"]=@"reply";
            result[@"request"]=@{@"op":@"GrantKeychainPaths"};
            result[@"reply"]=JSONValue(reply);
            result[@"extensions_consumed"]=@NO;
        } else { result[@"status"]=@"connection_error";char *desc=xpc_copy_description(reply);result[@"error"]=@(desc);free(desc); }
        NSData *data=[NSJSONSerialization dataWithJSONObject:result options:0 error:nil];
        fwrite(data.bytes,1,data.length,stdout);puts("");fflush(stdout);
        // Keep connection alive briefly for an independent PID sample.
        sleep(2);dispatch_semaphore_signal(done);
    });
    long timed=dispatch_semaphore_wait(done,dispatch_time(DISPATCH_TIME_NOW,8*NSEC_PER_SEC));
    if(timed) puts("{\"status\":\"timeout\"}");
    xpc_connection_cancel(c);return timed?3:0;
} }
