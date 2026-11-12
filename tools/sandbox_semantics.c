/* Local disposable process only: calibrate the exact sandbox API used by the target.
   Contacts FontValidator only with explicit --request-fontvalidator (invalid plist, no font payload).
   Never mints entitlements or changes system policy. */
#include <CoreFoundation/CoreFoundation.h>
#include <Security/SecTask.h>
#include <mach/mach.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
int main(int argc,char **argv) {
    void *lib=dlopen("/usr/lib/libsandbox.1.dylib",RTLD_NOW);
    int (*check)(audit_token_t,const char*,int,...)=dlsym(lib,"sandbox_check_by_audit_token");
    int (*init)(const char*,uint64_t,char**)=dlsym(lib,"sandbox_init");
    if(!check||!init)return 2;
    int sandboxed=argc>1 && strcmp(argv[1],"sandboxed")==0;
    if(sandboxed) {
        char *error=NULL;
        /* Restricts only this test process. Keeps IPC API calls otherwise comparable. */
        if(init("(version 1)(allow default)(deny file-write* (literal \"/tmp/ssj-probe-never-written\"))",0,&error)!=0) {
            fprintf(stderr,"sandbox_init failed: %s\n",error?error:"");return 3;
        }
    }
    audit_token_t token;mach_msg_type_number_t count=TASK_AUDIT_TOKEN_COUNT;
    kern_return_t kr=task_info(mach_task_self(),TASK_AUDIT_TOKEN,(task_info_t)&token,&count);
    if(kr!=KERN_SUCCESS)return 4;
    errno=0;int rc=check(token,NULL,0);int se=errno;
    SecTaskRef task=SecTaskCreateFromSelf(NULL);CFErrorRef error=NULL;
    CFTypeRef value=task?SecTaskCopyValueForEntitlement(task,CFSTR("com.apple.private.ats.validation"),&error):NULL;
    int entitlement_true=value && CFGetTypeID(value)==CFBooleanGetTypeID() && CFBooleanGetValue(value);
    int contacted=0, request_status=-999; long response_length=-1;
    if(argc>2 && strcmp(argv[2],"--request-fontvalidator")==0) {
        CFMessagePortRef remote=CFMessagePortCreateRemote(NULL,CFSTR("com.apple.ATS.FontValidator"));
        if(remote) {
            const char message[]="ssj ipc reachability probe (not a plist)";
            CFDataRef data=CFDataCreate(NULL,(const UInt8*)message,sizeof(message)-1),reply=NULL;
            contacted=1;
            request_status=CFMessagePortSendRequest(remote,0,data,2,2,kCFRunLoopDefaultMode,&reply);
            if(reply){response_length=CFDataGetLength(reply);CFRelease(reply);}
            CFRelease(data);CFRelease(remote);
        }
    }
    printf("{\"pid\":%d,\"uid\":%d,\"euid\":%d,\"requested_sandbox\":%s,\"sandbox_check_by_audit_token\":%d,\"errno\":%d,\"sec_task_created\":%s,\"entitlement_present\":%s,\"entitlement_boolean_true\":%s,\"query_error\":%ld,\"target_contacted\":%s,\"request_status\":%d,\"response_length\":%ld}\n",getpid(),getuid(),geteuid(),sandboxed?"true":"false",rc,se,task?"true":"false",value?"true":"false",entitlement_true?"true":"false",error?(long)CFErrorGetCode(error):0,contacted?"true":"false",request_status,response_length);
    if(value)CFRelease(value);if(error)CFRelease(error);if(task)CFRelease(task);
    return 0;
}
