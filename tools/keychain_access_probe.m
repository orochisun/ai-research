#import <Foundation/Foundation.h>
#include <unistd.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
extern int sandbox_check(pid_t,const char *,int,...);
#include "keychain_probe_common.h"
int main(void){@autoreleasepool{
    NSData *input=[[NSFileHandle fileHandleWithStandardInput] readDataToEndOfFile];
    NSError *error=nil;NSDictionary *record=[NSJSONSerialization JSONObjectWithData:input options:0 error:&error];
    if(!record){fprintf(stderr,"input JSON error: %s\n",error.description.UTF8String);return 2;}
    NSDictionary *reply=record[@"reply"];
    if(![reply isKindOfClass:[NSDictionary class]] || ![reply[@"extensions"] isKindOfClass:[NSArray class]] || ![reply[@"all-paths"] isKindOfClass:[NSDictionary class]] || ![reply[@"keychain-home"] isKindOfClass:[NSString class]]){
        fprintf(stderr,"missing or malformed XPC reply fields\n");return 2;
    }
    NSArray *tokens=reply[@"extensions"];
    for(id token in tokens)if(![token isKindOfClass:[NSString class]]){fprintf(stderr,"extension is not a string\n");return 2;}
    NSMutableOrderedSet *paths=[NSMutableOrderedSet orderedSet];
    for(id group in [reply[@"all-paths"] allValues]){
        if(![group isKindOfClass:[NSArray class]]){fprintf(stderr,"path group is not an array\n");return 2;}
        for(id p in group){if(![p isKindOfClass:[NSString class]]){fprintf(stderr,"path is not a string\n");return 2;}[paths addObject:p];}
    }
    [paths addObject:[reply[@"keychain-home"] stringByAppendingPathComponent:@"Library/Preferences/com.apple.security.plist"]];
    int sandboxed=sandbox_check(getpid(),NULL,0);
    NSArray *before=Checks(paths.array);
    int64_t (*consume)(const char*)=dlsym(RTLD_DEFAULT,"sandbox_extension_consume");
    int (*releaseExtension)(int64_t)=dlsym(RTLD_DEFAULT,"sandbox_extension_release");
    NSMutableArray *handles=[NSMutableArray array];NSMutableArray *attempts=[NSMutableArray array];
    for(NSString *token in tokens){errno=0;int64_t h=consume?consume(token.UTF8String):-1;int err=errno;[handles addObject:@(h)];[attempts addObject:@{@"handle":@(h),@"errno":@(err),@"path":[[token componentsSeparatedByString:@";"] lastObject]}];}
    NSArray *after=Checks(paths.array);
    for(NSNumber *h in handles)if(h.longLongValue>=0&&releaseExtension)releaseExtension(h.longLongValue);
    NSDictionary *result=@{@"pid":@(getpid()),@"uid":@(getuid()),@"sandbox_check_null":@(sandboxed),@"consume_symbol_available":@(consume!=NULL),@"scope":@"sandbox_check file-read-data/file-write-data and open(O_RDONLY)+close; no keychain content read or written; paths use reply spelling; tokens from separate ordinary-session probe",@"before":before,@"consume":attempts,@"after":after};
    NSData *output=[NSJSONSerialization dataWithJSONObject:result options:NSJSONWritingPrettyPrinted error:&error];fwrite(output.bytes,1,output.length,stdout);puts("");return 0;
}}
