#pragma once
#import <Foundation/Foundation.h>
#include <xpc/xpc.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
extern int sandbox_check(pid_t,const char *,int,...);
static id JSONValue(xpc_object_t value) {
    xpc_type_t t=xpc_get_type(value);
    if(t==XPC_TYPE_DICTIONARY){
        NSMutableDictionary *d=[NSMutableDictionary dictionary];
        xpc_dictionary_apply(value,^bool(const char *key,xpc_object_t v){ d[@(key)]=JSONValue(v);return true; });return d;
    }
    if(t==XPC_TYPE_ARRAY){
        NSMutableArray *a=[NSMutableArray array];
        xpc_array_apply(value,^bool(size_t i,xpc_object_t v){[a addObject:JSONValue(v)];return true;});return a;
    }
    if(t==XPC_TYPE_STRING)return @(xpc_string_get_string_ptr(value));
    if(t==XPC_TYPE_BOOL)return @(xpc_bool_get_value(value));
    if(t==XPC_TYPE_INT64)return @(xpc_int64_get_value(value));
    if(t==XPC_TYPE_UINT64)return @(xpc_uint64_get_value(value));
    if(t==XPC_TYPE_DATA)return @{ @"encoding":@"base64", @"data":[[NSData dataWithBytes:xpc_data_get_bytes_ptr(value) length:xpc_data_get_length(value)] base64EncodedStringWithOptions:0] };
    if(t==XPC_TYPE_NULL)return [NSNull null];
    char *desc=xpc_copy_description(value);NSString *s=@(desc);free(desc);return s;
}
static NSArray *Checks(NSArray *paths) {
    NSMutableArray *rows=[NSMutableArray array];
    for(NSString *p in paths){
        errno=0;int r=sandbox_check(getpid(),"file-read-data",1,p.UTF8String);int re=errno;
        errno=0;int w=sandbox_check(getpid(),"file-write-data",1,p.UTF8String);int we=errno;
        errno=0;int fd=open(p.UTF8String,O_RDONLY);int oe=fd<0?errno:0;if(fd>=0)close(fd);
        [rows addObject:@{@"open_readonly_success":@(fd>=0),@"open_errno":@(oe),@"path":p,@"file_read_data":@(r),@"read_errno":@(re),@"file_write_data":@(w),@"write_errno":@(we)}];
    }return rows;
}
