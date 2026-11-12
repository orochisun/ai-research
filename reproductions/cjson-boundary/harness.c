#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"

static void run(const char *name, const unsigned char *src, size_t n, int required)
{
    unsigned char *buf = malloc(n ? n : 1);
    const char *end = NULL;
    cJSON *item;
    size_t i;
    if (n) memcpy(buf, src, n);
    item = cJSON_ParseWithLengthOpts((const char *)buf, n, &end, required);
    printf("%s len=%zu require=%d result=%s end_offset=%td", name, n, required,
           item ? "success" : "failure", end ? end - (const char *)buf : -1);
    if (item) { char *s = cJSON_PrintUnformatted(item); printf(" json=%s", s ? s : "<print-failed>"); free(s); cJSON_Delete(item); }
    printf(" bytes="); for (i=0;i<n;i++) printf("%02x",buf[i]); puts("");
    free(buf);
}

int main(void)
{
    static const unsigned char valid_nul[] = {'{','"','a','"',':','1','}',0};
    static const unsigned char valid_raw[] = {'{','"','a','"',':','1','}'};
    static const unsigned char truncated[] = {'{','"','a','"',':','1'};
    static const unsigned char junk[] = {'{','"','a','"',':','1','}','x',0};
    static const unsigned char space_nul[] = {'{','}', ' ', 0};
    static const unsigned char empty[] = {0};
    run("valid_with_nul_required", valid_nul, sizeof valid_nul, 1);
    run("valid_without_nul_optional", valid_raw, sizeof valid_raw, 0);
    run("valid_without_nul_required", valid_raw, sizeof valid_raw, 1);
    run("truncated_optional", truncated, sizeof truncated, 0);
    run("truncated_required", truncated, sizeof truncated, 1);
    run("trailing_junk_optional", junk, sizeof junk, 0);
    run("trailing_junk_required", junk, sizeof junk, 1);
    run("whitespace_then_nul_required", space_nul, sizeof space_nul, 1);
    run("zero_length", empty, 0, 0);
    return 0;
}
