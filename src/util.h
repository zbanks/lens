#pragma once
#include "base.h"

#define LN_CONCAT(X, Y) LN_CONCAT2(X, Y)
#define LN_CONCAT2(X, Y) X ## Y

#define LN_STRINGIFY(X) LN_STRINGIFY2(X)
#define LN_STRINGIFY2(X) #X

//

struct ln_enum {
    int value;
    const char * name;
};

const char * ln_enum_str(const struct ln_enum * data, bool is_flags, int val);
int ln_enum_scan(const struct ln_enum * data, bool is_flags, const char * str);

//

#define LN_MAP_ENUM_DEFINE(name, prefix, MAP) enum name { MAP(LN_MAP_ENUM_DEFINE2, prefix) }
#define LN_MAP_ENUM_DEFINE2(PREFIX, NAME, VALUE)  LN_CONCAT(PREFIX ## _, NAME) = VALUE,

#define LN_MAP_ENUM_PRINT_PROTO(name, prefix, MAP) \
    const char * LN_CONCAT(name, _print)(enum name value)
#define LN_MAP_ENUM_PRINT_DEFINE(name, prefix, MAP) \
    LN_MAP_ENUM_PRINT_PROTO(name, prefix, MAP) { \
        switch(value) { \
            MAP(LN_MAP_DEFINE_ENUM_PRINT2, prefix) \
            default: return "???"; \
        } \
    }
#define LN_MAP_DEFINE_ENUM_PRINT2(PREFIX, NAME, VALUE) case VALUE: return LN_STRINGIFY(NAME);

#define LN_MAP_ENUM_BITMAP_PRINT_PROTO LN_MAP_ENUM_PRINT_PROTO
#define LN_MAP_ENUM_BITMAP_PRINT_DEFINE(name, prefix, MAP) \
    LN_MAP_ENUM_PRINT_PROTO(name, prefix, MAP) { \
        static char str[128]; char * ptr = str; size_t rlen = sizeof str; \
        MAP(LN_MAP_ENUM_BITMAP_PRINT_DEFINE2, PREFIX) \
        *--ptr = '\0'; \
        return str; \
        fail: return NULL; \
    }
#define LN_MAP_ENUM_BITMAP_PRINT_DEFINE2(PREFIX, NAME, VALUE) \
    if (value & VALUE) { \
        int len = snprintf(ptr, rlen, #NAME "|"); \
        if (len < 0) goto fail; \
        ptr += len; rlen -= len; \
    }

#define LN_MAP_ENUM_SCAN_PROTO(name, prefix, MAP) \
    enum name LN_CONCAT(name, _scan)(const char * value)
#define LN_MAP_ENUM_SCAN_DEFINE(name, prefix, MAP) \
    LN_MAP_ENUM_SCAN_PROTO(name, prefix, MAP) { \
        if (value == NULL || *value == '\0') goto fail; \
        MAP(LN_MAP_ENUM_SCAN_DEFINE2, PREFIX) \
        errno = 0; \
        enum name int_val = strtol(value, NULL, 0); \
        if (errno == 0) return int_val; \
        fail: \
        ERROR("Unable to parse enum value '%s'", value); \
        return -1; \
    }
#define LN_MAP_ENUM_SCAN_DEFINE2(PREFIX, NAME, VALUE) \
    if (strcasecmp(#NAME, value) == 0) return VALUE;
