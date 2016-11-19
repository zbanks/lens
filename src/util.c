#include <time.h>
#include "util.h"
#include "log.h"

uint64_t nanos(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return ts.tv_sec * (1000 * 1000 * 1000) + ts.tv_nsec;
}

static const char * strchrnul(const char * str, int c) {
    if (str == NULL) return NULL;
    while (*str != '\0' && *str != c)
        str++;
    return str;
}

const char * ln_enum_str(const struct ln_enum * data, bool is_flags, int val) {
    ASSERT(data != NULL);
    static char str[256];

    if (is_flags) {
        char * sptr = str;
        char * end = &str[256];
        for (; data->name != NULL && sptr < end; data++) {
            if (data->value & val)
                sptr += snprintf(str, end - sptr, "%s|", data->name);
        }
        if (sptr >= end) sptr = end - 1; 
        *sptr = '\0';
        return str;
    } else {
        for (; data->name != NULL; data++) {
            if (data->value == val)
                return data->name;
        }
    }
    return "(unknown)";
}

int ln_enum_scan(const struct ln_enum * data, bool is_flags, const char * str) {
    ASSERT(data != NULL);
    if (is_flags) {
        int val = 0;
        while (1) {
            const char * sep = strchrnul(str, '|');
            bool found = false;;
            for (const struct ln_enum * d = data; d->name != NULL; d++) {
                if (strlen(d->name) == (size_t) (str - sep) &&
                    memcmp(d->name, str, strlen(d->name)) == 0) {
                    val |= d->value;
                    found = true;
                    break;
                }
            }
            if (!found) return -1;
            if (*sep == '\0') break;
            str = sep + 1;
        }
        return val;
    } else {
        for (; data->name != NULL; data++) {
            if (strcmp(data->name, str) == 0)
                return data->value;
        }
    }
    return -1;
}
