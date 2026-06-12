#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <crypt.h>

void xcryptQ_libQ___ext_init__() {
    // NOP
}

static void xcrypt__raise_value_error(const char *msg) {
    $RAISE((B_BaseException)B_ValueErrorG_new(to$str((char *)msg)));
}

static B_str xcrypt__crypt(const char *phrase, const char *setting) {
    struct crypt_data data;
    memset(&data, 0, sizeof(data));

    char *result = crypt_r(phrase, setting, &data);
    if (result == NULL) {
        char buf[256];
        snprintf(buf, sizeof(buf), "crypt failed: %s", strerror(errno));
        xcrypt__raise_value_error(buf);
    }
    if (result[0] == '*') {
        xcrypt__raise_value_error("crypt failed");
    }
    return to$str(result);
}

static const char *xcrypt__build_setting(const char *prefix,
                                         const char *salt_or_setting,
                                         long rounds,
                                         char *buffer,
                                         size_t buffer_len) {
    if (rounds < 0) {
        xcrypt__raise_value_error("rounds must be non-negative");
    }
    const size_t prefix_len = strlen(prefix);
    if (strncmp(salt_or_setting, prefix, prefix_len) == 0) {
        return salt_or_setting;
    }

    if (rounds > 0) {
        int n = snprintf(buffer, buffer_len, "%srounds=%ld$%s",
                         prefix, rounds, salt_or_setting);
        if (n < 0 || (size_t)n >= buffer_len) {
            xcrypt__raise_value_error("salt too long");
        }
    } else {
        int n = snprintf(buffer, buffer_len, "%s%s", prefix, salt_or_setting);
        if (n < 0 || (size_t)n >= buffer_len) {
            xcrypt__raise_value_error("salt too long");
        }
    }

    return buffer;
}

static B_str xcrypt__gensalt(const char *prefix, long rounds);

static const char *xcrypt__normalize_bcrypt_ident(const char *ident,
                                                  char *out,
                                                  size_t out_len) {
    if (ident == NULL) {
        xcrypt__raise_value_error("bcrypt ident must be set");
    }
    if (out_len < 3) {
        xcrypt__raise_value_error("internal error");
    }
    size_t len = strlen(ident);
    if (len == 4 && ident[0] == '$' && ident[1] == '2' && ident[3] == '$') {
        out[0] = '2';
        out[1] = ident[2];
        out[2] = '\0';
    } else if (len == 2 && ident[0] == '2') {
        out[0] = '2';
        out[1] = ident[1];
        out[2] = '\0';
    } else {
        xcrypt__raise_value_error("invalid bcrypt ident");
    }
    if (!(out[1] == 'a' || out[1] == 'b' || out[1] == 'x' || out[1] == 'y')) {
        xcrypt__raise_value_error("invalid bcrypt ident");
    }
    return out;
}

static const char *xcrypt__build_setting_bcrypt(const char *salt_or_setting,
                                                long rounds,
                                                const char *ident,
                                                char *buffer,
                                                size_t buffer_len) {
    if (rounds < 0) {
        xcrypt__raise_value_error("rounds must be non-negative");
    }
    if (salt_or_setting == NULL) {
        xcrypt__raise_value_error("salt must be provided");
    }
    if (strncmp(salt_or_setting, "$2", 2) == 0) {
        return salt_or_setting;
    }

    char ident_buf[3];
    const char *ident_norm = xcrypt__normalize_bcrypt_ident(ident, ident_buf, sizeof(ident_buf));
    if (ident_norm[1] == 'x') {
        xcrypt__raise_value_error("bcrypt ident 2x cannot be used for new hashes");
    }
    if (rounds == 0) {
        rounds = 5;
    }
    if (rounds < 4 || rounds > 31) {
        xcrypt__raise_value_error("bcrypt rounds must be between 4 and 31");
    }

    int n = snprintf(buffer, buffer_len, "$%s$%02ld$%s",
                     ident_norm, rounds, salt_or_setting);
    if (n < 0 || (size_t)n >= buffer_len) {
        xcrypt__raise_value_error("salt too long");
    }

    return buffer;
}

static B_str xcrypt__gensalt_bcrypt(long rounds, const char *ident) {
    char ident_buf[3];
    const char *ident_norm = xcrypt__normalize_bcrypt_ident(ident, ident_buf, sizeof(ident_buf));
    if (ident_norm[1] == 'x') {
        xcrypt__raise_value_error("bcrypt ident 2x cannot be used for new hashes");
    }
    char prefix[5] = { '$', '2', ident_norm[1], '$', '\0' };
    return xcrypt__gensalt(prefix, rounds);
}

B_str xcryptQ_libQ_crypt(B_str phrase, B_str setting) {
    const char *phrase_c = (const char *)fromB_str(phrase);
    const char *setting_c = (const char *)fromB_str(setting);
    return xcrypt__crypt(phrase_c, setting_c);
}

B_str xcryptQ_libQ__crypt_sha256(B_str phrase, B_str salt_or_setting, int64_t rounds) {
    char setting_buf[CRYPT_GENSALT_OUTPUT_SIZE];
    const char *setting = xcrypt__build_setting(
        "$5$",
        (const char *)fromB_str(salt_or_setting),
        (long)rounds,
        setting_buf,
        sizeof(setting_buf)
    );
    return xcrypt__crypt((const char *)fromB_str(phrase), setting);
}

B_str xcryptQ_libQ__crypt_sha512(B_str phrase, B_str salt_or_setting, int64_t rounds) {
    char setting_buf[CRYPT_GENSALT_OUTPUT_SIZE];
    const char *setting = xcrypt__build_setting(
        "$6$",
        (const char *)fromB_str(salt_or_setting),
        (long)rounds,
        setting_buf,
        sizeof(setting_buf)
    );
    return xcrypt__crypt((const char *)fromB_str(phrase), setting);
}

B_str xcryptQ_libQ__crypt_md5(B_str phrase, B_str salt_or_setting) {
    char setting_buf[CRYPT_GENSALT_OUTPUT_SIZE];
    const char *setting = xcrypt__build_setting(
        "$1$",
        (const char *)fromB_str(salt_or_setting),
        0,
        setting_buf,
        sizeof(setting_buf)
    );
    return xcrypt__crypt((const char *)fromB_str(phrase), setting);
}

B_str xcryptQ_libQ__crypt_bcrypt(B_str phrase, B_str salt_or_setting, int64_t rounds, B_str ident) {
    char setting_buf[CRYPT_GENSALT_OUTPUT_SIZE];
    const char *setting = xcrypt__build_setting_bcrypt(
        (const char *)fromB_str(salt_or_setting),
        (long)rounds,
        (const char *)fromB_str(ident),
        setting_buf,
        sizeof(setting_buf)
    );
    return xcrypt__crypt((const char *)fromB_str(phrase), setting);
}

static B_str xcrypt__gensalt(const char *prefix, long rounds) {
    if (rounds < 0) {
        xcrypt__raise_value_error("rounds must be non-negative");
    }
    uint8_t rbytes[16];
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    arc4random_buf(rbytes, sizeof(rbytes));
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        char buf[256];
        snprintf(buf, sizeof(buf), "gensalt failed: %s", strerror(errno));
        xcrypt__raise_value_error(buf);
    }
    ssize_t nread = read(fd, rbytes, sizeof(rbytes));
    close(fd);
    if (nread < 0 || (size_t)nread != sizeof(rbytes)) {
        char buf[256];
        snprintf(buf, sizeof(buf), "gensalt failed: %s", strerror(errno));
        xcrypt__raise_value_error(buf);
    }
#endif
    char output[CRYPT_GENSALT_OUTPUT_SIZE];
    char *result = crypt_gensalt_rn(prefix, (unsigned long)rounds,
                                    (const char *)rbytes, (int)sizeof(rbytes),
                                    output, sizeof(output));
    if (result == NULL || result[0] == '*') {
        char buf[256];
        snprintf(buf, sizeof(buf), "gensalt failed: %s", strerror(errno));
        xcrypt__raise_value_error(buf);
    }
    return to$str(result);
}

B_str xcryptQ_libQ__gensalt_sha256(int64_t rounds) {
    return xcrypt__gensalt("$5$", (long)rounds);
}

B_str xcryptQ_libQ__gensalt_sha512(int64_t rounds) {
    return xcrypt__gensalt("$6$", (long)rounds);
}

B_str xcryptQ_libQ__gensalt_md5() {
    return xcrypt__gensalt("$1$", 0);
}

B_str xcryptQ_libQ__gensalt_bcrypt(int64_t rounds, B_str ident) {
    return xcrypt__gensalt_bcrypt((long)rounds, (const char *)fromB_str(ident));
}

// Raw scrypt KDF.  n must be a power of 2 > 1; r * p < 2^30; dklen <= (2^32 - 1) * 32.
B_bytes xcryptQ_libQ_scrypt(B_bytes phrase, B_bytes salt,
                           int64_t n, int64_t r, int64_t p, int64_t dklen) {
    if (n < 2 || (n & (n - 1)) != 0) {
        xcrypt__raise_value_error("scrypt n must be a power of 2 greater than 1");
    }
    if (r <= 0 || p <= 0) {
        xcrypt__raise_value_error("scrypt r and p must be positive");
    }
    if ((uint64_t)r * (uint64_t)p >= (1ULL << 30)) {
        xcrypt__raise_value_error("scrypt requires r * p < 2^30");
    }
    if (dklen <= 0) {
        xcrypt__raise_value_error("scrypt dklen must be positive");
    }

    uint8_t *out = (uint8_t *)acton_malloc((size_t)dklen);
    int rc = crypto_scrypt((const uint8_t *)fromB_bytes(phrase), (size_t)phrase->nbytes,
                           (const uint8_t *)fromB_bytes(salt), (size_t)salt->nbytes,
                           (uint64_t)n, (uint32_t)r, (uint32_t)p,
                           out, (size_t)dklen);
    if (rc != 0) {
        char buf[128];
        snprintf(buf, sizeof(buf), "scrypt failed: %s", strerror(errno));
        xcrypt__raise_value_error(buf);
    }
    return to$bytesD_len((char *)out, (int)dklen);
}
