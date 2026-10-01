/* Copyright (C) Isovalent, Inc. - All Rights Reserved. */
#include <jni.h>
#include <jvmti.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_CLASSES 32
#define MAX_CLASS_BYTES (16u * 1024u * 1024u)
#define MAX_SIGNATURE 4096u

typedef struct {
    char *signature;
    unsigned char *bytes;
    uint32_t length;
} patch_record;

static uint16_t read_u16(FILE *f, int *ok) {
    unsigned char b[2];
    if (fread(b, 1, sizeof(b), f) != sizeof(b)) { *ok = 0; return 0; }
    return (uint16_t)((b[0] << 8) | b[1]);
}

static uint32_t read_u32(FILE *f, int *ok) {
    unsigned char b[4];
    if (fread(b, 1, sizeof(b), f) != sizeof(b)) { *ok = 0; return 0; }
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8) | (uint32_t)b[3];
}

static int read_manifest(const char *path, patch_record *records, uint32_t *count) {
    static const unsigned char magic[7] = {'T','G','J','V','P','1',0};
    FILE *f = fopen(path, "rb");
    int ok = 1;
    unsigned char got[sizeof(magic)];
    if (f == NULL) return 0;
    if (fread(got, 1, sizeof(got), f) != sizeof(got) || memcmp(got, magic, sizeof(magic)) != 0) ok = 0;
    *count = read_u32(f, &ok);
    if (*count == 0 || *count > MAX_CLASSES) ok = 0;
    for (uint32_t i = 0; ok && i < *count; i++) {
        uint16_t sig_len = read_u16(f, &ok);
        uint32_t data_len = read_u32(f, &ok);
        if (!ok || sig_len < 3 || sig_len > MAX_SIGNATURE || data_len < 8 || data_len > MAX_CLASS_BYTES) { ok = 0; break; }
        records[i].signature = (char *)calloc((size_t)sig_len + 1, 1);
        records[i].bytes = (unsigned char *)malloc(data_len);
        records[i].length = data_len;
        if (!records[i].signature || !records[i].bytes ||
            fread(records[i].signature, 1, sig_len, f) != sig_len ||
            fread(records[i].bytes, 1, data_len, f) != data_len) ok = 0;
        if (ok && (records[i].bytes[0] != 0xca || records[i].bytes[1] != 0xfe ||
                   records[i].bytes[2] != 0xba || records[i].bytes[3] != 0xbe)) ok = 0;
    }
    if (fgetc(f) != EOF) ok = 0;
    fclose(f);
    return ok;
}

static void free_records(patch_record *records, uint32_t count) {
    for (uint32_t i = 0; i < count && i < MAX_CLASSES; i++) {
        free(records[i].signature);
        free(records[i].bytes);
    }
}

static jvmtiError redefine(jvmtiEnv *jvmti, patch_record *records, uint32_t count) {
    jint loaded_count = 0;
    jclass *loaded = NULL;
    jvmtiError err = (*jvmti)->GetLoadedClasses(jvmti, &loaded_count, &loaded);
    if (err != JVMTI_ERROR_NONE) return err;

    jint total = 0;
    for (uint32_t r = 0; r < count; r++) {
        for (jint i = 0; i < loaded_count; i++) {
            char *sig = NULL;
            if ((*jvmti)->GetClassSignature(jvmti, loaded[i], &sig, NULL) == JVMTI_ERROR_NONE &&
                sig != NULL && strcmp(sig, records[r].signature) == 0) total++;
            if (sig != NULL) (*jvmti)->Deallocate(jvmti, (unsigned char *)sig);
        }
    }
    if (total == 0) {
        (*jvmti)->Deallocate(jvmti, (unsigned char *)loaded);
        return JVMTI_ERROR_INVALID_CLASS;
    }

    jvmtiClassDefinition *defs = (jvmtiClassDefinition *)calloc((size_t)total, sizeof(*defs));
    if (defs == NULL) {
        (*jvmti)->Deallocate(jvmti, (unsigned char *)loaded);
        return JVMTI_ERROR_OUT_OF_MEMORY;
    }
    jint n = 0;
    for (uint32_t r = 0; r < count; r++) {
        int matched = 0;
        for (jint i = 0; i < loaded_count; i++) {
            char *sig = NULL;
            if ((*jvmti)->GetClassSignature(jvmti, loaded[i], &sig, NULL) == JVMTI_ERROR_NONE &&
                sig != NULL && strcmp(sig, records[r].signature) == 0) {
                defs[n].klass = loaded[i];
                defs[n].class_byte_count = (jint)records[r].length;
                defs[n].class_bytes = (const unsigned char *)records[r].bytes;
                n++;
                matched = 1;
            }
            if (sig != NULL) (*jvmti)->Deallocate(jvmti, (unsigned char *)sig);
        }
        if (!matched) {
            free(defs);
            (*jvmti)->Deallocate(jvmti, (unsigned char *)loaded);
            return JVMTI_ERROR_INVALID_CLASS;
        }
    }
    err = (*jvmti)->RedefineClasses(jvmti, n, defs);
    free(defs);
    (*jvmti)->Deallocate(jvmti, (unsigned char *)loaded);
    return err;
}

JNIEXPORT jint JNICALL Agent_OnAttach(JavaVM *vm, char *options, void *reserved) {
    (void)reserved;
    static const char manifest_prefix[] = "/run/tetragon-java-patch/";
    if (options == NULL || strncmp(options, manifest_prefix, sizeof(manifest_prefix) - 1) != 0) return JNI_ERR;
    jvmtiEnv *jvmti = NULL;
    if ((*vm)->GetEnv(vm, (void **)&jvmti, JVMTI_VERSION_1_2) != JNI_OK || jvmti == NULL) return JNI_ERR;

    jvmtiCapabilities wanted;
    memset(&wanted, 0, sizeof(wanted));
    wanted.can_redefine_classes = 1;
    jvmtiError err = (*jvmti)->AddCapabilities(jvmti, &wanted);
    if (err != JVMTI_ERROR_NONE) return JNI_ERR;

    patch_record records[MAX_CLASSES];
    memset(records, 0, sizeof(records));
    uint32_t count = 0;
    int ok = read_manifest(options, records, &count);
    if (!ok) { free_records(records, count); return JNI_ERR; }
    err = redefine(jvmti, records, count);
    free_records(records, count);
    return err == JVMTI_ERROR_NONE ? JNI_OK : JNI_ERR;
}

JNIEXPORT void JNICALL Agent_OnUnload(JavaVM *vm) { (void)vm; }
