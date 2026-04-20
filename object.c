// object.c — Content-addressable object store
//
// Every piece of data (file contents, directory listings, commits) is stored
// as an "object" named by its SHA-256 hash. Objects are stored under
// .pes/objects/XX/YYYYYY... where XX is the first two hex characters of the
// hash (directory sharding).
//
// PROVIDED functions: compute_hash, object_path, object_exists, hash_to_hex, hex_to_hash
// TODO functions:     object_write, object_read

#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>

// ─── PROVIDED ────────────────────────────────────────────────────────────────

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len);
    EVP_MD_CTX_free(ctx);
}

// Get the filesystem path where an object should be stored.
// Format: .pes/objects/XX/YYYYYYYY...
// The first 2 hex chars form the shard directory; the rest is the filename.
void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

// ─── TODO: Implement these ──────────────────────────────────────────────────
char *object_write(const char *type, const void *data, size_t len) {
    // 1. Prepare Header
    char header[64];
    int header_len = sprintf(header, "%s %zu", type, len) + 1; // +1 for the '\0'

    // 2. Combine Header and Data
    size_t total_len = header_len + len;
    unsigned char *buffer = malloc(total_len);
    if (!buffer) return NULL;

    memcpy(buffer, header, header_len);
    memcpy(buffer + header_len, data, len);

    // 3. Generate Hash (using the provided sha256_hex function)
    char *hash = sha256_hex(buffer, total_len);
    
    // 4. Create Path: .pes/objects/xx/rest_of_hash
    char dir_path[256], file_path[256];
    char prefix[3];
    strncpy(prefix, hash, 2);
    prefix[2] = '\0';

    sprintf(dir_path, ".pes/objects/%s", prefix);
    sprintf(file_path, "%s/%s", dir_path, hash + 2);

    // 5. Ensure directory exists
    mkdir(".pes/objects", 0755);
    mkdir(dir_path, 0755);

    // 6. Write to File
    FILE *f = fopen(file_path, "wb");
    if (f) {
        fwrite(buffer, 1, total_len, f);
        fclose(f);
    }

    free(buffer);
    return hash; // Caller is responsible for freeing this string
}

int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    // TODO: Implement
    (void)type; (void)data; (void)len; (void)id_out;
    return -1;
}

// Read an object from the store.
void *object_read(const char *hash, char *type_out, size_t *len_out) {
    char file_path[256];
    sprintf(file_path, ".pes/objects/%.2s/%s", hash, hash + 2);

    FILE *f = fopen(file_path, "rb");
    if (!f) return NULL;

    // Get file size
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);

    void *buffer = malloc(size);
    fread(buffer, 1, size, f);
    fclose(f);

    // Parse header: "type size\0data"
    char *header = (char *)buffer;
    strcpy(type_out, header);
    
    size_t header_len = strlen(header) + 1;
    *len_out = size - header_len;

    // Move data to front and return
    void *data = malloc(*len_out);
    memcpy(data, buffer + header_len, *len_out);
    free(buffer);
    
    return data;
}
int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    // TODO: Implement
    (void)id; (void)type_out; (void)data_out; (void)len_out;
    return -1;
}
