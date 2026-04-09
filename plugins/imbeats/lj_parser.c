/*
 * Minimal Lumberjack v2 parser helpers for imbeats.
 *
 * This layer deliberately stays transport-agnostic. Network reads, ACK timing,
 * and rsyslog message construction live in imbeats.c.
 */
#include "config.h"
#include "lj_parser.h"

#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <zlib.h>

static rsRetVal append_event_owned(struct lj_batch_s *batch, uint32_t seq, unsigned char *payload, size_t payload_len) {
    if (batch == NULL || batch->events == NULL || batch->count >= batch->window_size) {
        free(payload);
        return RS_RET_PARAM_ERROR;
    }

    batch->events[batch->count].seq = seq;
    batch->events[batch->count].payload = payload;
    batch->events[batch->count].payload_len = payload_len;
    ++batch->count;
    return RS_RET_OK;
}

rsRetVal lj_batch_alloc(struct lj_batch_s *batch, uint32_t window_size) {
    if (batch == NULL || window_size == 0) {
        return RS_RET_PARAM_ERROR;
    }
    memset(batch, 0, sizeof(*batch));
    batch->window_size = window_size;
    batch->events = calloc(window_size, sizeof(struct lj_event_s));
    return (batch->events == NULL) ? RS_RET_OUT_OF_MEMORY : RS_RET_OK;
}

void lj_batch_free(struct lj_batch_s *batch) {
    size_t i;
    if (batch == NULL) {
        return;
    }
    for (i = 0; i < batch->count; ++i) {
        free(batch->events[i].payload);
    }
    free(batch->events);
    memset(batch, 0, sizeof(*batch));
}

rsRetVal lj_parse_window_header(const unsigned char hdr[2], uint32_t window_size) {
    if (hdr[0] != LJ_VERSION_V2 || hdr[1] != LJ_FRAME_WINDOW || window_size == 0) {
        return RS_RET_INVALID_VALUE;
    }
    return RS_RET_OK;
}

rsRetVal lj_append_json_event(struct lj_batch_s *batch,
                              uint32_t seq,
                              const unsigned char *payload,
                              size_t payload_len) {
    unsigned char *cpy;
    if (batch == NULL || payload == NULL || payload_len == 0) {
        return RS_RET_PARAM_ERROR;
    }
    cpy = malloc(payload_len + 1);
    if (cpy == NULL) {
        return RS_RET_OUT_OF_MEMORY;
    }
    memcpy(cpy, payload, payload_len);
    cpy[payload_len] = '\0';
    return append_event_owned(batch, seq, cpy, payload_len);
}

static rsRetVal parse_frames_from_memory(struct lj_batch_s *batch, const unsigned char *buf, size_t len) {
    size_t off = 0;

    while (off + 2 <= len) {
        const unsigned char ver = buf[off++];
        const unsigned char type = buf[off++];
        uint32_t v1, v2;
        rsRetVal iRet;

        if (ver != LJ_VERSION_V2) {
            return RS_RET_INVALID_VALUE;
        }

        switch (type) {
            case LJ_FRAME_JSON:
                if (off + 8 > len) {
                    return RS_RET_INVALID_VALUE;
                }
                memcpy(&v1, buf + off, 4);
                memcpy(&v2, buf + off + 4, 4);
                off += 8;
                v1 = ntohl(v1);
                v2 = ntohl(v2);
                if (off + v2 > len) {
                    return RS_RET_INVALID_VALUE;
                }
                iRet = lj_append_json_event(batch, v1, buf + off, v2);
                if (iRet != RS_RET_OK) {
                    return iRet;
                }
                off += v2;
                break;
            case LJ_FRAME_COMPRESSED:
                if (off + 4 > len) {
                    return RS_RET_INVALID_VALUE;
                }
                memcpy(&v1, buf + off, 4);
                off += 4;
                v1 = ntohl(v1);
                if (off + v1 > len) {
                    return RS_RET_INVALID_VALUE;
                }
                iRet = lj_parse_compressed_frames(batch, buf + off, v1);
                if (iRet != RS_RET_OK) {
                    return iRet;
                }
                off += v1;
                break;
            default:
                return RS_RET_INVALID_VALUE;
        }
    }

    return (off == len) ? RS_RET_OK : RS_RET_INVALID_VALUE;
}

rsRetVal lj_parse_compressed_frames(struct lj_batch_s *batch, const unsigned char *payload, size_t payload_len) {
    z_stream zstrm;
    unsigned char *out = NULL;
    size_t out_cap = 0;
    size_t out_len = 0;
    int zrc;
    rsRetVal iRet = RS_RET_OK;

    if (batch == NULL || payload == NULL || payload_len == 0) {
        return RS_RET_PARAM_ERROR;
    }

    memset(&zstrm, 0, sizeof(zstrm));
    zstrm.next_in = (Bytef *)payload;
    zstrm.avail_in = payload_len;

    zrc = inflateInit(&zstrm);
    if (zrc != Z_OK) {
        return RS_RET_ZLIB_ERR;
    }

    do {
        if (out_len == out_cap) {
            size_t new_cap = (out_cap == 0) ? 4096 : out_cap * 2;
            unsigned char *tmp = realloc(out, new_cap);
            if (tmp == NULL) {
                iRet = RS_RET_OUT_OF_MEMORY;
                goto finalize_it;
            }
            out = tmp;
            out_cap = new_cap;
        }

        zstrm.next_out = out + out_len;
        zstrm.avail_out = out_cap - out_len;
        zrc = inflate(&zstrm, Z_NO_FLUSH);
        out_len = out_cap - zstrm.avail_out;
        if (zrc != Z_OK && zrc != Z_STREAM_END) {
            iRet = RS_RET_ZLIB_ERR;
            goto finalize_it;
        }
    } while (zrc != Z_STREAM_END);

    iRet = parse_frames_from_memory(batch, out, out_len);

finalize_it:
    inflateEnd(&zstrm);
    free(out);
    return iRet;
}
