#ifndef miniaudio_libopus_c
#define miniaudio_libopus_c

#include "miniaudio_libopus.h"

#if !defined(MA_NO_LIBOPUS)
#include <opus/opusfile.h>
#endif

#include <string.h> /* For memset(). */
#include <assert.h>

static ma_result ma_libopus_ds_read(ma_data_source* pDataSource, void* pFramesOut, ma_uint64 frameCount, ma_uint64* pFramesRead)
{
    return ma_libopus_read_pcm_frames((ma_libopus*)pDataSource, pFramesOut, frameCount, pFramesRead);
}

static ma_result ma_libopus_ds_seek(ma_data_source* pDataSource, ma_uint64 frameIndex)
{
    return ma_libopus_seek_to_pcm_frame((ma_libopus*)pDataSource, frameIndex);
}

static ma_result ma_libopus_ds_get_data_format(ma_data_source* pDataSource, ma_format* pFormat, ma_uint32* pChannels, ma_uint32* pSampleRate, ma_channel* pChannelMap, size_t channelMapCap)
{
    return ma_libopus_get_data_format((ma_libopus*)pDataSource, pFormat, pChannels, pSampleRate, pChannelMap, channelMapCap);
}

static ma_result ma_libopus_ds_get_cursor(ma_data_source* pDataSource, ma_uint64* pCursor)
{
    return ma_libopus_get_cursor_in_pcm_frames((ma_libopus*)pDataSource, pCursor);
}

static ma_result ma_libopus_ds_get_length(ma_data_source* pDataSource, ma_uint64* pLength)
{
    return ma_libopus_get_length_in_pcm_frames((ma_libopus*)pDataSource, pLength);
}

static ma_data_source_vtable g_ma_libopus_ds_vtable =
{
    ma_libopus_ds_read,
    ma_libopus_ds_seek,
    ma_libopus_ds_get_data_format,
    ma_libopus_ds_get_cursor,
    ma_libopus_ds_get_length,
    NULL,   /* onSetLooping */
    0       /* flags */
};


#if !defined(MA_NO_LIBOPUS)
static int ma_libopus_of_callback__read(void* pUserData, unsigned char* pBufferOut, int bytesToRead)
{
    ma_libopus* pOpus = (ma_libopus*)pUserData;
    ma_result result;
    size_t bytesRead;

    result = pOpus->onRead(pOpus->pReadSeekTellUserData, (void*)pBufferOut, bytesToRead, &bytesRead);

    if (result != MA_SUCCESS) {
        return -1;
    }

    return (int)bytesRead;
}

static int ma_libopus_of_callback__seek(void* pUserData, ogg_int64_t offset, int whence)
{
    ma_libopus* pOpus = (ma_libopus*)pUserData;
    ma_result result;
    ma_seek_origin origin;

    /*
    NVGT: libvorbisfile and opusfile ask whether a stream can seek with a seek by nothing from where it is, which a stream that can't seek
    answers as the no-op it is, and they then took where they were for the stream's end, cutting it short. The question is answered here,
    and only here, as dr_wav makes that same seek as a no-op that must succeed: by trying the stream's end and coming back to where it was.
    */
    if (offset == 0 && whence == SEEK_CUR) {
        ma_int64 cursor;
        ma_bool32 seekable;
        if (pOpus->onTell == NULL || pOpus->onTell(pOpus->pReadSeekTellUserData, &cursor) != MA_SUCCESS) {
            return -1;
        }
        seekable = pOpus->onSeek(pOpus->pReadSeekTellUserData, 0, ma_seek_origin_end) == MA_SUCCESS;
        if (pOpus->onSeek(pOpus->pReadSeekTellUserData, cursor, ma_seek_origin_start) != MA_SUCCESS) {
            return -1;
        }
        return seekable ? 0 : -1;
    }

    if (whence == SEEK_SET) {
        origin = ma_seek_origin_start;
    } else if (whence == SEEK_END) {
        origin = ma_seek_origin_end;
    } else {
        origin = ma_seek_origin_current;
    }

    result = pOpus->onSeek(pOpus->pReadSeekTellUserData, offset, origin);
    if (result != MA_SUCCESS) {
        return -1;
    }

    return 0;
}

static opus_int64 ma_libopus_of_callback__tell(void* pUserData)
{
    ma_libopus* pOpus = (ma_libopus*)pUserData;
    ma_result result;
    ma_int64 cursor;

    if (pOpus->onTell == NULL) {
        return -1;
    }

    result = pOpus->onTell(pOpus->pReadSeekTellUserData, &cursor);
    if (result != MA_SUCCESS) {
        return -1;
    }

    return cursor;
}

/*
opusfile reports a hole where the stream is interrupted, as at a damaged page: reading goes on past it rather than ending there. Only so many in a
row without a frame end the stream, as a guard against data with nothing to decode in it.
*/
#define MA_LIBOPUS_MAX_HOLES 16

static void ma_libopus_opened(ma_libopus* pOpus)
{
    /* The first logical stream's channels, which MiniAudio reads every frame in. Without a stream that can seek, opusfile knows only the current one, the first as it opens. */
    int channels = op_channel_count((OggOpusFile*)pOpus->of, 0);
    if (channels > 0) {
        pOpus->channels = (ma_uint32)channels;
    }
}
#endif

static ma_result ma_libopus_init_internal(const ma_decoding_backend_config* pConfig, const ma_allocation_callbacks* pAllocationCallbacks, ma_libopus* pOpus)
{
    ma_result result;
    ma_data_source_config dataSourceConfig;

    if (pOpus == NULL) {
        return MA_INVALID_ARGS;
    }

    memset(pOpus, 0, sizeof(*pOpus));
    pOpus->format = ma_format_f32;    /* f32 by default. */
    ma_ogg_link_frames_init(&pOpus->link, pAllocationCallbacks);

    if (pConfig != NULL && (pConfig->preferredFormat == ma_format_f32 || pConfig->preferredFormat == ma_format_s16)) {
        pOpus->format = pConfig->preferredFormat;
    } else {
        /* Getting here means something other than f32 and s16 was specified. Just leave this unset to use the default format. */
    }

    dataSourceConfig = ma_data_source_config_init();
    dataSourceConfig.vtable = &g_ma_libopus_ds_vtable;

    result = ma_data_source_init(&dataSourceConfig, &pOpus->ds);
    if (result != MA_SUCCESS) {
        return result;  /* Failed to initialize the base data source. */
    }

    return MA_SUCCESS;
}

MA_API ma_result ma_libopus_init(ma_read_proc onRead, ma_seek_proc onSeek, ma_tell_proc onTell, void* pReadSeekTellUserData, const ma_decoding_backend_config* pConfig, const ma_allocation_callbacks* pAllocationCallbacks, ma_libopus* pOpus)
{
    ma_result result;

    (void)pAllocationCallbacks; /* Can't seem to find a way to configure memory allocations in libopus. */
    
    result = ma_libopus_init_internal(pConfig, pAllocationCallbacks, pOpus);
    if (result != MA_SUCCESS) {
        return result;
    }

    if (onRead == NULL || onSeek == NULL) {
        return MA_INVALID_ARGS; /* onRead and onSeek are mandatory. */
    }

    pOpus->onRead = onRead;
    pOpus->onSeek = onSeek;
    pOpus->onTell = onTell;
    pOpus->pReadSeekTellUserData = pReadSeekTellUserData;

    #if !defined(MA_NO_LIBOPUS)
    {
        int libopusResult;
        OpusFileCallbacks libopusCallbacks;

        /* We can now initialize the Opus decoder. This must be done after we've set up the callbacks. */
        libopusCallbacks.read  = ma_libopus_of_callback__read;
        libopusCallbacks.seek  = ma_libopus_of_callback__seek;
        libopusCallbacks.close = NULL;
        libopusCallbacks.tell  = ma_libopus_of_callback__tell;

        pOpus->of = op_open_callbacks(pOpus, &libopusCallbacks, NULL, 0, &libopusResult);
        if (pOpus->of == NULL) {
            return MA_INVALID_FILE;
        }
        ma_libopus_opened(pOpus);

        return MA_SUCCESS;
    }
    #else
    {
        /* libopus is disabled. */
        return MA_NOT_IMPLEMENTED;
    }
    #endif
}

MA_API ma_result ma_libopus_init_file(const char* pFilePath, const ma_decoding_backend_config* pConfig, const ma_allocation_callbacks* pAllocationCallbacks, ma_libopus* pOpus)
{
    ma_result result;

    (void)pAllocationCallbacks; /* Can't seem to find a way to configure memory allocations in libopus. */

    result = ma_libopus_init_internal(pConfig, pAllocationCallbacks, pOpus);
    if (result != MA_SUCCESS) {
        return result;
    }

    #if !defined(MA_NO_LIBOPUS)
    {
        int libopusResult;

        pOpus->of = op_open_file(pFilePath, &libopusResult);
        if (pOpus->of == NULL) {
            return MA_INVALID_FILE;
        }
        ma_libopus_opened(pOpus);

        return MA_SUCCESS;
    }
    #else
    {
        /* libopus is disabled. */
        (void)pFilePath;
        return MA_NOT_IMPLEMENTED;
    }
    #endif
}

MA_API void ma_libopus_uninit(ma_libopus* pOpus, const ma_allocation_callbacks* pAllocationCallbacks)
{
    if (pOpus == NULL) {
        return;
    }

    (void)pAllocationCallbacks;

    #if !defined(MA_NO_LIBOPUS)
    {
        op_free((OggOpusFile*)pOpus->of);
    }
    #else
    {
        /* libopus is disabled. Should never hit this since initialization would have failed. */
        assert(MA_FALSE);
    }
    #endif

    ma_ogg_link_frames_uninit(&pOpus->link);
    ma_data_source_uninit(&pOpus->ds);
}

MA_API ma_result ma_libopus_read_pcm_frames(ma_libopus* pOpus, void* pFramesOut, ma_uint64 frameCount, ma_uint64* pFramesRead)
{
    if (pFramesRead != NULL) {
        *pFramesRead = 0;
    }

    if (frameCount == 0) {
        return MA_INVALID_ARGS;
    }

    if (pOpus == NULL) {
        return MA_INVALID_ARGS;
    }

    #if !defined(MA_NO_LIBOPUS)
    {
        ma_result result = MA_SUCCESS;  /* Must be initialized to MA_SUCCESS. */
        OggOpusFile* of = (OggOpusFile*)pOpus->of;
        ma_uint64 totalFramesRead;
        ma_format format = pOpus->format;
        ma_uint32 channels = pOpus->channels;
        int holes = 0;

        if (channels == 0) {
            return MA_INVALID_OPERATION;
        }

        totalFramesRead = 0;
        while (totalFramesRead < frameCount) {
            long libopusResult;
            ma_uint64 framesToRead;
            ma_uint64 framesRemaining;
            size_t samplesToRead;
            void* pHeld;
            int link;
            int linkChannels;

            framesRemaining = (frameCount - totalFramesRead);

            if (pOpus->link.frameCount > 0) {
                ma_uint64 framesTaken;

                result = ma_ogg_link_frames_take(&pOpus->link, format, channels, 48000, ma_offset_pcm_frames_ptr(pFramesOut, totalFramesRead, format, channels), framesRemaining, &framesTaken);
                if (result != MA_SUCCESS) {
                    break;
                }

                totalFramesRead += framesTaken;
                continue;
            }

            framesToRead = 1024;
            if (framesToRead > framesRemaining) {
                framesToRead = framesRemaining;
            }

            /*
            opusfile writes as many whole frames of the logical stream it reads as fit, in that stream's channels, which aren't known
            before it returns, so it writes to frames held, given as they are or converted. At least a frame of any stream fits.
            */
            linkChannels = op_channel_count(of, -1);
            samplesToRead = (size_t)framesToRead * (((ma_uint32)linkChannels > channels) ? (ma_uint32)linkChannels : channels);
            if (samplesToRead < 255) {
                samplesToRead = 255;
            }

            pHeld = ma_ogg_link_frames_reserve(&pOpus->link, samplesToRead * sizeof(float));   /* Room for them in float, if they are to be converted. */
            if (pHeld == NULL) {
                result = MA_OUT_OF_MEMORY;
                break;
            }

            link = -1;
            if (format == ma_format_f32) {
                libopusResult = op_read_float(of, (float*     )pHeld, (int)samplesToRead, &link);
            } else {
                libopusResult = op_read      (of, (opus_int16*)pHeld, (int)samplesToRead, &link);
            }

            if (libopusResult == OP_HOLE && ++holes <= MA_LIBOPUS_MAX_HOLES) {
                continue;
            }

            if (libopusResult < 0) {
                result = MA_ERROR;  /* Error while decoding. */
                break;
            }

            if (libopusResult == 0) {
                result = MA_AT_END;
                break;
            }

            linkChannels = op_channel_count(of, link);
            if (linkChannels <= 0) {
                result = MA_ERROR;
                break;
            }

            holes = 0;
            if ((ma_uint32)linkChannels == channels || format == ma_format_f32) {
                ma_ogg_link_frames_hold(&pOpus->link, libopusResult, format, (ma_uint32)linkChannels, 48000);
            } else {
                ma_ogg_link_frames_hold_s16_as_f32(&pOpus->link, libopusResult, (ma_uint32)linkChannels, 48000);
            }
        }

        pOpus->cursor += totalFramesRead;

        if (pFramesRead != NULL) {
            *pFramesRead = totalFramesRead;
        }

        if (result == MA_SUCCESS && totalFramesRead == 0) {
            result = MA_AT_END;
        }

        return result;
    }
    #else
    {
        /* libopus is disabled. Should never hit this since initialization would have failed. */
        assert(MA_FALSE);

        (void)pFramesOut;
        (void)frameCount;
        (void)pFramesRead;

        return MA_NOT_IMPLEMENTED;
    }
    #endif
}

MA_API ma_result ma_libopus_seek_to_pcm_frame(ma_libopus* pOpus, ma_uint64 frameIndex)
{
    if (pOpus == NULL) {
        return MA_INVALID_ARGS;
    }

    #if !defined(MA_NO_LIBOPUS)
    {
        int libopusResult = op_pcm_seek((OggOpusFile*)pOpus->of, (ogg_int64_t)frameIndex);
        if (libopusResult != 0) {
            if (libopusResult == OP_ENOSEEK) {
                return MA_INVALID_OPERATION;    /* Not seekable. */
            } else if (libopusResult == OP_EINVAL) {
                return MA_INVALID_ARGS;
            } else {
                return MA_ERROR;
            }
        }

        ma_ogg_link_frames_clear(&pOpus->link);
        pOpus->cursor = frameIndex;

        return MA_SUCCESS;
    }
    #else
    {
        /* libopus is disabled. Should never hit this since initialization would have failed. */
        assert(MA_FALSE);

        (void)frameIndex;

        return MA_NOT_IMPLEMENTED;
    }
    #endif
}

MA_API ma_result ma_libopus_get_data_format(ma_libopus* pOpus, ma_format* pFormat, ma_uint32* pChannels, ma_uint32* pSampleRate, ma_channel* pChannelMap, size_t channelMapCap)
{
    /* Defaults for safety. */
    if (pFormat != NULL) {
        *pFormat = ma_format_unknown;
    }
    if (pChannels != NULL) {
        *pChannels = 0;
    }
    if (pSampleRate != NULL) {
        *pSampleRate = 0;
    }
    if (pChannelMap != NULL) {
        memset(pChannelMap, 0, sizeof(*pChannelMap) * channelMapCap);
    }

    if (pOpus == NULL) {
        return MA_INVALID_OPERATION;
    }

    if (pFormat != NULL) {
        *pFormat = pOpus->format;
    }

    #if !defined(MA_NO_LIBOPUS)
    {
        /* The first logical stream's, whichever is read: MiniAudio reads every frame in the format reported as the decoder opened. */
        ma_uint32 channels = pOpus->channels;
        if (channels == 0) {
            return MA_INVALID_OPERATION;
        }

        if (pChannels != NULL) {
            *pChannels = channels;
        }

        if (pSampleRate != NULL) {
            *pSampleRate = 48000;
        }

        if (pChannelMap != NULL) {
            ma_channel_map_init_standard(ma_standard_channel_map_vorbis, pChannelMap, channelMapCap, channels);
        }

        return MA_SUCCESS;
    }
    #else
    {
        /* libopus is disabled. Should never hit this since initialization would have failed. */
        assert(MA_FALSE);
        return MA_NOT_IMPLEMENTED;
    }
    #endif
}

MA_API ma_result ma_libopus_get_cursor_in_pcm_frames(ma_libopus* pOpus, ma_uint64* pCursor)
{
    if (pCursor == NULL) {
        return MA_INVALID_ARGS;
    }

    *pCursor = 0;   /* Safety. */

    if (pOpus == NULL) {
        return MA_INVALID_ARGS;
    }

    #if !defined(MA_NO_LIBOPUS)
    {
        *pCursor = pOpus->cursor;

        return MA_SUCCESS;
    }
    #else
    {
        /* libopus is disabled. Should never hit this since initialization would have failed. */
        assert(MA_FALSE);
        return MA_NOT_IMPLEMENTED;
    }
    #endif
}

MA_API ma_result ma_libopus_get_length_in_pcm_frames(ma_libopus* pOpus, ma_uint64* pLength)
{
    if (pLength == NULL) {
        return MA_INVALID_ARGS;
    }

    *pLength = 0;   /* Safety. */

    if (pOpus == NULL) {
        return MA_INVALID_ARGS;
    }

    #if !defined(MA_NO_LIBOPUS)
    {
        ogg_int64_t length = op_pcm_total((OggOpusFile*)pOpus->of, -1);
        if (length < 0) {
            return MA_ERROR;
        }

        *pLength = (ma_uint64)length;

        return MA_SUCCESS;
    }
    #else
    {
        /* libopus is disabled. Should never hit this since initialization would have failed. */
        assert(MA_FALSE);
        return MA_NOT_IMPLEMENTED;
    }
    #endif
}


/*
The code below defines the vtable that you'll plug into your `ma_decoder_config` object.
*/
#if !defined(MA_NO_LIBOPUS)
static ma_result ma_decoding_backend_init__libopus(void* pUserData, ma_read_proc onRead, ma_seek_proc onSeek, ma_tell_proc onTell, void* pReadSeekTellUserData, const ma_decoding_backend_config* pConfig, const ma_allocation_callbacks* pAllocationCallbacks, ma_data_source** ppBackend)
{
    ma_result result;
    ma_libopus* pOpus;

    (void)pUserData;

    pOpus = (ma_libopus*)ma_malloc(sizeof(*pOpus), pAllocationCallbacks);
    if (pOpus == NULL) {
        return MA_OUT_OF_MEMORY;
    }

    result = ma_libopus_init(onRead, onSeek, onTell, pReadSeekTellUserData, pConfig, pAllocationCallbacks, pOpus);
    if (result != MA_SUCCESS) {
        ma_free(pOpus, pAllocationCallbacks);
        return result;
    }

    *ppBackend = pOpus;

    return MA_SUCCESS;
}

static ma_result ma_decoding_backend_init_file__libopus(void* pUserData, const char* pFilePath, const ma_decoding_backend_config* pConfig, const ma_allocation_callbacks* pAllocationCallbacks, ma_data_source** ppBackend)
{
    ma_result result;
    ma_libopus* pOpus;

    (void)pUserData;

    pOpus = (ma_libopus*)ma_malloc(sizeof(*pOpus), pAllocationCallbacks);
    if (pOpus == NULL) {
        return MA_OUT_OF_MEMORY;
    }

    result = ma_libopus_init_file(pFilePath, pConfig, pAllocationCallbacks, pOpus);
    if (result != MA_SUCCESS) {
        ma_free(pOpus, pAllocationCallbacks);
        return result;
    }

    *ppBackend = pOpus;

    return MA_SUCCESS;
}

static void ma_decoding_backend_uninit__libopus(void* pUserData, ma_data_source* pBackend, const ma_allocation_callbacks* pAllocationCallbacks)
{
    ma_libopus* pOpus = (ma_libopus*)pBackend;

    (void)pUserData;

    ma_libopus_uninit(pOpus, pAllocationCallbacks);
    ma_free(pOpus, pAllocationCallbacks);
}

static ma_decoding_backend_vtable ma_gDecodingBackendVTable_libopus =
{
    ma_decoding_backend_init__libopus,
    ma_decoding_backend_init_file__libopus,
    NULL, /* onInitFileW() */
    NULL, /* onInitMemory() */
    ma_decoding_backend_uninit__libopus
};
ma_decoding_backend_vtable* ma_decoding_backend_libopus = &ma_gDecodingBackendVTable_libopus;
#else
ma_decoding_backend_vtable* ma_decoding_backend_libopus = NULL;
#endif

#endif  /* miniaudio_libopus_c */
