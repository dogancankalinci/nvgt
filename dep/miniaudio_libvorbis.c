#ifndef miniaudio_libvorbis_c
#define miniaudio_libvorbis_c

#include "miniaudio_libvorbis.h"

#if !defined(MA_NO_LIBVORBIS)
#ifndef OV_EXCLUDE_STATIC_CALLBACKS
#define OV_EXCLUDE_STATIC_CALLBACKS
#endif
#include <vorbis/vorbisfile.h>
#endif

#include <string.h> /* For memset(). */
#include <assert.h>

static ma_result ma_libvorbis_ds_read(ma_data_source* pDataSource, void* pFramesOut, ma_uint64 frameCount, ma_uint64* pFramesRead)
{
    return ma_libvorbis_read_pcm_frames((ma_libvorbis*)pDataSource, pFramesOut, frameCount, pFramesRead);
}

static ma_result ma_libvorbis_ds_seek(ma_data_source* pDataSource, ma_uint64 frameIndex)
{
    return ma_libvorbis_seek_to_pcm_frame((ma_libvorbis*)pDataSource, frameIndex);
}

static ma_result ma_libvorbis_ds_get_data_format(ma_data_source* pDataSource, ma_format* pFormat, ma_uint32* pChannels, ma_uint32* pSampleRate, ma_channel* pChannelMap, size_t channelMapCap)
{
    return ma_libvorbis_get_data_format((ma_libvorbis*)pDataSource, pFormat, pChannels, pSampleRate, pChannelMap, channelMapCap);
}

static ma_result ma_libvorbis_ds_get_cursor(ma_data_source* pDataSource, ma_uint64* pCursor)
{
    return ma_libvorbis_get_cursor_in_pcm_frames((ma_libvorbis*)pDataSource, pCursor);
}

static ma_result ma_libvorbis_ds_get_length(ma_data_source* pDataSource, ma_uint64* pLength)
{
    return ma_libvorbis_get_length_in_pcm_frames((ma_libvorbis*)pDataSource, pLength);
}

static ma_data_source_vtable g_ma_libvorbis_ds_vtable =
{
    ma_libvorbis_ds_read,
    ma_libvorbis_ds_seek,
    ma_libvorbis_ds_get_data_format,
    ma_libvorbis_ds_get_cursor,
    ma_libvorbis_ds_get_length,
    NULL,   /* onSetLooping */
    0       /* flags */
};


#if !defined(MA_NO_LIBVORBIS)
static size_t ma_libvorbis_vf_callback__read(void* pBufferOut, size_t size, size_t count, void* pUserData)
{
    ma_libvorbis* pVorbis = (ma_libvorbis*)pUserData;
    ma_result result;
    size_t bytesToRead;
    size_t bytesRead;

    /* For consistency with fread(). If `size` of `count` is 0, return 0 immediately without changing anything. */
    if (size == 0 || count == 0) {
        return 0;
    }

    bytesToRead = size * count;
    result = pVorbis->onRead(pVorbis->pReadSeekTellUserData, pBufferOut, bytesToRead, &bytesRead);
    if (result != MA_SUCCESS) {
        /* Not entirely sure what to return here. What if an error occurs, but some data was read and bytesRead is > 0? */
        return 0;
    }

    return bytesRead / size;
}

static int ma_libvorbis_vf_callback__seek(void* pUserData, ogg_int64_t offset, int whence)
{
    ma_libvorbis* pVorbis = (ma_libvorbis*)pUserData;
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
        if (pVorbis->onTell == NULL || pVorbis->onTell(pVorbis->pReadSeekTellUserData, &cursor) != MA_SUCCESS) {
            return -1;
        }
        seekable = pVorbis->onSeek(pVorbis->pReadSeekTellUserData, 0, ma_seek_origin_end) == MA_SUCCESS;
        if (pVorbis->onSeek(pVorbis->pReadSeekTellUserData, cursor, ma_seek_origin_start) != MA_SUCCESS) {
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

    result = pVorbis->onSeek(pVorbis->pReadSeekTellUserData, offset, origin);
    if (result != MA_SUCCESS) {
        return -1;
    }

    return 0;
}

static long ma_libvorbis_vf_callback__tell(void* pUserData)
{
    ma_libvorbis* pVorbis = (ma_libvorbis*)pUserData;
    ma_result result;
    ma_int64 cursor;
    
    if (pVorbis->onTell == NULL) {
        return -1; /* NVGT: as the seek callback and the Opus backend's tell check theirs; -1 is libvorbisfile's "can't tell". */
    }
    result = pVorbis->onTell(pVorbis->pReadSeekTellUserData, &cursor);
    if (result != MA_SUCCESS) {
        return -1;
    }

    return (long)cursor;
}
#endif

#if !defined(MA_NO_LIBVORBIS)
/*
libvorbisfile reports a hole, which it calls recoverable, where the stream is interrupted, at a damaged page, and in a stream that can't seek at
the start of each logical stream after the first: reading goes on past it, as the library means, rather than ending there. Only so many in a row
without a frame end the stream, as a guard against data with nothing to decode in it.
*/
#define MA_LIBVORBIS_MAX_HOLES 16

static void ma_libvorbis_opened(ma_libvorbis* pVorbis)
{
    OggVorbis_File* vf = (OggVorbis_File*)pVorbis->vf;
    vorbis_info* pInfo;

    /* libvorbisfile leaves a seekable file of several logical streams one after another (a chained Ogg file) at the start of its second link once it is opened, so the first link was never played until something sought to the start. Back to the start, where an opened source begins; a file of one link is there already. */
    if (ov_seekable(vf) && ov_pcm_tell(vf) != 0) {
        ov_pcm_seek(vf, 0);
    }

    /* The first logical stream's format, which MiniAudio reads every frame in. Without a stream that can seek, libvorbisfile knows only the current one, the first as it opens. One of more channels than MiniAudio holds leaves none, which fails the decoder's opening. */
    pInfo = ov_info(vf, 0);
    if (pInfo != NULL && ma_ogg_link_channels_usable(pInfo->channels) && pInfo->rate > 0) {
        pVorbis->channels = (ma_uint32)pInfo->channels;
        pVorbis->sampleRate = (ma_uint32)pInfo->rate;
    }
}

/* The library's frame index of one the decoder reads: libvorbisfile counts each logical stream at its own sample rate, while the decoder reads every one at the first's. */
static ogg_int64_t ma_libvorbis_library_frame(ma_libvorbis* pVorbis, ma_uint64 frameIndex)
{
    OggVorbis_File* vf = (OggVorbis_File*)pVorbis->vf;
    long links = ov_streams(vf);
    ogg_int64_t libraryStart = 0;
    ma_uint64 start = 0;
    long link;

    if (!ov_seekable(vf)) {
        return (ogg_int64_t)frameIndex;
    }

    for (link = 0; link < links; link += 1) {
        vorbis_info* pInfo = ov_info(vf, link);
        ogg_int64_t libraryFrames = ov_pcm_total(vf, link);
        ma_uint64 frames;

        if (pInfo == NULL || pInfo->rate <= 0 || libraryFrames < 0) {
            break;
        }

        frames = ((ma_uint32)pInfo->rate == pVorbis->sampleRate) ? (ma_uint64)libraryFrames : (ma_uint64)libraryFrames * pVorbis->sampleRate / (ma_uint64)pInfo->rate;
        if (frameIndex < start + frames || link == links - 1) {
            ma_uint64 within = frameIndex - start;
            return libraryStart + (ogg_int64_t)(((ma_uint32)pInfo->rate == pVorbis->sampleRate) ? within : within * (ma_uint64)pInfo->rate / pVorbis->sampleRate);
        }

        start += frames;
        libraryStart += libraryFrames;
    }

    return (ogg_int64_t)frameIndex;
}
#endif

static ma_result ma_libvorbis_init_internal(const ma_decoding_backend_config* pConfig, const ma_allocation_callbacks* pAllocationCallbacks, ma_libvorbis* pVorbis)
{
    if (pVorbis == NULL) {
        return MA_INVALID_ARGS;
    }

    memset(pVorbis, 0, sizeof(*pVorbis));
    pVorbis->format = ma_format_f32;    /* f32 by default. */
    ma_ogg_link_frames_init(&pVorbis->link, pAllocationCallbacks);

    if (pConfig != NULL && (pConfig->preferredFormat == ma_format_f32 || pConfig->preferredFormat == ma_format_s16)) {
        pVorbis->format = pConfig->preferredFormat;
    } else {
        /* Getting here means something other than f32 and s16 was specified. Just leave this unset to use the default format. */
    }

    #if !defined(MA_NO_LIBVORBIS)
    {
        ma_result result;
        ma_data_source_config dataSourceConfig;

        dataSourceConfig = ma_data_source_config_init();
        dataSourceConfig.vtable = &g_ma_libvorbis_ds_vtable;

        result = ma_data_source_init(&dataSourceConfig, &pVorbis->ds);
        if (result != MA_SUCCESS) {
            return result;  /* Failed to initialize the base data source. */
        }

        pVorbis->vf = (OggVorbis_File*)ma_malloc(sizeof(OggVorbis_File), pAllocationCallbacks);
        if (pVorbis->vf == NULL) {
            ma_data_source_uninit(&pVorbis->ds);
            return MA_OUT_OF_MEMORY;
        }

        return MA_SUCCESS;
    }
    #else
    {
        /* libvorbis is disabled. */
        (void)pAllocationCallbacks;
        return MA_NOT_IMPLEMENTED;
    }
    #endif
}

MA_API ma_result ma_libvorbis_init(ma_read_proc onRead, ma_seek_proc onSeek, ma_tell_proc onTell, void* pReadSeekTellUserData, const ma_decoding_backend_config* pConfig, const ma_allocation_callbacks* pAllocationCallbacks, ma_libvorbis* pVorbis)
{
    ma_result result;

    (void)pAllocationCallbacks; /* Can't seem to find a way to configure memory allocations in libvorbis. */

    if (onRead == NULL || onSeek == NULL) {
        return MA_INVALID_ARGS; /* onRead and onSeek are mandatory. */
    }
    
    result = ma_libvorbis_init_internal(pConfig, pAllocationCallbacks, pVorbis);
    if (result != MA_SUCCESS) {
        return result;
    }

    pVorbis->onRead = onRead;
    pVorbis->onSeek = onSeek;
    pVorbis->onTell = onTell;
    pVorbis->pReadSeekTellUserData = pReadSeekTellUserData;

    #if !defined(MA_NO_LIBVORBIS)
    {
        int libvorbisResult;
        ov_callbacks libvorbisCallbacks;

        /* We can now initialize the vorbis decoder. This must be done after we've set up the callbacks. */
        libvorbisCallbacks.read_func  = ma_libvorbis_vf_callback__read;
        libvorbisCallbacks.seek_func  = ma_libvorbis_vf_callback__seek;
        libvorbisCallbacks.close_func = NULL;
        libvorbisCallbacks.tell_func  = ma_libvorbis_vf_callback__tell;

        libvorbisResult = ov_open_callbacks(pVorbis, (OggVorbis_File*)pVorbis->vf, NULL, 0, libvorbisCallbacks);
        if (libvorbisResult < 0) {
            ma_data_source_uninit(&pVorbis->ds);
            ma_free(pVorbis->vf, pAllocationCallbacks);
            return MA_INVALID_FILE;
        }
        ma_libvorbis_opened(pVorbis);

        return MA_SUCCESS;
    }
    #else
    {
        /* libvorbis is disabled. */
        return MA_NOT_IMPLEMENTED;
    }
    #endif
}

MA_API ma_result ma_libvorbis_init_file(const char* pFilePath, const ma_decoding_backend_config* pConfig, const ma_allocation_callbacks* pAllocationCallbacks, ma_libvorbis* pVorbis)
{
    ma_result result;

    (void)pAllocationCallbacks; /* Can't seem to find a way to configure memory allocations in libvorbis. */

    result = ma_libvorbis_init_internal(pConfig, pAllocationCallbacks, pVorbis);
    if (result != MA_SUCCESS) {
        return result;
    }

    #if !defined(MA_NO_LIBVORBIS)
    {
        int libvorbisResult;

        libvorbisResult = ov_fopen(pFilePath, (OggVorbis_File*)pVorbis->vf);
        if (libvorbisResult < 0) {
            ma_data_source_uninit(&pVorbis->ds);
            ma_free(pVorbis->vf, pAllocationCallbacks);
            return MA_INVALID_FILE;
        }
        ma_libvorbis_opened(pVorbis);

        return MA_SUCCESS;
    }
    #else
    {
        /* libvorbis is disabled. */
        (void)pFilePath;
        return MA_NOT_IMPLEMENTED;
    }
    #endif
}

MA_API void ma_libvorbis_uninit(ma_libvorbis* pVorbis, const ma_allocation_callbacks* pAllocationCallbacks)
{
    if (pVorbis == NULL) {
        return;
    }

    (void)pAllocationCallbacks;

    #if !defined(MA_NO_LIBVORBIS)
    {
        ov_clear((OggVorbis_File*)pVorbis->vf);
    }
    #else
    {
        /* libvorbis is disabled. Should never hit this since initialization would have failed. */
        assert(MA_FALSE);
    }
    #endif

    ma_ogg_link_frames_uninit(&pVorbis->link);
    ma_data_source_uninit(&pVorbis->ds);
    ma_free(pVorbis->vf, pAllocationCallbacks);
}

MA_API ma_result ma_libvorbis_read_pcm_frames(ma_libvorbis* pVorbis, void* pFramesOut, ma_uint64 frameCount, ma_uint64* pFramesRead)
{
    if (pFramesRead != NULL) {
        *pFramesRead = 0;
    }

    if (frameCount == 0) {
        return MA_INVALID_ARGS;
    }

    if (pVorbis == NULL) {
        return MA_INVALID_ARGS;
    }

    #if !defined(MA_NO_LIBVORBIS)
    {
        ma_result result = MA_SUCCESS;  /* Must be initialized to MA_SUCCESS. */
        OggVorbis_File* vf = (OggVorbis_File*)pVorbis->vf;
        ma_uint64 totalFramesRead;
        ma_format format = pVorbis->format;
        ma_uint32 channels = pVorbis->channels;
        int holes = 0;

        if (channels == 0) {
            return MA_INVALID_OPERATION;
        }

        totalFramesRead = 0;
        while (totalFramesRead < frameCount) {
            long libvorbisResult;
            ma_uint64 framesToRead;
            ma_uint64 framesRemaining;
            void* pFramesOutHere;
            vorbis_info* pInfo;

            framesRemaining = (frameCount - totalFramesRead);
            pFramesOutHere = ma_offset_pcm_frames_ptr(pFramesOut, totalFramesRead, format, channels);

            if (pVorbis->link.frameCount > 0 || pVorbis->link.owes) {
                ma_uint64 framesTaken;

                result = ma_ogg_link_frames_take(&pVorbis->link, format, channels, pVorbis->sampleRate, pFramesOutHere, framesRemaining, &framesTaken);
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

            if (format == ma_format_f32) {
                float** ppFramesF32;

                libvorbisResult = ov_read_float(vf, &ppFramesF32, (int)framesToRead, NULL);
                if (libvorbisResult == OV_HOLE && ++holes <= MA_LIBVORBIS_MAX_HOLES) {
                    continue;
                }

                if (libvorbisResult < 0) {
                    result = MA_ERROR;  /* Error while decoding. */
                    break;
                }

                if (libvorbisResult == 0) {
                    result = MA_AT_END;
                    break;
                }

                /* Frames need to be interleaved, with the channels of the logical stream they are of. */
                pInfo = ov_info(vf, -1);
                if (pInfo == NULL) {
                    result = MA_ERROR;
                    break;
                }

                holes = 0;
                if ((ma_uint32)pInfo->channels == channels && (ma_uint32)pInfo->rate == pVorbis->sampleRate) {
                    ma_ogg_link_frames_forget_converter(&pVorbis->link); /* Given straight, never held: a later stream to convert starts afresh, not with the tail of one before this. */
                    ma_interleave_pcm_frames(format, channels, libvorbisResult, (const void**)ppFramesF32, pFramesOutHere);
                    totalFramesRead += libvorbisResult;
                } else if (ma_ogg_link_channels_usable(pInfo->channels) && pInfo->rate > 0) {
                    void* pHeld = ma_ogg_link_frames_reserve(&pVorbis->link, (size_t)libvorbisResult * pInfo->channels * sizeof(float));
                    if (pHeld == NULL) {
                        result = MA_OUT_OF_MEMORY;
                        break;
                    }

                    ma_interleave_pcm_frames(format, pInfo->channels, libvorbisResult, (const void**)ppFramesF32, pHeld);
                    ma_ogg_link_frames_hold(&pVorbis->link, libvorbisResult, ma_format_f32, pInfo->channels, pInfo->rate);
                } else {
                    result = ma_ogg_link_frames_hold_silence(&pVorbis->link, libvorbisResult, channels, pInfo->rate > 0 ? (ma_uint32)pInfo->rate : pVorbis->sampleRate);
                    if (result != MA_SUCCESS) {
                        break;
                    }
                }
            } else {
                /*
                ov_read() writes as many whole frames of the logical stream it reads as fit, in that stream's channels, which aren't known
                before it returns, so it writes to frames held, given as they are or converted. At least a frame of any stream fits.
                */
                size_t sizeInBytes;
                void* pHeld;

                pInfo = ov_info(vf, -1);
                sizeInBytes = (size_t)framesToRead * sizeof(ma_int16) * ((pInfo != NULL && (ma_uint32)pInfo->channels > channels) ? (ma_uint32)pInfo->channels : channels);
                if (sizeInBytes < sizeof(ma_int16) * 255) {
                    sizeInBytes = sizeof(ma_int16) * 255;
                }

                pHeld = ma_ogg_link_frames_reserve(&pVorbis->link, sizeInBytes * 2);   /* Room for them in float, if they are to be converted. */
                if (pHeld == NULL) {
                    result = MA_OUT_OF_MEMORY;
                    break;
                }

                libvorbisResult = ov_read(vf, (char*)pHeld, (int)sizeInBytes, 0, 2, 1, NULL);
                if (libvorbisResult == OV_HOLE && ++holes <= MA_LIBVORBIS_MAX_HOLES) {
                    continue;
                }

                if (libvorbisResult < 0) {
                    result = MA_ERROR;  /* Error while decoding. */
                    break;
                }

                if (libvorbisResult == 0) {
                    result = MA_AT_END;
                    break;
                }

                pInfo = ov_info(vf, -1);
                if (pInfo == NULL || pInfo->channels <= 0) {
                    result = MA_ERROR;
                    break;
                }

                holes = 0;
                if ((ma_uint32)pInfo->channels == channels && (ma_uint32)pInfo->rate == pVorbis->sampleRate) {
                    ma_ogg_link_frames_hold(&pVorbis->link, libvorbisResult / (sizeof(ma_int16) * pInfo->channels), format, pInfo->channels, pInfo->rate);
                } else if (ma_ogg_link_channels_usable(pInfo->channels) && pInfo->rate > 0) {
                    ma_ogg_link_frames_hold_s16_as_f32(&pVorbis->link, libvorbisResult / (sizeof(ma_int16) * pInfo->channels), pInfo->channels, pInfo->rate);
                } else {
                    result = ma_ogg_link_frames_hold_silence(&pVorbis->link, libvorbisResult / (sizeof(ma_int16) * pInfo->channels), channels, pInfo->rate > 0 ? (ma_uint32)pInfo->rate : pVorbis->sampleRate);
                    if (result != MA_SUCCESS) {
                        break;
                    }
                }
            }
        }

        pVorbis->cursor += totalFramesRead;

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
        /* libvorbis is disabled. Should never hit this since initialization would have failed. */
        assert(MA_FALSE);

        (void)pFramesOut;
        (void)frameCount;
        (void)pFramesRead;

        return MA_NOT_IMPLEMENTED;
    }
    #endif
}

MA_API ma_result ma_libvorbis_seek_to_pcm_frame(ma_libvorbis* pVorbis, ma_uint64 frameIndex)
{
    if (pVorbis == NULL) {
        return MA_INVALID_ARGS;
    }

    #if !defined(MA_NO_LIBVORBIS)
    {
        int libvorbisResult = ov_pcm_seek((OggVorbis_File*)pVorbis->vf, ma_libvorbis_library_frame(pVorbis, frameIndex));
        if (libvorbisResult != 0) {
            if (libvorbisResult == OV_ENOSEEK) {
                return MA_INVALID_OPERATION;    /* Not seekable. */
            } else if (libvorbisResult == OV_EINVAL) {
                return MA_INVALID_ARGS;
            } else {
                return MA_ERROR;
            }
        }

        ma_ogg_link_frames_clear(&pVorbis->link);
        pVorbis->cursor = frameIndex;

        return MA_SUCCESS;
    }
    #else
    {
        /* libvorbis is disabled. Should never hit this since initialization would have failed. */
        assert(MA_FALSE);

        (void)frameIndex;

        return MA_NOT_IMPLEMENTED;
    }
    #endif
}

MA_API ma_result ma_libvorbis_get_data_format(ma_libvorbis* pVorbis, ma_format* pFormat, ma_uint32* pChannels, ma_uint32* pSampleRate, ma_channel* pChannelMap, size_t channelMapCap)
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

    if (pVorbis == NULL) {
        return MA_INVALID_OPERATION;
    }

    if (pFormat != NULL) {
        *pFormat = pVorbis->format;
    }

    #if !defined(MA_NO_LIBVORBIS)
    {
        /* The first logical stream's, whichever is read: MiniAudio reads every frame in the format reported as the decoder opened. */
        if (pVorbis->channels == 0) {
            return MA_INVALID_OPERATION;
        }

        if (pChannels != NULL) {
            *pChannels = pVorbis->channels;
        }

        if (pSampleRate != NULL) {
            *pSampleRate = pVorbis->sampleRate;
        }

        if (pChannelMap != NULL) {
            ma_channel_map_init_standard(ma_standard_channel_map_vorbis, pChannelMap, channelMapCap, pVorbis->channels);
        }

        return MA_SUCCESS;
    }
    #else
    {
        /* libvorbis is disabled. Should never hit this since initialization would have failed. */
        assert(MA_FALSE);
        return MA_NOT_IMPLEMENTED;
    }
    #endif
}

MA_API ma_result ma_libvorbis_get_cursor_in_pcm_frames(ma_libvorbis* pVorbis, ma_uint64* pCursor)
{
    if (pCursor == NULL) {
        return MA_INVALID_ARGS;
    }

    *pCursor = 0;   /* Safety. */

    if (pVorbis == NULL) {
        return MA_INVALID_ARGS;
    }

    #if !defined(MA_NO_LIBVORBIS)
    {
        *pCursor = pVorbis->cursor;

        return MA_SUCCESS;
    }
    #else
    {
        /* libvorbis is disabled. Should never hit this since initialization would have failed. */
        assert(MA_FALSE);
        return MA_NOT_IMPLEMENTED;
    }
    #endif
}

MA_API ma_result ma_libvorbis_get_length_in_pcm_frames(ma_libvorbis* pVorbis, ma_uint64* pLength)
{
    if (pLength == NULL) {
        return MA_INVALID_ARGS;
    }

    *pLength = 0;   /* Safety. */

    if (pVorbis == NULL) {
        return MA_INVALID_ARGS;
    }

    #if !defined(MA_NO_LIBVORBIS)
    {
        OggVorbis_File* vf = (OggVorbis_File*)pVorbis->vf;
        long links = ov_streams(vf);
        long link;

        if (links == 1) {
            ogg_int64_t length = ov_pcm_total(vf, 0);
            if(length != OV_EINVAL) {
                *pLength = (ma_uint64)length;
            } else {
                /* Unseekable. */
            }
        } else if (ov_seekable(vf)) {
            /*
            Concatenated streams, each counted at the first's sample rate as the decoder reads it, as seeks map them (see
            ma_libvorbis_library_frame()): reported as 0, unknown, a stream read from a file could be neither sought nor
            rewound. One converted to another rate may give a frame or two more or fewer than counted here.
            */
            ma_uint64 length = 0;
            for (link = 0; link < links; link += 1) {
                vorbis_info* pInfo = ov_info(vf, link);
                ogg_int64_t libraryFrames = ov_pcm_total(vf, link);
                if (pInfo == NULL || pInfo->rate <= 0 || libraryFrames < 0) {
                    return MA_SUCCESS;  /* Unknown, as before. */
                }

                length += ((ma_uint32)pInfo->rate == pVorbis->sampleRate) ? (ma_uint64)libraryFrames : (ma_uint64)libraryFrames * pVorbis->sampleRate / (ma_uint64)pInfo->rate;
            }

            *pLength = length;
        } else {
            /* Concatenated and unseekable: unknown. */
        }

        return MA_SUCCESS;
    }
    #else
    {
        /* libvorbis is disabled. Should never hit this since initialization would have failed. */
        assert(MA_FALSE);
        return MA_NOT_IMPLEMENTED;
    }
    #endif
}


/*
The code below defines the vtable that you'll plug into your `ma_decoder_config` object.
*/
#if !defined(MA_NO_LIBVORBIS)
static ma_result ma_decoding_backend_init__libvorbis(void* pUserData, ma_read_proc onRead, ma_seek_proc onSeek, ma_tell_proc onTell, void* pReadSeekTellUserData, const ma_decoding_backend_config* pConfig, const ma_allocation_callbacks* pAllocationCallbacks, ma_data_source** ppBackend)
{
    ma_result result;
    ma_libvorbis* pVorbis;

    (void)pUserData;

    pVorbis = (ma_libvorbis*)ma_malloc(sizeof(*pVorbis), pAllocationCallbacks);
    if (pVorbis == NULL) {
        return MA_OUT_OF_MEMORY;
    }

    result = ma_libvorbis_init(onRead, onSeek, onTell, pReadSeekTellUserData, pConfig, pAllocationCallbacks, pVorbis);
    if (result != MA_SUCCESS) {
        ma_free(pVorbis, pAllocationCallbacks);
        return result;
    }

    *ppBackend = pVorbis;

    return MA_SUCCESS;
}

static ma_result ma_decoding_backend_init_file__libvorbis(void* pUserData, const char* pFilePath, const ma_decoding_backend_config* pConfig, const ma_allocation_callbacks* pAllocationCallbacks, ma_data_source** ppBackend)
{
    ma_result result;
    ma_libvorbis* pVorbis;

    (void)pUserData;

    pVorbis = (ma_libvorbis*)ma_malloc(sizeof(*pVorbis), pAllocationCallbacks);
    if (pVorbis == NULL) {
        return MA_OUT_OF_MEMORY;
    }

    result = ma_libvorbis_init_file(pFilePath, pConfig, pAllocationCallbacks, pVorbis);
    if (result != MA_SUCCESS) {
        ma_free(pVorbis, pAllocationCallbacks);
        return result;
    }

    *ppBackend = pVorbis;

    return MA_SUCCESS;
}

static void ma_decoding_backend_uninit__libvorbis(void* pUserData, ma_data_source* pBackend, const ma_allocation_callbacks* pAllocationCallbacks)
{
    ma_libvorbis* pVorbis = (ma_libvorbis*)pBackend;

    (void)pUserData;

    ma_libvorbis_uninit(pVorbis, pAllocationCallbacks);
    ma_free(pVorbis, pAllocationCallbacks);
}


static ma_decoding_backend_vtable ma_gDecodingBackendVTable_libvorbis =
{
    ma_decoding_backend_init__libvorbis,
    ma_decoding_backend_init_file__libvorbis,
    NULL, /* onInitFileW() */
    NULL, /* onInitMemory() */
    ma_decoding_backend_uninit__libvorbis
};
ma_decoding_backend_vtable* ma_decoding_backend_libvorbis = &ma_gDecodingBackendVTable_libvorbis;
#else
ma_decoding_backend_vtable* ma_decoding_backend_libvorbis = NULL;
#endif

#endif /* miniaudio_libvorbis_c */
