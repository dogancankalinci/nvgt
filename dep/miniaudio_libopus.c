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

    /* The end of the data is 0 bytes for opusfile, not an error: a stream that can't seek, whose end opusfile doesn't know, reads to it, and taken as an error it never ended, a sound playing it staying on silence for good. */
    if (result != MA_SUCCESS && result != MA_AT_END) {
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
row without a frame fail the read with MA_ERROR, as a guard against data with nothing to decode in it, which a sound playing it takes for its end
(see held_decoder_read() in src/sound.cpp).
*/
#define MA_LIBOPUS_MAX_HOLES 16
#define MA_LIBOPUS_MAX_HOLE_FRAMES (48000 * 60) /* The most silence a hole is given; a jump past it is taken as pages placed wrong rather than lost. */

static void ma_libopus_opened(ma_libopus* pOpus)
{
    /* The first logical stream's channels, which MiniAudio reads every frame in. Without a stream that can seek, opusfile knows only the current one, the first as it opens. One of more channels than MiniAudio holds leaves none, which fails the decoder's opening. */
    int channels = op_channel_count((OggOpusFile*)pOpus->of, 0);
    if (ma_ogg_link_channels_usable(channels)) {
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

    /* NVGT: checked before the data source is initialized, and that uninitialized again when the open fails below, as the Vorbis backend does. */
    if (onRead == NULL || onSeek == NULL) {
        return MA_INVALID_ARGS; /* onRead and onSeek are mandatory. */
    }

    result = ma_libopus_init_internal(pConfig, pAllocationCallbacks, pOpus);
    if (result != MA_SUCCESS) {
        return result;
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
            ma_data_source_uninit(&pOpus->ds);
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
            ma_data_source_uninit(&pOpus->ds); /* NVGT: as ma_libopus_init() and the Vorbis backend do. */
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

    /* NVGT: a NULL output skips frames, as MiniAudio's data sources allow, read into scratch memory a chunk at a time; the reads below write to it. */
    if (pFramesOut == NULL) {
        ma_uint8 scratch[16384];
        ma_format format;
        ma_uint32 channels;
        ma_uint64 skipped = 0;
        ma_uint64 chunk;
        ma_result result = ma_libopus_get_data_format(pOpus, &format, &channels, NULL, NULL, 0);
        if (result != MA_SUCCESS) {
            return result;
        }
        chunk = ma_get_bytes_per_frame(format, channels) ? sizeof(scratch) / ma_get_bytes_per_frame(format, channels) : 0;
        if (chunk == 0) {
            return MA_INVALID_OPERATION;
        }
        while (skipped < frameCount) {
            ma_uint64 got = 0;
            result = ma_libopus_read_pcm_frames(pOpus, scratch, frameCount - skipped < chunk ? frameCount - skipped : chunk, &got);
            skipped += got;
            if (result != MA_SUCCESS || got == 0) {
                break;
            }
        }
        if (pFramesRead != NULL) {
            *pFramesRead = skipped;
        }
        return result;
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
            ogg_int64_t libraryPlace;

            framesRemaining = (frameCount - totalFramesRead);

            if (pOpus->silenceOwed > 0) {
                ma_uint64 framesSilent = (pOpus->silenceOwed < framesRemaining) ? pOpus->silenceOwed : framesRemaining;
                if (pFramesOut != NULL) {
                    ma_silence_pcm_frames(ma_offset_pcm_frames_ptr(pFramesOut, totalFramesRead, format, channels), framesSilent, format, channels);
                }

                pOpus->silenceOwed -= framesSilent;
                totalFramesRead += framesSilent;
                continue;
            }

            if (pOpus->link.frameCount > 0 || pOpus->link.owes) {
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
            libraryPlace = op_pcm_tell(of);
            if (format == ma_format_f32) {
                libopusResult = op_read_float(of, (float*     )pHeld, (int)samplesToRead, &link);
            } else {
                libopusResult = op_read      (of, (opus_int16*)pHeld, (int)samplesToRead, &link);
            }

            if (libopusResult == OP_HOLE && ++holes <= MA_LIBOPUS_MAX_HOLES) {
                if (!pOpus->inHole && libraryPlace >= 0) {
                    pOpus->inHole = MA_TRUE;
                    pOpus->holeFrom = libraryPlace;
                }

                continue;
            }

            /*
            Past a hole, as a page lost from a damaged file or a gap in a stream, libopusfile goes on from the next page, whose place
            is later by what was lost: given as silence, ahead of what follows, so that the cursor keeps to the places seeks and the
            length are counted in, as a truncated file's missing part plays.
            */
            if (libopusResult > 0 && pOpus->inHole) {
                ogg_int64_t libraryAfter = op_pcm_tell(of);
                pOpus->inHole = MA_FALSE;
                if (libraryAfter >= 0 && libraryAfter - libopusResult > pOpus->holeFrom && libraryAfter - libopusResult - pOpus->holeFrom <= MA_LIBOPUS_MAX_HOLE_FRAMES) {
                    pOpus->silenceOwed = (ma_uint64)(libraryAfter - libopusResult - pOpus->holeFrom);
                }
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
            if (!ma_ogg_link_channels_usable(linkChannels)) {
                result = ma_ogg_link_frames_hold_silence(&pOpus->link, libopusResult, channels, 48000);
                if (result != MA_SUCCESS) {
                    break;
                }
            } else if ((ma_uint32)linkChannels == channels || format == ma_format_f32) {
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

#if !defined(MA_NO_LIBOPUS)
/*
Reads on to a place in libopusfile's count, dropping what it reads, by what it gives whatever the stream's channels, and past holes
as a read goes past them. The place it got to: short of the one asked at the stream's end, or on an error, which pError is given (0
at the end), or past it where a hole skipped over it; -1 where it can't tell.
*/
/*
A read can give more than asked: a whole frame of any logical stream fits what is asked for, and a read that crosses into a stream of
fewer channels gives as many more frames as the room holds. Those past the place asked for are given back in pKept (room for 255 * 8
floats), with their frame count and channels, for the caller to hold, rather than dropped, which played them as silence.
*/
static ogg_int64_t ma_libopus_read_on(OggOpusFile* of, ogg_int64_t target, int* pError, float* pKept, int* pKeptFrames, int* pKeptChannels)
{
    float dropped[255 * 8];
    int holes = 0;
    ogg_int64_t place = op_pcm_tell(of);

    if (pError != NULL) {
        *pError = 0;
    }

    if (pKeptFrames != NULL) {
        *pKeptFrames = 0;
    }

    while (place >= 0 && place < target) {
        int channels = op_channel_count(of, -1);
        int room = (int)(sizeof(dropped) / sizeof(dropped[0])) / channels;
        int samples = ((target - place < room) ? (int)(target - place) : room) * channels;
        int link = -1;
        int framesRead;
        ogg_int64_t after;

        if (samples < 255) {
            samples = 255; /* At least a frame of a logical stream of any channels that follows. */
        }

        framesRead = op_read_float(of, dropped, samples, &link);
        if (framesRead == OP_HOLE && ++holes <= MA_LIBOPUS_MAX_HOLES) {
            place = op_pcm_tell(of);
            continue;
        }

        if (framesRead <= 0) {
            if (pError != NULL) {
                *pError = framesRead;
            }

            break;
        }

        holes = 0;
        after = op_pcm_tell(of);
        if (after > target && pKept != NULL) {
            ogg_int64_t start = after - framesRead;
            ogg_int64_t keepFrom = (start > target) ? start : target;
            int linkChannels = op_channel_count(of, link);
            if (linkChannels > 0 && after - keepFrom <= framesRead) {
                *pKeptFrames = (int)(after - keepFrom);
                *pKeptChannels = linkChannels;
                memcpy(pKept, dropped + (size_t)(keepFrom - start) * linkChannels, (size_t)*pKeptFrames * linkChannels * sizeof(float));
            }

            return keepFrom;
        }

        place = after;
    }

    return place;
}
#endif

#if !defined(MA_NO_LIBOPUS)
/* Holds what a read on gave past the frame sought (see ma_libopus_read_on()), in place of what was held before the seek. */
static ma_result ma_libopus_hold_kept(ma_libopus* pOpus, const float* pKept, int frameCount, int channels)
{
    void* pHeld;

    ma_ogg_link_frames_clear(&pOpus->link);
    if (frameCount <= 0) {
        return MA_SUCCESS;
    }

    if (!ma_ogg_link_channels_usable(channels)) {
        return ma_ogg_link_frames_hold_silence(&pOpus->link, (ma_uint64)frameCount, pOpus->channels, 48000);
    }

    pHeld = ma_ogg_link_frames_reserve(&pOpus->link, (size_t)frameCount * channels * sizeof(float));
    if (pHeld == NULL) {
        return MA_OUT_OF_MEMORY;
    }

    memcpy(pHeld, pKept, (size_t)frameCount * channels * sizeof(float));
    ma_ogg_link_frames_hold(&pOpus->link, (ma_uint64)frameCount, ma_format_f32, (ma_uint32)channels, 48000);
    return MA_SUCCESS;
}

/* A seek to a frame within a hole, read on to where the stream goes on: silence from the frame to there, as a read gives a hole. */
static ma_result ma_libopus_seek_into_hole(ma_libopus* pOpus, ma_uint64 frameIndex, ogg_int64_t resumesAt)
{
    pOpus->inHole = MA_FALSE;
    pOpus->silenceOwed = (ma_uint64)(resumesAt - (ogg_int64_t)frameIndex);
    pOpus->cursor = frameIndex;
    return MA_SUCCESS;
}

/*
Lands a seek whose read on reached the frame, or a hole past it, with what it read past the frame held. Without room to hold that, the
link was let go of and libopusfile is already past the frame: sought to it then, rather than left reading on from past the frame with
the cursor and the frames held from before.
*/
static ma_result ma_libopus_land(ma_libopus* pOpus, ma_uint64 frameIndex, ogg_int64_t reached, const float* pKept, int keptFrames, int keptChannels)
{
    ma_result result = ma_libopus_hold_kept(pOpus, pKept, keptFrames, keptChannels);
    if (result == MA_SUCCESS) {
        return ma_libopus_seek_into_hole(pOpus, frameIndex, reached);
    }

    ma_ogg_link_frames_clear(&pOpus->link);
    if (op_pcm_seek((OggOpusFile*)pOpus->of, (ogg_int64_t)frameIndex) != 0) {
        /*
        Neither: the frames held before are gone with the link, so the cursor no longer reaches where libopusfile is, past the frame.
        The place it tells is where reads go on from, which a caller finding the cursor moved by the failed seek puts back.
        */
        ogg_int64_t now = op_pcm_tell((OggOpusFile*)pOpus->of);
        pOpus->inHole = MA_FALSE;
        pOpus->silenceOwed = 0;
        if (now >= 0) {
            pOpus->cursor = (ma_uint64)now;
        }
        return result;
    }

    pOpus->inHole = MA_FALSE;
    pOpus->silenceOwed = 0;
    pOpus->cursor = frameIndex;
    return MA_SUCCESS;
}
#endif

MA_API ma_result ma_libopus_seek_to_pcm_frame(ma_libopus* pOpus, ma_uint64 frameIndex)
{
    if (pOpus == NULL) {
        return MA_INVALID_ARGS;
    }

    /*
    Within the silence still to come for a hole, or the frames already held, which a read past a logical stream's frame or of fewer
    channels than the decoder's leaves: only less of them, exact, where libopusfile's own seek starts afresh behind them and its
    pre-roll gave other frames. Every logical stream is at 48 kHz, so the frames held are given one for one.
    */
    if (frameIndex >= pOpus->cursor) {
        ma_uint64 skip = frameIndex - pOpus->cursor;
        if (skip < pOpus->silenceOwed || (skip < pOpus->silenceOwed + pOpus->link.frameCount && !pOpus->link.owes)) {
            ma_uint64 skipSilence = (skip < pOpus->silenceOwed) ? skip : pOpus->silenceOwed;
            pOpus->silenceOwed -= skipSilence;
            pOpus->link.frameOffset += skip - skipSilence;
            pOpus->link.frameCount -= skip - skipSilence;
            pOpus->cursor = frameIndex;
            return MA_SUCCESS;
        }
    }

    #if !defined(MA_NO_LIBOPUS)
    {
        /*
        libopusfile refuses a seek to its total, which every other decoder takes, reading nothing from there, as seeking a
        known length allows: the last frame is sought and read past instead. A multistream frame is at most 255 channels.
        */
        ogg_int64_t total = op_pcm_total((OggOpusFile*)pOpus->of, -1);
        ogg_int64_t at = op_pcm_tell((OggOpusFile*)pOpus->of);
        int libopusResult;

        /*
        A stream that can't seek: libopusfile counts its places from each logical stream's start there, while the cursor counts from
        the whole stream's, so that a place it tells can't be set against a frame sought, and a frame far behind, in an earlier
        logical stream, was taken for one a short way ahead. A short way forward is read on through the reads themselves, which give
        holes and the frames held as they would; anything else, behind included, is refused. At the stream's end, the cursor says
        where it is.
        */
        if (!op_seekable((OggOpusFile*)pOpus->of)) {
            float dropped[255 * 8];
            ma_uint64 chunk = (pOpus->channels > 0) ? (sizeof(dropped) / sizeof(dropped[0])) / pOpus->channels : 0;

            if (frameIndex < pOpus->cursor || frameIndex - pOpus->cursor > 5760 || chunk == 0) {
                return MA_INVALID_OPERATION;
            }

            while (pOpus->cursor < frameIndex) {
                ma_uint64 framesRead = 0;
                ma_libopus_read_pcm_frames(pOpus, dropped, ((frameIndex - pOpus->cursor) < chunk) ? (frameIndex - pOpus->cursor) : chunk, &framesRead);
                if (framesRead == 0) {
                    break;
                }
            }

            return (pOpus->cursor == frameIndex) ? MA_SUCCESS : MA_INVALID_OPERATION;
        }

        /*
        libopusfile's seek a short way forward, under 90 ms, keeps what's left of the packet it decoded, which a read that took
        less than a packet leaves, so that those frames played as what was sought to. Read on rather than seek, to 120 ms, its
        longest packet, which needs no pre-roll either.
        */
        if (at >= 0 && (ogg_int64_t)frameIndex >= at && (ogg_int64_t)frameIndex - at <= 5760) { /* Its place too, the frames held all passed: read on by nothing. */
            int readError;
            float kept[255 * 8];
            int keptFrames;
            int keptChannels = 0;
            ogg_int64_t reached = ma_libopus_read_on((OggOpusFile*)pOpus->of, (ogg_int64_t)frameIndex, &readError, kept, &keptFrames, &keptChannels);
            if (reached == (ogg_int64_t)frameIndex || (reached > (ogg_int64_t)frameIndex && reached - (ogg_int64_t)frameIndex <= MA_LIBOPUS_MAX_HOLE_FRAMES)) {
                return ma_libopus_land(pOpus, frameIndex, reached, kept, keptFrames, keptChannels); /* At the frame, or within a hole: silence to where it goes on. */
            } else {
                /*
                The stream ended first, or a hole skipped over the frame: libopusfile's own seek, which finds it by the pages' places,
                or else back to where it was, the cursor and the frames held still saying so.
                */
                libopusResult = op_pcm_seek((OggOpusFile*)pOpus->of, (ogg_int64_t)frameIndex);
                if (libopusResult != 0) {
                    op_pcm_seek((OggOpusFile*)pOpus->of, at);
                    return (readError < 0 && readError != OP_HOLE) ? MA_ERROR : MA_INVALID_ARGS; /* A read that failed, or past what can be read. */
                }
            }
        } else if (total > 0 && frameIndex == (ma_uint64)total) {
            libopusResult = op_pcm_seek((OggOpusFile*)pOpus->of, total - 1);
            if (libopusResult == 0 && ma_libopus_read_on((OggOpusFile*)pOpus->of, total, NULL, NULL, NULL, NULL) < total) {
                op_pcm_seek((OggOpusFile*)pOpus->of, at >= 0 ? at : 0); /* Back where it was, as the cursor and the frames held still say. */
                libopusResult = OP_EREAD;
            }
        } else {
            libopusResult = op_pcm_seek((OggOpusFile*)pOpus->of, (ogg_int64_t)frameIndex);

            /*
            A frame within a hole, where no page holds it, which libopusfile can't seek to: sought from a frame before the hole, at
            most a minute or so before it, and read on through it, the rest of the hole given as silence, as a read gives it.
            */
            if (libopusResult != 0 && libopusResult != OP_ENOSEEK && libopusResult != OP_EINVAL) {
                ogg_int64_t back;
                for (back = 48000; back <= (ogg_int64_t)MA_LIBOPUS_MAX_HOLE_FRAMES * 2; back *= 2) {
                    ogg_int64_t anchor = ((ogg_int64_t)frameIndex > back) ? (ogg_int64_t)frameIndex - back : 0;
                    if (op_pcm_seek((OggOpusFile*)pOpus->of, anchor) == 0) {
                        int readError;
                        float kept[255 * 8];
                        int keptFrames;
                        int keptChannels = 0;
                        ogg_int64_t reached = ma_libopus_read_on((OggOpusFile*)pOpus->of, (ogg_int64_t)frameIndex, &readError, kept, &keptFrames, &keptChannels);
                        if (reached == (ogg_int64_t)frameIndex || (reached > (ogg_int64_t)frameIndex && reached - (ogg_int64_t)frameIndex <= MA_LIBOPUS_MAX_HOLE_FRAMES)) {
                            return ma_libopus_land(pOpus, frameIndex, reached, kept, keptFrames, keptChannels);
                        } else if (reached >= 0 && reached < (ogg_int64_t)frameIndex) {
                            libopusResult = (readError < 0 && readError != OP_HOLE) ? readError : OP_EINVAL; /* A read that failed keeps its error; the stream's end before it, in a hole at its end, is past what can be read, as Vorbis refuses it. */
                        }

                        break;
                    }

                    if (anchor == 0) {
                        break;
                    }
                }

                if (libopusResult != 0 && at >= 0) {
                    op_pcm_seek((OggOpusFile*)pOpus->of, at); /* Back where it was, as the cursor and the frames held still say. */
                }
            }
        }

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
        pOpus->inHole = MA_FALSE;
        pOpus->silenceOwed = 0;
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
            ma_ogg_channel_map(pChannelMap, channelMapCap, channels);
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
            /* A stream that can't seek has no total opusfile can give: unknown, 0, as libvorbis gives, rather than an error, which left a decoder's length asked again on each read and failed a resource manager's whole load. */
            return op_seekable((OggOpusFile*)pOpus->of) ? MA_ERROR : MA_SUCCESS;
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
