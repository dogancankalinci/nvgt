/*
Frames of a logical stream of a chained Ogg file whose channel count or sample rate differs from the first stream's. A chained file holds several logical streams one after another, as an Ogg radio's tracks are, and each has its own format, while MiniAudio reads every frame of a decoder in the format it reported when it opened: the first stream's. Such frames are held here and converted to that format as they are read.
*/
#ifndef miniaudio_ogg_link_h
#define miniaudio_ogg_link_h

#include "miniaudio.h"

typedef struct
{
    void* pFrames;                  /* Interleaved, in the decoder's sample format, with the logical stream's channels. */
    size_t capacityInBytes;
    ma_uint64 frameCount;           /* Not given yet, from frameOffset on. */
    ma_uint64 frameOffset;
    ma_uint32 channels;             /* The logical stream's. */
    ma_uint32 sampleRate;
    ma_data_converter converter;    /* From the logical stream's channels and sample rate to the decoder's, while hasConverter. */
    ma_bool32 hasConverter;
    ma_allocation_callbacks allocationCallbacks;
    ma_bool32 hasAllocationCallbacks;
} ma_ogg_link_frames;

#endif  /* miniaudio_ogg_link_h */

#if (defined(miniaudio_libvorbis_c) || defined(miniaudio_libopus_c)) && !defined(miniaudio_ogg_link_c)
#define miniaudio_ogg_link_c

#include <string.h> /* For memset(). */

static const ma_allocation_callbacks* ma_ogg_link_frames_allocation_callbacks(const ma_ogg_link_frames* pLink)
{
    return pLink->hasAllocationCallbacks ? &pLink->allocationCallbacks : NULL;
}

static void ma_ogg_link_frames_init(ma_ogg_link_frames* pLink, const ma_allocation_callbacks* pAllocationCallbacks)
{
    memset(pLink, 0, sizeof(*pLink));
    if (pAllocationCallbacks != NULL) {
        pLink->allocationCallbacks = *pAllocationCallbacks;
        pLink->hasAllocationCallbacks = MA_TRUE;
    }
}

static void ma_ogg_link_frames_uninit(ma_ogg_link_frames* pLink)
{
    if (pLink->hasConverter) {
        ma_data_converter_uninit(&pLink->converter, ma_ogg_link_frames_allocation_callbacks(pLink));
        pLink->hasConverter = MA_FALSE;
    }

    ma_free(pLink->pFrames, ma_ogg_link_frames_allocation_callbacks(pLink));
    pLink->pFrames = NULL;
    pLink->capacityInBytes = 0;
    pLink->frameCount = 0;
    pLink->frameOffset = 0;
}

/* Room for frames about to be decoded, once those held were all given. */
static void* ma_ogg_link_frames_reserve(ma_ogg_link_frames* pLink, size_t sizeInBytes)
{
    pLink->frameCount = 0;
    pLink->frameOffset = 0;

    if (pLink->capacityInBytes < sizeInBytes) {
        void* pFrames = ma_realloc(pLink->pFrames, sizeInBytes, ma_ogg_link_frames_allocation_callbacks(pLink));
        if (pFrames == NULL) {
            return NULL;
        }

        pLink->pFrames = pFrames;
        pLink->capacityInBytes = sizeInBytes;
    }

    return pLink->pFrames;
}

/* Holds the frames just decoded into the reserved room, of a logical stream of the given channels and sample rate. */
static void ma_ogg_link_frames_hold(ma_ogg_link_frames* pLink, ma_uint64 frameCount, ma_uint32 channels, ma_uint32 sampleRate)
{
    if (pLink->hasConverter && (pLink->channels != channels || pLink->sampleRate != sampleRate)) {
        ma_data_converter_uninit(&pLink->converter, ma_ogg_link_frames_allocation_callbacks(pLink));
        pLink->hasConverter = MA_FALSE;
    }

    pLink->frameCount = frameCount;
    pLink->frameOffset = 0;
    pLink->channels = channels;
    pLink->sampleRate = sampleRate;
}

/* Forgets the frames held, and what the converter kept of earlier ones, as a seek does. */
static void ma_ogg_link_frames_clear(ma_ogg_link_frames* pLink)
{
    pLink->frameCount = 0;
    pLink->frameOffset = 0;

    if (pLink->hasConverter) {
        ma_data_converter_reset(&pLink->converter);
    }
}

/* Gives up to frameCount of the frames held in the decoder's format, channels and sample rate. */
static ma_result ma_ogg_link_frames_take(ma_ogg_link_frames* pLink, ma_format format, ma_uint32 channels, ma_uint32 sampleRate, void* pFramesOut, ma_uint64 frameCount, ma_uint64* pFramesTaken)
{
    const void* pFramesIn = ma_offset_pcm_frames_const_ptr(pLink->pFrames, pLink->frameOffset, format, pLink->channels);
    ma_uint64 framesIn = pLink->frameCount;
    ma_uint64 framesOut = frameCount;

    *pFramesTaken = 0;

    if (pLink->channels == channels && pLink->sampleRate == sampleRate) {
        if (framesIn > framesOut) {
            framesIn = framesOut;
        }

        framesOut = framesIn;
        ma_copy_pcm_frames(pFramesOut, pFramesIn, framesOut, format, channels);
    } else {
        ma_result result;

        if (!pLink->hasConverter) {
            /* Ogg Vorbis and Ogg Opus share the Vorbis channel order. */
            ma_channel channelMapIn[MA_MAX_CHANNELS];
            ma_channel channelMapOut[MA_MAX_CHANNELS];
            ma_data_converter_config config = ma_data_converter_config_init(format, format, pLink->channels, channels, pLink->sampleRate, sampleRate);
            ma_channel_map_init_standard(ma_standard_channel_map_vorbis, channelMapIn, MA_MAX_CHANNELS, pLink->channels);
            ma_channel_map_init_standard(ma_standard_channel_map_vorbis, channelMapOut, MA_MAX_CHANNELS, channels);
            config.pChannelMapIn = channelMapIn;
            config.pChannelMapOut = channelMapOut;

            result = ma_data_converter_init(&config, ma_ogg_link_frames_allocation_callbacks(pLink), &pLink->converter);
            if (result != MA_SUCCESS) {
                return result;
            }

            pLink->hasConverter = MA_TRUE;
        }

        result = ma_data_converter_process_pcm_frames(&pLink->converter, pFramesIn, &framesIn, pFramesOut, &framesOut);
        if (result != MA_SUCCESS) {
            return result;
        }

        if (framesIn == 0 && framesOut == 0) {
            framesIn = pLink->frameCount;   /* Nothing more comes of them: dropped rather than offered again forever. */
        }
    }

    pLink->frameOffset += framesIn;
    pLink->frameCount  -= framesIn;
    *pFramesTaken = framesOut;

    return MA_SUCCESS;
}

#endif
