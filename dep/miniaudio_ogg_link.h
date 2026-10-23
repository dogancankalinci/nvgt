/*
Frames of a logical stream of a chained Ogg file whose channel count or sample rate differs from the first stream's. A chained file holds several logical streams one after another, as an Ogg radio's tracks are, and each has its own format, while MiniAudio reads every frame of a decoder in the format it reported when it opened: the first stream's. Such frames are held here and converted to that format as they are read.
*/
#ifndef miniaudio_ogg_link_h
#define miniaudio_ogg_link_h

#include "miniaudio.h"

typedef struct
{
    void* pFrames;                  /* Interleaved, with the logical stream's channels: in the decoder's sample format for a stream of its format, in float for one to convert. */
    size_t capacityInBytes;
    ma_uint64 frameCount;           /* Not given yet, from frameOffset on. */
    ma_uint64 frameOffset;
    ma_format format;               /* Of the frames held. */
    ma_uint32 channels;             /* The logical stream's. */
    ma_uint32 sampleRate;
    ma_data_converter converter;    /* From the logical stream's channels and sample rate to the decoder's, float to float, while hasConverter. */
    ma_bool32 hasConverter;
    void* pScratch;                 /* The converter's float output, for a decoder whose format isn't float. */
    size_t scratchCapacityInBytes;
    ma_allocation_callbacks allocationCallbacks;
    ma_bool32 hasAllocationCallbacks;
} ma_ogg_link_frames;

#endif  /* miniaudio_ogg_link_h */

#if (defined(miniaudio_libvorbis_c) || defined(miniaudio_libopus_c)) && !defined(miniaudio_ogg_link_c)
#define miniaudio_ogg_link_c

#include <string.h> /* For memset(). */

/* Ogg Vorbis and Opus allow 255 channels, one more than MiniAudio's channel maps and converters hold. */
static ma_bool32 ma_ogg_link_channels_usable(int channels)
{
    return channels >= 1 && channels <= MA_MAX_CHANNELS;
}

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

    ma_free(pLink->pScratch, ma_ogg_link_frames_allocation_callbacks(pLink));
    pLink->pScratch = NULL;
    pLink->scratchCapacityInBytes = 0;
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

/* Holds the frames just decoded into the reserved room, in the given format, of a logical stream of the given channels and sample rate. */
static void ma_ogg_link_frames_hold(ma_ogg_link_frames* pLink, ma_uint64 frameCount, ma_format format, ma_uint32 channels, ma_uint32 sampleRate)
{
    if (pLink->hasConverter && (pLink->channels != channels || pLink->sampleRate != sampleRate)) {
        ma_data_converter_uninit(&pLink->converter, ma_ogg_link_frames_allocation_callbacks(pLink));
        pLink->hasConverter = MA_FALSE;
    }

    pLink->frameCount = frameCount;
    pLink->frameOffset = 0;
    pLink->format = format;
    pLink->channels = channels;
    pLink->sampleRate = sampleRate;
}

/*
Holds 16-bit frames just decoded into the reserved room as float, converted in place, from the last sample back so that none is overwritten before
it is read; the room reserved must take them in float. MiniAudio's converter mixes channels in its output format when that is s16, and its mixing
down to one channel there divides a signed sum by an unsigned count, which spoils every negative sample of 3, 5, 6 or 7 channels: converting in
float avoids that.
*/
static void ma_ogg_link_frames_hold_s16_as_f32(ma_ogg_link_frames* pLink, ma_uint64 frameCount, ma_uint32 channels, ma_uint32 sampleRate)
{
    const ma_int16* pSamplesIn = (const ma_int16*)pLink->pFrames;
    float* pSamplesOut = (float*)pLink->pFrames;
    ma_uint64 sampleCount = frameCount * channels;

    while (sampleCount > 0) {
        ma_int16 sample;
        sampleCount -= 1;
        sample = pSamplesIn[sampleCount];
        pSamplesOut[sampleCount] = sample * 0.000030517578125f;
    }

    ma_ogg_link_frames_hold(pLink, frameCount, ma_format_f32, channels, sampleRate);
}

/*
Holds silence in the given channels for frames of a logical stream of more channels than MiniAudio holds, which can't be converted: played as
silence for its length rather than passed over, which decoded the whole stream in one read and stalled whatever read the decoder, as the
audio thread, for its length.
*/
static ma_result ma_ogg_link_frames_hold_silence(ma_ogg_link_frames* pLink, ma_uint64 frameCount, ma_uint32 channels, ma_uint32 sampleRate)
{
    void* pFrames = ma_ogg_link_frames_reserve(pLink, (size_t)frameCount * channels * sizeof(float));
    if (pFrames == NULL) {
        return MA_OUT_OF_MEMORY;
    }

    memset(pFrames, 0, (size_t)frameCount * channels * sizeof(float));
    ma_ogg_link_frames_hold(pLink, frameCount, ma_format_f32, channels, sampleRate);
    return MA_SUCCESS;
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
    const void* pFramesIn = ma_offset_pcm_frames_const_ptr(pLink->pFrames, pLink->frameOffset, pLink->format, pLink->channels);
    ma_uint64 framesIn = pLink->frameCount;
    ma_uint64 framesOut = frameCount;

    *pFramesTaken = 0;

    if (pLink->channels == channels && pLink->sampleRate == sampleRate && pLink->format == format) {
        if (framesIn > framesOut) {
            framesIn = framesOut;
        }

        framesOut = framesIn;
        ma_copy_pcm_frames(pFramesOut, pFramesIn, framesOut, format, channels);
    } else {
        ma_result result;
        void* pConverted = pFramesOut;

        if (!pLink->hasConverter) {
            /* Ogg Vorbis and Ogg Opus share the Vorbis channel order. */
            ma_channel channelMapIn[MA_MAX_CHANNELS];
            ma_channel channelMapOut[MA_MAX_CHANNELS];
            ma_data_converter_config config = ma_data_converter_config_init(ma_format_f32, ma_format_f32, pLink->channels, channels, pLink->sampleRate, sampleRate);
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

        if (format != ma_format_f32) {
            size_t sizeInBytes;

            /* Converted in float into the scratch room, a part at a time, then to the decoder's format. */
            if (framesOut > 1024) {
                framesOut = 1024;
            }

            sizeInBytes = (size_t)framesOut * channels * sizeof(float);
            if (pLink->scratchCapacityInBytes < sizeInBytes) {
                void* pScratch = ma_realloc(pLink->pScratch, sizeInBytes, ma_ogg_link_frames_allocation_callbacks(pLink));
                if (pScratch == NULL) {
                    return MA_OUT_OF_MEMORY;
                }

                pLink->pScratch = pScratch;
                pLink->scratchCapacityInBytes = sizeInBytes;
            }

            pConverted = pLink->pScratch;
        }

        result = ma_data_converter_process_pcm_frames(&pLink->converter, pFramesIn, &framesIn, pConverted, &framesOut);
        if (result != MA_SUCCESS) {
            return result;
        }

        if (format != ma_format_f32) {
            ma_pcm_convert(pFramesOut, format, pConverted, ma_format_f32, framesOut * channels, ma_dither_mode_none);
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
