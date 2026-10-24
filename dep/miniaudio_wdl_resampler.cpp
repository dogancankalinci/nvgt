/* miniaudio_wdl_resampler.cpp - Miniaudio binding for WDL resampler.
 *
 * Written by Caturria and released into the public domain
 */
#include <resample.h>
#include <miniaudio.h>
struct wdl_resampler_state
{
    WDL_Resampler resampler;
    ma_uint32 rate_in;
    ma_uint32 rate_out;
    ma_uint8 channels;
    bool should_flush; // More about this flag where it's used.
    ma_uint64 frames_in, frames_out; // Taken and given since the last reset, see the flush in resampler_process().
};
// The frames MiniAudio counts for frame_count_in resampled, as its ma_calculate_frame_count_after_resampling() does, with which it reports a decoder's length but which its header doesn't declare.
static ma_uint64 frames_after_resampling(ma_uint32 rate_out, ma_uint32 rate_in, ma_uint64 frame_count_in)
{
    if (rate_in == 0 || rate_out == 0 || frame_count_in == 0)
        return 0;
    if (rate_out == rate_in)
        return frame_count_in;
    ma_uint64 frame_count_out = (frame_count_in * rate_out) / rate_in;
    ma_uint64 preliminary_from_frac = (frame_count_out * (rate_in / rate_out)) / rate_out;
    ma_uint64 preliminary = (frame_count_out * (rate_in % rate_out)) + preliminary_from_frac;
    if (preliminary <= frame_count_in)
        frame_count_out += 1;
    return frame_count_out;
}
// Counted from a seek's frame rather than from the reset the seek made, the flush at the end gives no more than the decoder's length, rather than no more than its length counted from that frame, a frame or two more.
void wdl_resampler_set_counts(ma_resampling_backend *backend, ma_uint64 frames_in, ma_uint64 frames_out)
{
    wdl_resampler_state *state = (wdl_resampler_state *)backend;
    state->frames_in = frames_in;
    state->frames_out = frames_out;
}
// Miniaudio allocates heap space for our resampler and expects us to fill it in. So we must report how much we need.
static ma_result resampler_get_heap_size(void *pUserData, const ma_resampler_config *pConfig, size_t *pHeapSizeInBytes)
{
    *pHeapSizeInBytes = sizeof(wdl_resampler_state);
    return MA_SUCCESS;
}
static ma_result resampler_init(void *pUserData, const ma_resampler_config *pConfig, void *pHeap, ma_resampling_backend **ppBackend)
{
    memset(pHeap, 0, sizeof(wdl_resampler_state));
    wdl_resampler_state *state = (wdl_resampler_state *)pHeap;
    state->channels = pConfig->channels;
    state->rate_in = pConfig->sampleRateIn;
    state->rate_out = pConfig->sampleRateOut;
    state->should_flush = false;
    state->resampler = WDL_Resampler();
    state->resampler.SetMode(false, 0, true, 64, 32);
    state->resampler.SetRates(pConfig->sampleRateIn, pConfig->sampleRateOut);
    state->resampler.SetFeedMode(false);
    *ppBackend = state;

    return MA_SUCCESS;
}
static void resampler_uninit(void *pUserData, ma_resampling_backend *pBackend, const ma_allocation_callbacks *pAllocationCallbacks)
{
    wdl_resampler_state *state = (wdl_resampler_state *)pBackend;
    // Need to make an explicit destructor call because MA is about to just free the buffer it gave me.
    state->resampler.~WDL_Resampler();
}
static ma_result resampler_process(void *pUserData, ma_resampling_backend *pBackend, const void *pFramesIn, ma_uint64 *pFrameCountIn, void *pFramesOut, ma_uint64 *pFrameCountOut)
{
    wdl_resampler_state *state = (wdl_resampler_state *)pBackend;
    state->resampler.SetFeedMode(false);
    float *dest; // The resampler will point this to internal memory where we'll need to write some audio data.
    int prepare;
    if (*pFrameCountIn == 0 && state->should_flush)
    {
        // MiniAudio didn't give us any input but it expects output. This is at least the second time it has done this back to back. In this situation we know that no more input will come, so we flush the resampler's internal buffers and produce the final few frames.
        // No more than MiniAudio counts for the input taken, as it reports a decoder's length from that count: the flush gave a frame more, which a stream, its cursor wrapping at that length, played as one more each pass, so that a stream turned from looping ended further from its pass's end the longer it had looped.
        ma_uint64 owed = frames_after_resampling(state->rate_out, state->rate_in, state->frames_in);
        ma_uint64 left = owed > state->frames_out ? owed - state->frames_out : 0;
        if (*pFrameCountOut > left)
            *pFrameCountOut = left;
        // When you want to finalize the WDL resampler, you prepare and then report that you provided fewer samples than you prepared for. As many silent frames as one output frame spans are given first, as input past the end, which WDL pads with silence anyway, so that its tail reaches MiniAudio's count where it fell a frame short: for a rate an integer multiple of the output's, MiniAudio counts a last frame that lies at the input's end. Measured against MiniAudio's count for every length from 48000 to 48119 frames at 13 rate pairs: fewer were short for some, none came out longer.
        if (*pFrameCountOut)
        {
            int silent = (int)((state->rate_in + state->rate_out - 1) / state->rate_out);
            state->resampler.SetFeedMode(true);
            prepare = state->resampler.ResamplePrepare(silent + 1, state->channels, &dest);
            if (prepare > silent)
                memset(dest, 0, sizeof(float) * state->channels * silent);
            *pFrameCountOut = state->resampler.ResampleOut((float *)pFramesOut, prepare > silent ? silent : 0, *pFrameCountOut, state->channels);
        }
        state->frames_out += *pFrameCountOut;
        return MA_SUCCESS;
    }
    state->should_flush = false; // We received more input, so keep going.
    prepare = state->resampler.ResamplePrepare(*pFrameCountOut, state->channels, &dest);

    if (prepare > *pFrameCountIn)
    {
        // We don't have enough to produce the requested amount of output, so prepare again to produce as much as possible.

        state->resampler.SetFeedMode(true);
        prepare = state->resampler.ResamplePrepare(*pFrameCountIn, state->channels, &dest);
    }
    // Dest points to memory inside of the resampler where it wants us to send the input data.
    memcpy(dest, pFramesIn, prepare * sizeof(float) * state->channels);
    *pFrameCountIn = prepare; // MiniAudio lets us leave input on the table, in which case it will provide it to us again next time.
    *pFrameCountOut = state->resampler.ResampleOut((float *)pFramesOut, prepare, *pFrameCountOut, state->channels);
    state->frames_in += prepare;
    state->frames_out += *pFrameCountOut;
    if (*pFrameCountOut == 0)
    {
        // We produced nothing. If this is the case again on the next iteration, we're dealing with an EOF situation and should finalize the resampler.
        state->should_flush = true;
    }

    return MA_SUCCESS;
}
static ma_result resampler_set_rate(void *pUserData, ma_resampling_backend *pBackend, ma_uint32 sampleRateIn, ma_uint32 sampleRateOut)
{
    wdl_resampler_state *state = (wdl_resampler_state *)pBackend;
    state->resampler.SetRates(sampleRateIn, sampleRateOut);
    state->rate_in = sampleRateIn;
    state->rate_out = sampleRateOut;
    state->frames_in = state->frames_out = 0; // Counted at the new rates from here.
    return MA_SUCCESS;
}
static ma_uint64 resampler_get_input_latency(void *pUserData, const ma_resampling_backend *pBackend)
{
    wdl_resampler_state *state = (wdl_resampler_state *)pBackend;
    return (ma_uint64)(state->resampler.GetCurrentLatency() * state->rate_in);
}
static ma_uint64 resampler_get_output_latency(void *pUserData, const ma_resampling_backend *pBackend)
{
    wdl_resampler_state *state = (wdl_resampler_state *)pBackend;
    return (ma_uint64)(state->resampler.GetCurrentLatency() * state->rate_in);
}
// Important: returns how many frames would need to be provided in order to produce the requested amount of output.
static ma_result resampler_get_required_input_frame_count(void *pUserData, const ma_resampling_backend *pBackend, ma_uint64 outputFrameCount, ma_uint64 *pInputFrameCount)
{
    wdl_resampler_state *state = (wdl_resampler_state *)pBackend;
    state->resampler.SetFeedMode(false);
    float *dest;
    *pInputFrameCount = state->resampler.ResamplePrepare(outputFrameCount, state->channels, &dest); // Harmless. We can just prepare again with whatever amount of input we actually receive.
    return MA_SUCCESS;
}
static ma_result resampler_get_expected_output_frame_count(void *pUserData, const ma_resampling_backend *pBackend, ma_uint64 inputFrameCount, ma_uint64 *pOutputFrameCount)
{
    // We could theoretically implement this one by swapping in and out rates and then doing the same as above, but MiniAudio doesn't use this so leaving it out for now.
    *pOutputFrameCount = 0;
    return MA_NOT_IMPLEMENTED;
}
static ma_result resampler_reset(void *pUserData, ma_resampling_backend *pBackend)
{
    wdl_resampler_state *state = (wdl_resampler_state *)pBackend;
    state->resampler.Reset();
    state->should_flush = false;
    state->frames_in = state->frames_out = 0;
    return MA_SUCCESS;
}
ma_resampling_backend_vtable wdl_resampler_backend_vtable = {
    resampler_get_heap_size,
    resampler_init,
    resampler_uninit,
    resampler_process,
    resampler_set_rate,
    resampler_get_input_latency,
    resampler_get_output_latency,
    resampler_get_required_input_frame_count,
    resampler_get_expected_output_frame_count,
    resampler_reset,
};
