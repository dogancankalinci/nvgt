/* miniaudio_wdl_resampler.h - Miniaudio binding for WDL resampler header.
 *
 * Written by Caturria and released into the public domain
 */
#pragma once
#include "miniaudio.h"
extern ma_resampling_backend_vtable wdl_resampler_backend_vtable;
// Sets a resampler's counts of input taken and output given (see resampler_process()) to a decoder's places in its file and in its output, as after a seek, which resets them.
void wdl_resampler_set_counts(ma_resampling_backend *backend, ma_uint64 frames_in, ma_uint64 frames_out);
// MiniAudio's ma_calculate_frame_count_after_resampling(), which its header doesn't declare: the frames frame_count_in come to at rate_out, as a decoder maps a frame to its file's.
ma_uint64 wdl_frames_after_resampling(ma_uint32 rate_out, ma_uint32 rate_in, ma_uint64 frame_count_in);
// Whether the resampler was reset since this was last asked, its counts with it.
bool wdl_resampler_take_reset(ma_resampling_backend *backend);
