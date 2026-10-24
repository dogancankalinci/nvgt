/* miniaudio_wdl_resampler.h - Miniaudio binding for WDL resampler header.
 *
 * Written by Caturria and released into the public domain
 */
#pragma once
#include "miniaudio.h"
extern ma_resampling_backend_vtable wdl_resampler_backend_vtable;
// Sets a resampler's counts of input taken and output given (see resampler_process()) to a decoder's places in its file and in its output, as after a seek, which resets them.
void wdl_resampler_set_counts(ma_resampling_backend *backend, ma_uint64 frames_in, ma_uint64 frames_out);
