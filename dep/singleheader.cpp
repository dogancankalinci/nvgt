/* singleheader.cpp
 * This file defines the implementations of all single header dependencies used in this project to increase build speed.
 *
 * NVGT - NonVisual Gaming Toolkit
 * Copyright (c) 2022-2026 Sam Tupy
 * https://nvgt.dev
 * This software is provided "as-is", without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 * 1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 * 2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 * 3. This notice may not be removed or altered from any source distribution.
*/

#ifdef _WIN32
#include <windows.h>
#else
#include <cstdio>
#include <cstdlib>
#include <cstring>
#endif
#ifdef __ANDROID__
#define ANDROID_FOPEN_IMPLEMENTATION
#include "android_fopen.h"
#endif

#define BL_NUMWORDS_IMPLEMENTATION
#include "bl_number_to_words.h"
#define DBGTOOLS_IMPLEMENTATION
#include "dbgtools.h"
#define MINIAUDIO_IMPLEMENTATION
#include <miniaudio.h>
// Seeks a file a decoder reads, given its data source's own vtable, for what MiniAudio's FLAC and MP3 decoders get wrong; here, where their structures are known. See held_file in sound.cpp.
ma_result nvgt_file_seek(const ma_data_source_vtable* vtable, ma_data_source* file, ma_uint64 frame, ma_bool32 can_seek) {
	if (vtable == &g_ma_flac_ds_vtable && ((ma_flac*)file)->dr) {
		ma_dr_flac* flac = ((ma_flac*)file)->dr;
		const ma_uint64 at = flac->currentPCMFrame;
		const ma_uint32 remaining = flac->currentFLACFrame.pcmFramesRemaining;
		// dr_flac takes a frame behind it within the block it last decoded as still decoded, which a block that failed to decode, as at a file's truncated end, left with no samples: reading them crashed. A block with nothing left to give is taken as spent, which sends the seek through the file.
		if (frame < at && !remaining) flac->currentFLACFrame.header.blockSizeInPCMFrames = 0;
	} else if (vtable == &g_ma_mp3_ds_vtable) {
		// dr_mp3's cursor counts the encoder delay a LAME header gives, which it skips, and its seek forward reads on from that cursor to the frame asked for, landing the delay short, 1105 frames as a rule, reported as made. A seek back, from the start, counts it right.
		ma_dr_mp3* mp3 = &((ma_mp3*)file)->dr;
		const ma_uint64 delay = mp3->delayInPCMFrames;
		if (frame && delay && mp3->currentPCMFrame >= delay && frame <= ~(ma_uint64)0 - delay && frame + delay >= mp3->currentPCMFrame) frame += delay;
	}
	return vtable->onSeek(file, frame);
}
// The frames a file's own cursor counts that it never gives (see above).
ma_uint64 nvgt_file_delay(const ma_data_source_vtable* vtable, ma_data_source* file) { return vtable == &g_ma_mp3_ds_vtable? ((ma_mp3*)file)->dr.delayInPCMFrames : 0; }
#define RND_IMPLEMENTATION
#include "rnd.h"
#define SPEECH_IMPLEMENTATION
#include "speech.h"
#define THREAD_IMPLEMENTATION
#include "thread.h"
