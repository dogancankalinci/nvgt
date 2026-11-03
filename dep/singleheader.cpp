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
#define MA_USE_QUAD_MICROSOFT_CHANNEL_MAP // Four channels are quad, as FLAC's specification says, a WAV without a mask means and Vorbis and Opus order them, rather than MiniAudio's default of left, right, centre and back centre, which took the third to the centre and lost the fourth.
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
		// A stream that can't seek: dr_flac's seeks need the file, and when that's refused it carries on from the file's real place as if at its start, reporting a seek made, and clamps to a total it may not have. Forward is reading on, and back is from the first block, while the decoder's window still reaches it.
		if (!can_seek && frame != at) {
			const ma_uint32 consumed = flac->currentFLACFrame.header.blockSizeInPCMFrames - remaining;
			if (frame < at && remaining && consumed > at - frame) { // Within the block, needing no file: as dr_flac does it, which first clamps the frame to a total it may not have.
				flac->currentFLACFrame.pcmFramesRemaining += (ma_uint32)(at - frame);
				flac->currentPCMFrame = frame;
				return MA_SUCCESS;
			}
			ma_uint64 from = at;
			if (frame < at) {
				if (flac->firstFLACFramePosInBytes > 0x7FFFFFFF || !flac->bs.onSeek(flac->bs.pUserData, (int)flac->firstFLACFramePosInBytes, MA_DR_FLAC_SEEK_SET)) return MA_INVALID_OPERATION; // Before anything changes, so that it reads on from where it was.
				if (!ma_dr_flac__seek_to_first_frame(flac)) return MA_INVALID_OPERATION;
				from = 0;
			}
			return ma_dr_flac_read_pcm_frames_f32(flac, frame - from, NULL) == frame - from? MA_SUCCESS : MA_INVALID_ARGS;
		}
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
// The weights ([in][out]) by which a source of two or more channels plays on two or more others, for a channel converter's custom weights; false for one or the other of a single channel, which MiniAudio's own modes take. MiniAudio's simple mode, which a sound with fewer channels than its engine played in, dropped every channel the engine has no place of, a quad file's rear pair on a 5.1 engine, and copied the front pair into the sides; and its rectangular mode, which mixed one with more, gave a channel sharing no plane with any output, as a back centre on a stereo or 5.1 engine, no weight at all, and filled outputs the source has no channel for from those near them. Here, a channel goes to its own place, or else, a side to the back of its side or the other way, where the source has no channel there, or else as the rectangular mode weighs it, or else, one at the back to the rearmost pair, and any other to the centre or the front pair. An LFE goes only to an LFE; an output no channel goes to stays silent, as other players leave it.
extern "C" ma_bool32 nvgt_channel_weights(const ma_channel* map_in, ma_uint32 channels_in, const ma_channel* map_out, ma_uint32 channels_out, float** weights) {
	if (channels_in < 2 || channels_out < 2 || channels_in > MA_MAX_CHANNELS || channels_out > MA_MAX_CHANNELS) return MA_FALSE;
	auto out_index = [=](ma_channel position) -> int {
		for (ma_uint32 out = 0; out < channels_out; out++) {
			if (ma_channel_map_get_channel(map_out, channels_out, out) == position) return (int)out;
		}
		return -1;
	};
	auto pair = [&](float* row, ma_channel left, ma_channel right) {
		const int l = out_index(left), r = out_index(right);
		if (l < 0 || r < 0) return false;
		row[l] = row[r] = 0.5f;
		return true;
	};
	for (ma_uint32 in = 0; in < channels_in; in++) {
		float* row = weights[in];
		for (ma_uint32 out = 0; out < channels_out; out++) row[out] = 0;
		const ma_channel position = ma_channel_map_get_channel(map_in, channels_in, in);
		const int own = position == MA_CHANNEL_NONE? -1 : out_index(position);
		if (own >= 0) {
			row[own] = 1;
			continue;
		}
		if (!ma_is_spatial_channel_position(position)) continue; // An LFE with no LFE to go to, as MiniAudio leaves it, or a channel of no place.
		ma_channel counterpart = MA_CHANNEL_NONE;
		switch (position) {
			case MA_CHANNEL_SIDE_LEFT: counterpart = MA_CHANNEL_BACK_LEFT; break;
			case MA_CHANNEL_SIDE_RIGHT: counterpart = MA_CHANNEL_BACK_RIGHT; break;
			case MA_CHANNEL_BACK_LEFT: counterpart = MA_CHANNEL_SIDE_LEFT; break;
			case MA_CHANNEL_BACK_RIGHT: counterpart = MA_CHANNEL_SIDE_RIGHT; break;
			default: break;
		}
		const int stand_in = counterpart != MA_CHANNEL_NONE && !ma_channel_map_contains_channel_position(channels_in, map_in, counterpart)? out_index(counterpart) : -1;
		if (stand_in >= 0) {
			row[stand_in] = 1;
			continue;
		}
		bool placed = false;
		for (ma_uint32 out = 0; out < channels_out; out++) {
			const ma_channel position_out = ma_channel_map_get_channel(map_out, channels_out, out);
			if (ma_is_spatial_channel_position(position_out) && (row[out] = ma_calculate_channel_position_rectangular_weight(position, position_out)) != 0) placed = true;
		}
		if (placed) continue;
		if (g_maChannelPlaneRatios[position][MA_PLANE_BACK] > 0 && (pair(row, MA_CHANNEL_BACK_LEFT, MA_CHANNEL_BACK_RIGHT) || pair(row, MA_CHANNEL_SIDE_LEFT, MA_CHANNEL_SIDE_RIGHT) || pair(row, MA_CHANNEL_FRONT_LEFT, MA_CHANNEL_FRONT_RIGHT))) continue;
		const int centre = out_index(MA_CHANNEL_FRONT_CENTER);
		if (centre >= 0) row[centre] = 1;
		else pair(row, MA_CHANNEL_FRONT_LEFT, MA_CHANNEL_FRONT_RIGHT);
	}
	return MA_TRUE;
}
// dr_mp3 skips the frame of a LAME or Xing header by setting its stream cursor to that frame's end, forgetting what it had read past it, so that its clamp at the audio's end, which keeps it out of an ID3v1 tag, let the tag through, and the last MPEG frame, not followed by another, became silence. Put right as an MP3 opens, on every route to it through MiniAudio's table of its backend.
static ma_result nvgt_mp3_backend_init(void* user_data, ma_read_proc on_read, ma_seek_proc on_seek, ma_tell_proc on_tell, void* read_user_data, const ma_decoding_backend_config* config, const ma_allocation_callbacks* allocation_callbacks, ma_data_source** backend) {
	ma_result result = ma_decoding_backend_init__mp3(user_data, on_read, on_seek, on_tell, read_user_data, config, allocation_callbacks, backend);
	if (result == MA_SUCCESS) {
		ma_dr_mp3* mp3 = &((ma_mp3*)*backend)->dr;
		if (mp3->streamCursor == mp3->streamStartOffset) mp3->streamCursor += mp3->dataSize; // What's left of what it read, after a header's frame only: any other read moves the cursor past the start.
		// An APE tag: dr_mp3 reads its size from reserved bytes, which are 0, so that it trims the 32-byte footer alone, leaving the tag in the audio, whose last frame then wasn't followed by another and became silence. The file is read as it was left; where the footer is, as it was trimmed, is where its audio ends without the rest of the tag.
		ma_int64 at = 0;
		if (mp3->streamLength != MA_UINT64_MAX && mp3->streamLength > mp3->streamStartOffset && on_tell && on_tell(read_user_data, &at) == MA_SUCCESS && on_seek(read_user_data, (ma_int64)mp3->streamLength, ma_seek_origin_start) == MA_SUCCESS) {
			ma_uint8 footer[32];
			size_t got = 0;
			if (on_read(read_user_data, footer, sizeof(footer), &got) == MA_SUCCESS && got == sizeof(footer) && memcmp(footer, "APETAGEX", 8) == 0) {
				const ma_uint64 size = (ma_uint64)footer[12] | (ma_uint64)footer[13] << 8 | (ma_uint64)footer[14] << 16 | (ma_uint64)footer[15] << 24; // With the footer.
				const ma_uint64 tag = size + (footer[23] & 0x80? 32 : 0), tag_end = mp3->streamLength + 32; // With a header too, flagged in the top bit.
				if (tag < tag_end - mp3->streamStartOffset) {
					mp3->streamLength = tag_end - tag;
					// What it read of the tag already, all of it for a file that fits its first read.
					const ma_uint64 past = mp3->streamCursor > mp3->streamLength? mp3->streamCursor - mp3->streamLength : 0;
					if (past && past <= mp3->dataSize) {
						mp3->dataSize -= (size_t)past;
						mp3->streamCursor = mp3->streamLength;
					}
				}
			}
			on_seek(read_user_data, at, ma_seek_origin_start);
		}
	}
	return result;
}
static const bool nvgt_mp3_backend_installed = (g_ma_decoding_backend_vtable_mp3.onInit = nvgt_mp3_backend_init, true);
// A WAV whose data size is 0, as from a recording that never closed its header, reads to the end of its file, as other players take it, rather than as empty. Only for samples of a fixed size. A source that can't seek is read to its end and come back to, as dr_wav does for a size of 0xFFFFFFFF, which such a source can do within what it keeps of its start; one too long for that can't be opened, as such a WAV can't.
static ma_result nvgt_wav_backend_init(void* user_data, ma_read_proc on_read, ma_seek_proc on_seek, ma_tell_proc on_tell, void* read_user_data, const ma_decoding_backend_config* config, const ma_allocation_callbacks* allocation_callbacks, ma_data_source** backend) {
	ma_result result = ma_decoding_backend_init__wav(user_data, on_read, on_seek, on_tell, read_user_data, config, allocation_callbacks, backend);
	if (result != MA_SUCCESS) return result;
	ma_dr_wav* wav = &((ma_wav*)*backend)->dr;
	const bool plain = wav->translatedFormatTag == MA_DR_WAVE_FORMAT_PCM || wav->translatedFormatTag == MA_DR_WAVE_FORMAT_IEEE_FLOAT;
	if (wav->dataChunkDataSize || !plain || !wav->fmt.blockAlign) return result;
	ma_uint64 size = 0;
	ma_int64 end = 0;
	if (on_tell && on_seek(read_user_data, 0, ma_seek_origin_end) == MA_SUCCESS) {
		const bool told = on_tell(read_user_data, &end) == MA_SUCCESS;
		on_seek(read_user_data, (ma_int64)wav->dataChunkDataPos, ma_seek_origin_start);
		if (!told || (ma_uint64)end <= wav->dataChunkDataPos) return result;
		size = (ma_uint64)end - wav->dataChunkDataPos;
	} else {
		for (;;) {
			ma_uint8 block[4096];
			size_t got = 0;
			const ma_result read = on_read(read_user_data, block, sizeof(block), &got);
			size += got;
			if (read != MA_SUCCESS || got < sizeof(block)) break;
		}
		if (on_seek(read_user_data, (ma_int64)wav->dataChunkDataPos, ma_seek_origin_start) != MA_SUCCESS) {
			ma_decoding_backend_uninit__wav(user_data, *backend, allocation_callbacks);
			*backend = NULL;
			return MA_INVALID_FILE;
		}
	}
	const ma_uint64 frames = size / wav->fmt.blockAlign;
	wav->dataChunkDataSize = frames * wav->fmt.blockAlign;
	wav->bytesRemaining = wav->dataChunkDataSize;
	wav->totalPCMFrameCount = frames;
	return result;
}
static const bool nvgt_wav_backend_installed = (g_ma_decoding_backend_vtable_wav.onInit = nvgt_wav_backend_init, true);
#define RND_IMPLEMENTATION
#include "rnd.h"
#define SPEECH_IMPLEMENTATION
#include "speech.h"
#define THREAD_IMPLEMENTATION
#include "thread.h"
