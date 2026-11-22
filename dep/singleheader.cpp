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
#include <vector>
#define MA_USE_QUAD_MICROSOFT_CHANNEL_MAP // Four channels are quad, as FLAC's specification says, a WAV without a mask means and Vorbis and Opus order them, rather than MiniAudio's default of left, right, centre and back centre, which took the third to the centre and lost the fourth.
#define MINIAUDIO_IMPLEMENTATION
#include <miniaudio.h>
// A FLAC, with what its reads keep (see nvgt_flac_read()).
struct nvgt_flac {
	ma_flac flac; // First: MiniAudio takes this struct for it.
	bool placed; // A block was read, numbered and sized as below.
	bool in_order; // A block came right after another by their numbers.
	bool from_zero; // And at the frame its number gives, as one cut out of a longer file doesn't.
	ma_uint32 number;
	ma_uint32 size;
	ma_uint64 first; // For blocks of varying sizes, which are numbered by their first frame.
	ma_uint64 silence; // For lost blocks, still to be given ahead of the one read last.
};
// The frame the block dr_flac decoded last starts at, by its number, as dr_flac's seeks take it.
static ma_uint64 nvgt_flac_first(ma_dr_flac* flac) {
	ma_uint64 first = 0;
	ma_dr_flac__get_pcm_frame_range_of_current_flac_frame(flac, &first, NULL);
	return first;
}
static void nvgt_flac_place(nvgt_flac* f) {
	const ma_dr_flac_frame_header& header = f->flac.dr->currentFLACFrame.header;
	f->placed = true;
	f->number = header.flacFrameNumber;
	f->first = header.pcmFrameNumber;
	f->size = header.blockSizeInPCMFrames;
}
// Whether another block was decoded: one that can't be, other than for its checksum, ends dr_flac's read, which goes on from the next block when asked again.
static bool nvgt_flac_next_block(ma_dr_flac* flac) {
	for (int tries = 0; tries < 8; tries++) {
		if (ma_dr_flac__read_and_decode_next_flac_frame(flac)) return true;
	}
	return false;
}
// dr_flac drops a block whose checksum doesn't match, as of a damaged file, so that everything after it came early by its length, with silence at the file's end to make up for it, and disagreed with where a seek lands: silence in its place, as for a hole in a Vorbis or Opus file. By the blocks' numbers, where they were in order before, as an encoder that numbers them otherwise has none lost.
static ma_result nvgt_flac_read(ma_data_source* source, void* frames_out, ma_uint64 frame_count, ma_uint64* frames_read) {
	nvgt_flac* f = (nvgt_flac*)source;
	ma_dr_flac* flac = f->flac.dr;
	const ma_uint32 frame_size = ma_get_bytes_per_frame(f->flac.format, flac->channels);
	ma_uint64 total = 0;
	ma_result result = MA_SUCCESS;
	while (total < frame_count) {
		void* out = frames_out? ma_offset_ptr(frames_out, total * frame_size) : NULL;
		if (f->silence) {
			const ma_uint64 count = ma_min(frame_count - total, f->silence);
			if (out) ma_silence_pcm_frames(out, count, f->flac.format, flac->channels);
			flac->currentPCMFrame += count;
			f->silence -= count;
			total += count;
			continue;
		}
		if (!flac->currentFLACFrame.pcmFramesRemaining) {
			if (!nvgt_flac_next_block(flac)) break;
			const ma_dr_flac_frame_header& header = flac->currentFLACFrame.header;
			ma_uint64 lost = 0;
			if (f->placed) {
				if (header.pcmFrameNumber) {
					const ma_uint64 next = f->first + f->size;
					if (header.pcmFrameNumber == next) f->in_order = true;
					else if (header.pcmFrameNumber > next) lost = header.pcmFrameNumber - next;
				} else if (header.flacFrameNumber > f->number) {
					if (header.flacFrameNumber == f->number + 1) f->in_order = true;
					else lost = (ma_uint64)(header.flacFrameNumber - f->number - 1) * f->size;
				}
				if (!lost && f->in_order) f->from_zero = nvgt_flac_first(flac) == flac->currentPCMFrame;
			}
			nvgt_flac_place(f);
			// Not past the file's length, nor, without one, more than ten minutes at 192 kHz: a number damaged too.
			const ma_uint64 most = flac->totalPCMFrameCount? (flac->totalPCMFrameCount > flac->currentPCMFrame? flac->totalPCMFrameCount - flac->currentPCMFrame : 0) : 115200000;
			if (lost && f->in_order && lost <= most) {
				f->silence = lost;
				continue;
			}
		}
		ma_uint64 got = 0;
		result = ma_flac_read_pcm_frames(&f->flac, out, ma_min(frame_count - total, (ma_uint64)flac->currentFLACFrame.pcmFramesRemaining), &got);
		total += got;
		if (result != MA_SUCCESS || !got) break;
	}
	if (frames_read) *frames_read = total;
	return total? MA_SUCCESS : result != MA_SUCCESS? result : MA_AT_END;
}
// Before a seek moves it: the silence left is passed over, as dr_flac takes the cursor to be at the block it decoded.
static void nvgt_flac_pass_silence(nvgt_flac* f) {
	f->flac.dr->currentPCMFrame += f->silence;
	f->silence = 0;
}
static ma_result nvgt_flac_seek(ma_data_source* source, ma_uint64 frame) {
	nvgt_flac* f = (nvgt_flac*)source;
	ma_dr_flac* flac = f->flac.dr;
	nvgt_flac_pass_silence(f);
	const ma_uint64 before = flac->currentPCMFrame;
	const ma_result result = ma_flac_seek_to_pcm_frame(&f->flac, frame);
	f->placed = false;
	// A frame of a lost block, which dr_flac refuses, or lands past, in the next block, reporting it made: it is in the silence ahead of that block, as it plays. One refused is read on to from the start.
	if (result != MA_SUCCESS && frame < flac->totalPCMFrameCount && ma_flac_seek_to_pcm_frame(&f->flac, 0) == MA_SUCCESS) {
		ma_uint64 passed = 0;
		nvgt_flac_read(source, NULL, frame, &passed);
		if (passed == frame) return MA_SUCCESS;
		f->silence = 0;
		f->placed = false;
		ma_flac_seek_to_pcm_frame(&f->flac, before);
	}
	ma_dr_flac_frame& block = flac->currentFLACFrame;
	if (!block.header.blockSizeInPCMFrames || block.pcmFramesRemaining > block.header.blockSizeInPCMFrames) return result;
	nvgt_flac_place(f);
	if (result != MA_SUCCESS || flac->currentPCMFrame != frame) return result;
	const ma_uint64 first = nvgt_flac_first(flac), at = first + (block.header.blockSizeInPCMFrames - block.pcmFramesRemaining);
	if (at == frame) f->in_order = f->from_zero = true;
	else if (at > frame && (f->from_zero || flac->totalPCMFrameCount && at - frame <= (ma_uint64)flac->maxBlockSizeInPCMFrames * 16)) { // Unless its numbers don't start at 0, as one's cut out of a longer file don't, told by then or by how far they are off.
		f->silence = first > frame? first - frame : 0;
		block.pcmFramesRemaining = block.header.blockSizeInPCMFrames - (ma_uint32)(frame > first? frame - first : 0);
	}
	return result;
}
static ma_result nvgt_flac_opened(ma_result result, nvgt_flac* f, const ma_allocation_callbacks* allocation_callbacks, ma_data_source** backend) {
	if (result == MA_SUCCESS) *backend = f;
	else ma_free(f, allocation_callbacks);
	return result;
}
static ma_result nvgt_flac_backend_init(void* user_data, ma_read_proc on_read, ma_seek_proc on_seek, ma_tell_proc on_tell, void* read_user_data, const ma_decoding_backend_config* config, const ma_allocation_callbacks* allocation_callbacks, ma_data_source** backend) {
	nvgt_flac* f = (nvgt_flac*)ma_calloc(sizeof(nvgt_flac), allocation_callbacks);
	if (!f) return MA_OUT_OF_MEMORY;
	return nvgt_flac_opened(ma_flac_init(on_read, on_seek, on_tell, read_user_data, config, allocation_callbacks, &f->flac), f, allocation_callbacks, backend);
}
static ma_result nvgt_flac_backend_init_memory(void* user_data, const void* data, size_t size, const ma_decoding_backend_config* config, const ma_allocation_callbacks* allocation_callbacks, ma_data_source** backend) {
	nvgt_flac* f = (nvgt_flac*)ma_calloc(sizeof(nvgt_flac), allocation_callbacks);
	if (!f) return MA_OUT_OF_MEMORY;
	return nvgt_flac_opened(ma_flac_init_memory(data, size, config, allocation_callbacks, &f->flac), f, allocation_callbacks, backend);
}
static ma_result nvgt_flac_backend_init_file(void* user_data, const char* path, const ma_decoding_backend_config* config, const ma_allocation_callbacks* allocation_callbacks, ma_data_source** backend) {
	nvgt_flac* f = (nvgt_flac*)ma_calloc(sizeof(nvgt_flac), allocation_callbacks);
	if (!f) return MA_OUT_OF_MEMORY;
	return nvgt_flac_opened(ma_flac_init_file(path, config, allocation_callbacks, &f->flac), f, allocation_callbacks, backend);
}
static ma_result nvgt_flac_backend_init_file_w(void* user_data, const wchar_t* path, const ma_decoding_backend_config* config, const ma_allocation_callbacks* allocation_callbacks, ma_data_source** backend) {
	nvgt_flac* f = (nvgt_flac*)ma_calloc(sizeof(nvgt_flac), allocation_callbacks);
	if (!f) return MA_OUT_OF_MEMORY;
	return nvgt_flac_opened(ma_flac_init_file_w(path, config, allocation_callbacks, &f->flac), f, allocation_callbacks, backend);
}
// Every way MiniAudio makes a FLAC's data source, so that each one is the struct above.
static const bool nvgt_flac_backend_installed = (g_ma_flac_ds_vtable.onRead = nvgt_flac_read, g_ma_flac_ds_vtable.onSeek = nvgt_flac_seek, g_ma_decoding_backend_vtable_flac.onInit = nvgt_flac_backend_init, g_ma_decoding_backend_vtable_flac.onInitMemory = nvgt_flac_backend_init_memory, g_ma_decoding_backend_vtable_flac.onInitFile = nvgt_flac_backend_init_file, g_ma_decoding_backend_vtable_flac.onInitFileW = nvgt_flac_backend_init_file_w, true);
// Seeks a file a decoder reads, given its data source's own vtable, for what MiniAudio's FLAC decoder gets wrong; here, where their structures are known. See held_file in sound.cpp.
ma_result nvgt_file_seek(const ma_data_source_vtable* vtable, ma_data_source* file, ma_uint64 frame, ma_bool32 can_seek) {
	if (vtable == &g_ma_flac_ds_vtable && ((ma_flac*)file)->dr) {
		ma_dr_flac* flac = ((ma_flac*)file)->dr;
		nvgt_flac_pass_silence((nvgt_flac*)file);
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
			ma_uint64 from = at, passed = 0;
			if (frame < at) {
				if (flac->firstFLACFramePosInBytes > 0x7FFFFFFF || !flac->bs.onSeek(flac->bs.pUserData, (int)flac->firstFLACFramePosInBytes, MA_DR_FLAC_SEEK_SET)) return MA_INVALID_OPERATION; // Before anything changes, so that it reads on from where it was.
				if (!ma_dr_flac__seek_to_first_frame(flac)) return MA_INVALID_OPERATION;
				((nvgt_flac*)file)->placed = false;
				from = 0;
			}
			nvgt_flac_read(file, NULL, frame - from, &passed); // With silence for lost blocks, as it plays.
			return passed == frame - from? MA_SUCCESS : MA_INVALID_ARGS;
		}
	}
	return vtable->onSeek(file, frame);
}
// The frames a file's own cursor counts that it never gives: the encoder delay a LAME header gives, which dr_mp3 skips, but counts in its cursor. Its seeks don't count it from 0.7.4 on, in MiniAudio 0.11.26.
ma_uint64 nvgt_file_delay(const ma_data_source_vtable* vtable, ma_data_source* file) { return vtable == &g_ma_mp3_ds_vtable? ((ma_mp3*)file)->dr.delayInPCMFrames : 0; }
// Whether asking a file's length counts its frames by reading it through to its end, rather than reading what its header says: an MP3 without a frame count in a Xing, Info or VBRI header, which dr_mp3 counts anew at each ask.
bool nvgt_file_length_counted(const ma_data_source_vtable* vtable, ma_data_source* file) { return vtable == &g_ma_mp3_ds_vtable && ((ma_mp3*)file)->dr.totalPCMFrameCount == MA_UINT64_MAX; }
// The most frames a byte of a file can give in its format, which a count its header claims can't go past (see file_length_impossible() in sound.cpp): an MPEG frame gives at most 1152 and is no smaller than its 4-byte header, while silence in FLAC or Opus makes about 3000 a byte. Taken as 16384 for an MP3 too, a count of 2^32 frames, as dr_mp3 wraps a Xing header's huge one to, passed for a file of 262 KB or more, which load() then asked 34 GB for.
ma_uint64 nvgt_file_most_frames_per_byte(const ma_data_source_vtable* vtable) { return vtable == &g_ma_mp3_ds_vtable? 1152 / 4 : 16384; }
// The weights ([in][out]) by which a source's channels play on other channels, for a channel converter's custom weights; false from one channel to one, which needs none. MiniAudio's simple mode, which a sound with fewer channels than its engine played in, dropped every channel the engine has no place of, a quad file's rear pair on a 5.1 engine, and copied the front pair into the sides; its rectangular mode, which mixed one with more, gave a back centre on a stereo or 5.1 engine no weight at all, took a back pair into the front at a quarter, a side pair at a half, and split one into the front where the source had both pairs, and filled outputs the source has no channel for from those near them; and a single channel went to every output, an LFE included, as every channel went at the same weight into one.
// Here, as other players lay it out (FFmpeg's rematrixing), at the half MiniAudio gives the centre in a front pair: a channel goes to its own place. A centre goes to the front pair. A back channel goes to the side of its side where the source has none, or else to a back centre, the side or its front at a half; a side goes to the back of its side, at a half where the source has that too, or else to a back centre or its front at a half; a back centre to the rearmost pair at a half each. Any other goes as the rectangular mode weighs it, and one that gets nothing from that goes to the rearmost pair if it is at the back, or else to the centre or the front pair. An LFE goes only to an LFE, and an output no channel goes to stays silent. A single channel goes to the front pair at its full level, as on a stereo engine, or the centre; and every channel goes into a single one as into the front pair, at the average of the two.
extern "C" ma_bool32 nvgt_channel_weights(const ma_channel* map_in, ma_uint32 channels_in, const ma_channel* map_out, ma_uint32 channels_out, float** weights) {
	if (!channels_in || !channels_out || channels_in > MA_MAX_CHANNELS || channels_out > MA_MAX_CHANNELS || channels_in == 1 && channels_out == 1) return MA_FALSE;
	if (channels_out == 1) {
		static const ma_channel front_pair[2] = {MA_CHANNEL_FRONT_LEFT, MA_CHANNEL_FRONT_RIGHT};
		// On the stack, at most MA_MAX_CHANNELS: called from C, as the Ogg link conversion on an audio or job thread, where an allocation that threw ended the program.
		float pair_weights[MA_MAX_CHANNELS * 2] = {};
		float* rows[MA_MAX_CHANNELS];
		for (ma_uint32 in = 0; in < channels_in; in++) rows[in] = &pair_weights[(size_t)in * 2];
		nvgt_channel_weights(map_in, channels_in, front_pair, 2, rows);
		for (ma_uint32 in = 0; in < channels_in; in++) weights[in][0] = (rows[in][0] + rows[in][1]) / 2;
		return MA_TRUE;
	}
	auto out_index = [=](ma_channel position) -> int {
		for (ma_uint32 out = 0; out < channels_out; out++) {
			if (ma_channel_map_get_channel(map_out, channels_out, out) == position) return (int)out;
		}
		return -1;
	};
	auto in_has = [=](ma_channel position) { return ma_channel_map_contains_channel_position(channels_in, map_in, position) != MA_FALSE; };
	auto put = [&](float* row, ma_channel position, float weight) {
		const int out = out_index(position);
		if (out < 0) return false;
		row[out] = weight;
		return true;
	};
	auto put_pair = [&](float* row, ma_channel left, ma_channel right, float weight) {
		const int l = out_index(left), r = out_index(right);
		if (l < 0 || r < 0) return false;
		row[l] = row[r] = weight;
		return true;
	};
	for (ma_uint32 in = 0; in < channels_in; in++) {
		float* row = weights[in];
		for (ma_uint32 out = 0; out < channels_out; out++) row[out] = 0;
		if (channels_in == 1) {
			if (!put_pair(row, MA_CHANNEL_FRONT_LEFT, MA_CHANNEL_FRONT_RIGHT, 1) && !put(row, MA_CHANNEL_FRONT_CENTER, 1)) {
				for (ma_uint32 out = 0; out < channels_out; out++) row[out] = ma_is_spatial_channel_position(ma_channel_map_get_channel(map_out, channels_out, out))? 1.0f : 0.0f;
			}
			continue;
		}
		const ma_channel position = ma_channel_map_get_channel(map_in, channels_in, in);
		if (position != MA_CHANNEL_NONE && put(row, position, 1)) continue;
		if (!ma_is_spatial_channel_position(position)) continue; // An LFE with no LFE to go to, as MiniAudio leaves it, or a channel of no place.
		const bool left = position == MA_CHANNEL_BACK_LEFT || position == MA_CHANNEL_SIDE_LEFT;
		const ma_channel side = left? MA_CHANNEL_SIDE_LEFT : MA_CHANNEL_SIDE_RIGHT, back = left? MA_CHANNEL_BACK_LEFT : MA_CHANNEL_BACK_RIGHT, front = left? MA_CHANNEL_FRONT_LEFT : MA_CHANNEL_FRONT_RIGHT;
		switch (position) {
			case MA_CHANNEL_FRONT_CENTER:
				if (put_pair(row, MA_CHANNEL_FRONT_LEFT, MA_CHANNEL_FRONT_RIGHT, 0.5f)) continue;
				break;
			case MA_CHANNEL_BACK_LEFT: case MA_CHANNEL_BACK_RIGHT:
				if (!in_has(side) && put(row, side, 1) || put(row, MA_CHANNEL_BACK_CENTER, 0.5f) || put(row, side, 0.5f) || put(row, front, 0.5f)) continue;
				break;
			case MA_CHANNEL_SIDE_LEFT: case MA_CHANNEL_SIDE_RIGHT:
				if (put(row, back, in_has(back)? 0.5f : 1.0f) || put(row, MA_CHANNEL_BACK_CENTER, 0.5f) || put(row, front, 0.5f)) continue;
				break;
			case MA_CHANNEL_BACK_CENTER:
				if (put_pair(row, MA_CHANNEL_BACK_LEFT, MA_CHANNEL_BACK_RIGHT, 0.5f) || put_pair(row, MA_CHANNEL_SIDE_LEFT, MA_CHANNEL_SIDE_RIGHT, 0.5f) || put_pair(row, MA_CHANNEL_FRONT_LEFT, MA_CHANNEL_FRONT_RIGHT, 0.5f) || put(row, MA_CHANNEL_FRONT_CENTER, 1)) continue;
				break;
			default: break;
		}
		bool placed = false;
		for (ma_uint32 out = 0; out < channels_out; out++) {
			const ma_channel position_out = ma_channel_map_get_channel(map_out, channels_out, out);
			if (ma_is_spatial_channel_position(position_out) && (row[out] = ma_calculate_channel_position_rectangular_weight(position, position_out)) != 0) placed = true;
		}
		if (placed) continue;
		if (g_maChannelPlaneRatios[position][MA_PLANE_BACK] > 0 && (put_pair(row, MA_CHANNEL_BACK_LEFT, MA_CHANNEL_BACK_RIGHT, 0.5f) || put_pair(row, MA_CHANNEL_SIDE_LEFT, MA_CHANNEL_SIDE_RIGHT, 0.5f) || put_pair(row, MA_CHANNEL_FRONT_LEFT, MA_CHANNEL_FRONT_RIGHT, 0.5f))) continue;
		if (!put(row, MA_CHANNEL_FRONT_CENTER, 1)) put_pair(row, MA_CHANNEL_FRONT_LEFT, MA_CHANNEL_FRONT_RIGHT, 0.5f);
	}
	return MA_TRUE;
}
// How far past any ID3v2 tag an MP3's first frame is looked for in a stream whose end can't be found, as far as libvorbisfile and opusfile look for their first page: dr_mp3 reads on until it finds one, so that on an endless stream of something else, as an AAC radio or a datastream of other data, the open never returned.
static const ma_uint64 nvgt_mp3_search_bytes = 65536;
// The file's own callbacks, wrapped while dr_mp3 opens it (see nvgt_mp3_backend_init()).
struct nvgt_mp3_open_file {
	ma_read_proc read;
	ma_seek_proc seek;
	ma_tell_proc tell;
	void* user;
	bool sized = false; // A seek to its end was made, so that it ends: not bounded.
	ma_uint64 got = 0; // Where it was read to, from where it started, as its reads and seeks moved it.
	ma_uint8 head[10] = {}; // Its first bytes, which give an ID3v2 tag's size.
	ma_uint64 limit = 0; // How far it may be read, once its first bytes are.
};
static ma_result nvgt_mp3_open_read(void* user, void* out, size_t bytes, size_t* bytes_read) {
	nvgt_mp3_open_file* file = (nvgt_mp3_open_file*)user;
	if (bytes_read) *bytes_read = 0;
	if (!file->sized && file->got >= sizeof(file->head)) {
		if (file->got >= file->limit) return MA_AT_END;
		if (bytes > file->limit - file->got) bytes = (size_t)(file->limit - file->got);
	}
	size_t got = 0;
	ma_result result = file->read(file->user, out, bytes, &got);
	const ma_uint64 before = file->got;
	for (size_t i = 0; before + i < sizeof(file->head) && i < got; i++) file->head[before + i] = ((const ma_uint8*)out)[i];
	file->got += got;
	if (before < sizeof(file->head) && file->got >= sizeof(file->head)) {
		const ma_uint8* h = file->head;
		ma_uint64 tag = 0;
		// As dr_mp3 reads the size of the tag it skips, with no check of the header's other bytes and each size byte's top bit dropped: a tag it skips that this took as none bounded the search from the stream's start, refusing an MP3 whose first frame follows a tag of 64 KB or more.
		if (h[0] == 'I' && h[1] == 'D' && h[2] == '3')
			tag = 10 + ((ma_uint64)(h[6] & 0x7F) << 21 | (ma_uint64)(h[7] & 0x7F) << 14 | (ma_uint64)(h[8] & 0x7F) << 7 | (h[9] & 0x7F)) + (h[5] & 0x10? 10 : 0); // With its footer, flagged.
		file->limit = tag + nvgt_mp3_search_bytes;
	}
	if (bytes_read) *bytes_read = got;
	return result;
}
static ma_result nvgt_mp3_open_seek(void* user, ma_int64 offset, ma_seek_origin origin) {
	nvgt_mp3_open_file* file = (nvgt_mp3_open_file*)user;
	ma_result result = file->seek(file->user, offset, origin);
	if (result == MA_SUCCESS) { // Where it now is, the search measured from there: past a tag dr_mp3 skips, so that it stops 64 KB past the tag rather than as far again as the tag claims to be long, and back at the start after the bytes dr_mp3 read to look for one, rather than counting them as searched.
		if (origin == ma_seek_origin_end) file->sized = true;
		else if (origin == ma_seek_origin_current) file->got = offset < 0 && (ma_uint64)-offset > file->got? 0 : file->got + offset;
		else if (origin == ma_seek_origin_start && offset >= 0) file->got = (ma_uint64)offset;
	}
	return result;
}
static ma_result nvgt_mp3_open_tell(void* user, ma_int64* cursor) {
	nvgt_mp3_open_file* file = (nvgt_mp3_open_file*)user;
	return file->tell(file->user, cursor);
}
// dr_mp3 skips the frame of a LAME or Xing header by setting its stream cursor to that frame's end, forgetting what it had read past it, so that its clamp at the audio's end, which keeps it out of an ID3v1 tag, let the tag through, and the last MPEG frame, not followed by another, became silence. Put right as an MP3 opens, on every route to it through MiniAudio's table of its backend.
static ma_result nvgt_mp3_backend_init(void* user_data, ma_read_proc on_read, ma_seek_proc on_seek, ma_tell_proc on_tell, void* read_user_data, const ma_decoding_backend_config* config, const ma_allocation_callbacks* allocation_callbacks, ma_data_source** backend) {
	// Opened through the wrapped callbacks, which bound its search for a first frame (see nvgt_mp3_search_bytes), then given its own back, as it is read through them for good.
	nvgt_mp3_open_file wrapped{on_read, on_seek, on_tell, read_user_data};
	ma_result result = ma_decoding_backend_init__mp3(user_data, nvgt_mp3_open_read, on_seek? nvgt_mp3_open_seek : NULL, on_tell? nvgt_mp3_open_tell : NULL, &wrapped, config, allocation_callbacks, backend);
	if (result == MA_SUCCESS) {
		ma_mp3* opened = (ma_mp3*)*backend;
		opened->onRead = on_read;
		opened->onSeek = on_seek;
		opened->onTell = on_tell;
		opened->pReadSeekTellUserData = read_user_data;
		ma_dr_mp3* mp3 = &opened->dr;
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
// The most of a WAV that is read to find where its data ends, when its end can't be found otherwise: within the 16 MiB a source that can't seek keeps of its start while a decoder opens it (see prebuffer_istreambuf::OPEN_CAP).
static const ma_uint64 nvgt_wav_count_bytes = 15 * 1024 * 1024;
// A WAV's own callbacks, wrapped while dr_wav opens it: for a data size of 0xFFFFFFFF, as a WAV written to a pipe or streamed live has, it reads a source whose end it can't seek to until it ends, an endless one for good. Past the bytes above it is refused, as one of a size of 0 is.
struct nvgt_wav_open_file {
	ma_read_proc read;
	ma_seek_proc seek;
	ma_tell_proc tell;
	void* user;
	bool sized = false; // A seek to its end was made, so that it ends.
	bool endless = false; // It went on past nvgt_wav_count_bytes.
	ma_uint64 got = 0; // Read since it was last sought from its start, as it is to the data.
};
static ma_result nvgt_wav_open_read(void* user, void* out, size_t bytes, size_t* bytes_read) {
	nvgt_wav_open_file* file = (nvgt_wav_open_file*)user;
	size_t got = 0;
	const ma_result result = file->read(file->user, out, bytes, &got);
	if (!file->sized && file->got >= nvgt_wav_count_bytes && got) {
		file->endless = true;
		if (bytes_read) *bytes_read = 0;
		return MA_AT_END;
	}
	file->got += got;
	if (bytes_read) *bytes_read = got;
	return result;
}
static ma_result nvgt_wav_open_seek(void* user, ma_int64 offset, ma_seek_origin origin) {
	nvgt_wav_open_file* file = (nvgt_wav_open_file*)user;
	// A step of 2 GB (see seek_step_in_stream()), which MiniAudio's memory cuts short at its end, reporting it made.
	const bool step = origin == ma_seek_origin_current && offset >= 0x7FFFFFFF;
	ma_int64 before = 0, after = 0;
	if (step && (!file->tell || file->tell(file->user, &before) != MA_SUCCESS)) return MA_BAD_SEEK;
	const ma_result result = file->seek(file->user, offset, origin);
	if (step && result == MA_SUCCESS && (file->tell(file->user, &after) != MA_SUCCESS || after - before != offset)) return MA_BAD_SEEK;
	if (result == MA_SUCCESS && origin == ma_seek_origin_end) file->sized = true;
	if (result == MA_SUCCESS && origin == ma_seek_origin_start) file->got = 0;
	return result;
}
static ma_result nvgt_wav_open_tell(void* user, ma_int64* cursor) {
	nvgt_wav_open_file* file = (nvgt_wav_open_file*)user;
	return file->tell(file->user, cursor);
}
// A WAV whose data size is 0, as from a recording that never closed its header, reads to the end of its file, as other players take it, rather than as empty. Only for samples of a fixed size. A source that can't seek is read to its end and come back to, as dr_wav does for a size of 0xFFFFFFFF, which such a source can do within what it keeps of its start; one too long for that, or one that doesn't end, as a live stream, can't be opened, rather than holding its opening for as long as it lasts.
// Opens a WAV into the struct given, which is left uninitialized when it can't be.
static ma_result nvgt_wav_open(ma_wav* opened, ma_read_proc on_read, ma_seek_proc on_seek, ma_tell_proc on_tell, void* read_user_data, const ma_decoding_backend_config* config, const ma_allocation_callbacks* allocation_callbacks) {
	nvgt_wav_open_file wrapped{on_read, on_seek, on_tell, read_user_data};
	ma_result result = ma_wav_init(nvgt_wav_open_read, on_seek? nvgt_wav_open_seek : NULL, on_tell? nvgt_wav_open_tell : NULL, &wrapped, config, allocation_callbacks, opened);
	if (result != MA_SUCCESS) return result;
	opened->onRead = on_read;
	opened->onSeek = on_seek;
	opened->onTell = on_tell;
	opened->pReadSeekTellUserData = read_user_data;
	if (wrapped.endless) {
		ma_wav_uninit(opened, allocation_callbacks);
		return MA_INVALID_FILE;
	}
	ma_dr_wav* wav = &opened->dr;
	// The frames its data holds, rather than those an RF64's or a Wave64's own count of them claims, which some writers count for each channel: read past its data, it gave silence, or ended before its data did. An AIFF's count ends data that is padded.
	const ma_uint32 frame_bytes = ma_dr_wav_get_bytes_per_pcm_frame(wav);
	if (frame_bytes && (wav->translatedFormatTag == MA_DR_WAVE_FORMAT_PCM || wav->translatedFormatTag == MA_DR_WAVE_FORMAT_IEEE_FLOAT || wav->translatedFormatTag == MA_DR_WAVE_FORMAT_ALAW || wav->translatedFormatTag == MA_DR_WAVE_FORMAT_MULAW)) {
		const ma_uint64 held = wav->dataChunkDataSize / frame_bytes;
		if (wav->container != ma_dr_wav_container_aiff || wav->totalPCMFrameCount > held) wav->totalPCMFrameCount = held;
	}
	const bool plain = wav->translatedFormatTag == MA_DR_WAVE_FORMAT_PCM || wav->translatedFormatTag == MA_DR_WAVE_FORMAT_IEEE_FLOAT;
	if (wav->dataChunkDataSize || !plain || !wav->fmt.blockAlign) return result;
	ma_uint64 size = 0;
	ma_int64 end = 0;
	if (on_tell && on_seek(read_user_data, 0, ma_seek_origin_end) == MA_SUCCESS) {
		const bool told = on_tell(read_user_data, &end) == MA_SUCCESS;
		const bool back = on_seek(read_user_data, (ma_int64)wav->dataChunkDataPos, ma_seek_origin_start) == MA_SUCCESS;
		if (!back) { // Left at the end, it read nothing while it told the length counted.
			ma_wav_uninit(opened, allocation_callbacks);
			return MA_INVALID_FILE;
		}
		if (!told || (ma_uint64)end <= wav->dataChunkDataPos) return result;
		size = (ma_uint64)end - wav->dataChunkDataPos;
	} else {
		bool ended = false;
		while (!ended && size <= nvgt_wav_count_bytes) { // A read past it too, which sees the end of one of just that size.
			ma_uint8 block[4096];
			size_t got = 0;
			const ma_result read = on_read(read_user_data, block, sizeof(block), &got);
			size += got;
			if (read != MA_SUCCESS || got < sizeof(block)) ended = true;
		}
		if (!ended || on_seek(read_user_data, (ma_int64)wav->dataChunkDataPos, ma_seek_origin_start) != MA_SUCCESS) {
			ma_wav_uninit(opened, allocation_callbacks);
			return MA_INVALID_FILE;
		}
	}
	const ma_uint64 frames = size / wav->fmt.blockAlign;
	wav->dataChunkDataSize = frames * wav->fmt.blockAlign;
	wav->bytesRemaining = wav->dataChunkDataSize;
	wav->totalPCMFrameCount = frames;
	return result;
}
static ma_result nvgt_wav_backend_init(void* user_data, ma_read_proc on_read, ma_seek_proc on_seek, ma_tell_proc on_tell, void* read_user_data, const ma_decoding_backend_config* config, const ma_allocation_callbacks* allocation_callbacks, ma_data_source** backend) {
	ma_wav* wav = (ma_wav*)ma_malloc(sizeof(ma_wav), allocation_callbacks);
	if (!wav) return MA_OUT_OF_MEMORY;
	const ma_result result = nvgt_wav_open(wav, on_read, on_seek, on_tell, read_user_data, config, allocation_callbacks);
	if (result == MA_SUCCESS) *backend = wav;
	else ma_free(wav, allocation_callbacks);
	return result;
}
// One in memory, opened as any other: dr_wav's own, whose seeks stop at its end and report success, took the billions of steps of 2 GB a damaged size makes (see seek_step_in_stream()), and one of a data size of 0 was empty.
struct nvgt_wav_memory {
	ma_wav wav; // First: MiniAudio takes this struct for it.
	const ma_uint8* data;
	size_t size;
	size_t at;
};
static ma_result nvgt_wav_memory_read(void* user, void* out, size_t bytes, size_t* bytes_read) {
	nvgt_wav_memory* memory = (nvgt_wav_memory*)user;
	const size_t got = ma_min(bytes, memory->size - memory->at);
	if (got) memcpy(out, memory->data + memory->at, got);
	memory->at += got;
	if (bytes_read) *bytes_read = got;
	return got? MA_SUCCESS : MA_AT_END;
}
static ma_result nvgt_wav_memory_seek(void* user, ma_int64 offset, ma_seek_origin origin) {
	nvgt_wav_memory* memory = (nvgt_wav_memory*)user;
	const ma_int64 from = origin == ma_seek_origin_start? 0 : origin == ma_seek_origin_current? (ma_int64)memory->at : (ma_int64)memory->size;
	if (offset < -from || offset > (ma_int64)memory->size - from) return MA_BAD_SEEK;
	memory->at = (size_t)(from + offset);
	return MA_SUCCESS;
}
static ma_result nvgt_wav_memory_tell(void* user, ma_int64* cursor) {
	*cursor = (ma_int64)((nvgt_wav_memory*)user)->at;
	return MA_SUCCESS;
}
static ma_result nvgt_wav_backend_init_memory(void* user_data, const void* data, size_t size, const ma_decoding_backend_config* config, const ma_allocation_callbacks* allocation_callbacks, ma_data_source** backend) {
	nvgt_wav_memory* memory = (nvgt_wav_memory*)ma_malloc(sizeof(nvgt_wav_memory), allocation_callbacks);
	if (!memory) return MA_OUT_OF_MEMORY;
	memory->data = (const ma_uint8*)data;
	memory->size = size;
	memory->at = 0;
	const ma_result result = nvgt_wav_open(&memory->wav, nvgt_wav_memory_read, nvgt_wav_memory_seek, nvgt_wav_memory_tell, memory, config, allocation_callbacks);
	if (result == MA_SUCCESS) *backend = memory;
	else ma_free(memory, allocation_callbacks);
	return result;
}
static const bool nvgt_wav_backend_installed = (g_ma_decoding_backend_vtable_wav.onInit = nvgt_wav_backend_init, g_ma_decoding_backend_vtable_wav.onInitMemory = nvgt_wav_backend_init_memory, true);
#define RND_IMPLEMENTATION
#include "rnd.h"
#define SPEECH_IMPLEMENTATION
#include "speech.h"
#define THREAD_IMPLEMENTATION
#include "thread.h"
