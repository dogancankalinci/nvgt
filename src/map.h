/* map.h - coordinate map implementation header
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

#pragma once
#include <cstdint>
#include <string>
#include <ankerl/unordered_dense.h>
#include <vector>
#include <angelscript.h>
#include <reactphysics3d/mathematics/Vector3.h>
#include <scriptany.h>
#include "pathfinder.h"
// Hash for the keys of coordinate_map's frame tables. Those keys are frame origins, so every coordinate is a multiple of
// the frame size (32, 256 or 8192) and its low bits are always zero. hashpoint_hash builds a Morton code from only the
// low 10 bits of each coordinate, which for these keys throws away everything that tells two frames apart: every frame
// of an area that runs along one axis landed on the same hash, and each insertion then walked all of the colliding
// entries, so registering one long area took time that grew with the square of its length. This mixes all 96 bits.
struct map_frame_key_hash {
	using is_avalanching = void;
	static std::uint64_t mix(std::uint64_t v) {
		v += 0x9e3779b97f4a7c15ULL;
		v = (v ^ (v >> 30)) * 0xbf58476d1ce4e5b9ULL;
		v = (v ^ (v >> 27)) * 0x94d049bb133111ebULL;
		return v ^ (v >> 31);
	}
	std::uint64_t operator()(const hashpoint& p) const noexcept {
		std::uint64_t xy = static_cast<std::uint64_t>(static_cast<std::uint32_t>(p.x)) | (static_cast<std::uint64_t>(static_cast<std::uint32_t>(p.y)) << 32);
		return mix(mix(xy) ^ static_cast<std::uint64_t>(static_cast<std::uint32_t>(p.z)));
	}
};
#define total_frame_sizes 3

class coordinate_map;

class map_frame;
class map_area {
	int ref_count;
	bool is_unfiltered(asIScriptFunction* filter_callback);
public:
	coordinate_map* parent;
	float minx;
	float maxx;
	float miny;
	float maxy;
	float minz;
	float maxz;
	float rotation;
	reactphysics3d::Vector3 center;
	int framesize;
	CScriptAny* primary_data;
	std::string data1;
	std::string data2;
	std::string data3;
	int priority;
	asINT64 flags;
	bool framed;
	bool tmp_adding_to_result;
	std::vector<map_frame*> frames;
	map_area(coordinate_map* p, float minx, float max, float miny, float maxy, float minz, float maxz, float rotation, CScriptAny* primary_data, const std::string& data1, const std::string& data2, const std::string& data3, int priority, asINT64 flags);
	void add_ref();
	void release();
	void unframe();
	void reframe();
	void set(float minx, float maxx, float miny, float maxy, float minz, float maxz, float rotation);
	void set_area(float minx, float maxx, float miny, float maxy, float minz, float maxz);
	void set_rotation(float rotation);
	bool is_in_area(float x, float y, float z, float d = 0.0, asIScriptFunction* filter_callback = NULL, asINT64 required_flags = 0, asINT64 excluded_flags = 0);
	bool is_in_area_range(float minx, float maxx, float miny, float maxy, float minz, float maxz, float d = 0.0, float r = 0.0, asIScriptFunction* filter_callback = NULL, asINT64 required_flags = 0, asINT64 excluded_flags = 0);
};
class map_frame {
public:
	std::vector<map_area*> areas;
	int size;
	int add_areas_for_point(std::vector<map_area*>& local_areas, float x, float y, float z, float d = 0.0, int p = -1, asIScriptFunction* filter_callback = NULL, asINT64 flags = 0, asINT64 excluded_flags = 0);
	int add_areas_for_range(std::vector<map_area*>& local_areas, float minx, float maxx, float miny, float maxy, float minz, float maxz, float d = 0.0, int p = -1, asIScriptFunction* filter_callback = NULL, asINT64 flags = 0, asINT64 excluded_flags = 0);
	void reset();
};
class coordinate_map {
	ankerl::unordered_dense::map<hashpoint, map_frame*, map_frame_key_hash, hashpoint_equals> frames[total_frame_sizes];
	int ref_count;
public:
	coordinate_map() : ref_count(1) {}
	void add_ref();
	void release();
	reactphysics3d::Vector3 get_frame_coordinates(int x, int y, int z, int size);
	map_frame* get_frame(int x, int y, int z, int size, bool create = true);
	map_area* add_area(float minx, float maxx, float miny, float maxy, float minz, float maxz, float rotation, CScriptAny* primary_data, const std::string& data1, const std::string& data2, const std::string& data3, int priority, asINT64 flags = 0);
	void get_areas(float minx, float maxx, float miny, float maxy, float minz, float maxz, float d, std::vector<map_area*>& local_areas, bool priority_check = true, asIScriptFunction* filter_callback = NULL, asINT64 flags = 0, asINT64 excluded_flags = 0);
	CScriptArray* get_areas_script(float x, float y, float z, float d = 0.0, asIScriptFunction* filter_callback = NULL, asINT64 flags = 0, asINT64 excluded_flags = 0);
	CScriptArray* get_areas_in_range_script(float minx, float maxx, float miny, float maxy, float minz, float maxz, float d = 0.0, asIScriptFunction* filter_callback = NULL, asINT64 flags = 0, asINT64 excluded_flags = 0);
	map_area* get_area(float x, float y, float z, int max_priority = -1, float d = 0.0, asIScriptFunction* filter_callback = NULL, asINT64 flags = 0, asINT64 excluded_flags = 0);
	void reset();
};

void RegisterScriptMap(asIScriptEngine* engine);
