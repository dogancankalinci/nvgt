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
#include <string>
#include <ankerl/unordered_dense.h>
#include <unordered_set>
#include <vector>
#include <angelscript.h>
#include <reactphysics3d/mathematics/Vector3.h>
#include <scriptany.h>
#include <mutex>
#include "pathfinder.h"
#define total_frame_sizes 3

class coordinate_map;

class map_frame;
class map_area {
	int ref_count;
	bool gc_flag = false;
	bool is_unfiltered(asIScriptFunction* filter_callback);
public:
	coordinate_map* parent; // not a reference the area holds: read and changed under coordinate_map::links_mutex() only (see get_map())
	coordinate_map* get_map() const;
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
	std::vector<map_frame*> frames;
	map_area(coordinate_map* p, float minx, float max, float miny, float maxy, float minz, float maxz, float rotation, CScriptAny* primary_data, const std::string& data1, const std::string& data2, const std::string& data3, int priority, asINT64 flags);
	void add_ref();
	void release();
	// The garbage collector's behaviours (see coordinate_map's): primary_data is a reference the area holds, often to the object that holds the map.
	int get_ref_count() { return ref_count; }
	void set_gc_flag() { gc_flag = true; }
	bool get_gc_flag() { return gc_flag; }
	void enum_references(asIScriptEngine* engine);
	void release_all_references(asIScriptEngine* engine);
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
	int add_areas_for_range(std::vector<map_area*>& local_areas, std::unordered_set<map_area*>& taken, float minx, float maxx, float miny, float maxy, float minz, float maxz, float d = 0.0, int p = -1, asIScriptFunction* filter_callback = NULL, asINT64 flags = 0, asINT64 excluded_flags = 0);
	void reset(std::vector<map_area*>& held);
};
class coordinate_map {
	ankerl::unordered_dense::map<hashpoint, map_frame*, hashpoint_hash, hashpoint_equals> frames[total_frame_sizes];
	int ref_count;
	bool gc_flag = false;
	bool collected = false; // given to the garbage collector, which then holds a reference of its own
	asILockableSharedBool* weak_flag = nullptr; // see get_weakref_flag()
	friend coordinate_map* new_coordinate_map();
public:
	// One lock for every map, held while the frames' lists of areas, a map's set of areas or an area's parent change and while the garbage collector reads the frames, and around a map's last release. Every map and area is now freed by the collector's last release, on its own thread with garbage_collect_mode 3 or on any thread that makes a garbage-collected object, so a map going there cleared the parent of the areas a script still held while that script read it, and an area going there took itself out of a map the script was adding to. A lock of the map's own went with the map. Never destroyed, never held while script code runs.
	static std::recursive_mutex& links_mutex();
	std::unordered_set<map_area*> areas;
	coordinate_map() : ref_count(1) {}
	void add_ref();
	void release();
	// The garbage collector's behaviours. The frames hold references to the areas, whose primary data is often the object that holds the map: a cycle the collector couldn't see while coordinate_map and coordinate_map_area weren't its types, so such an object was never freed (its destructor never ran) once the script let go of it.
	int get_ref_count() { return ref_count; }
	int collector_refs() const { return collected ? 1 : 0; }
	// An area's link to its map is a weak reference (the area holds none), which map_area::get_map() turns strong. The collector marks this flag dead, under its lock, once it has found the map to be garbage and before it breaks it: get_map() handed out a map the collector then emptied (reset() as its RELEASEREFS) between the steps of breaking the cycle, on the collector's thread or between incremental steps on the script's. Made when first asked for, under links_mutex().
	asILockableSharedBool* get_weakref_flag();
	void set_gc_flag() { gc_flag = true; }
	bool get_gc_flag() { return gc_flag; }
	void enum_references(asIScriptEngine* engine);
	void release_all_references(asIScriptEngine* engine) { reset(); }
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
