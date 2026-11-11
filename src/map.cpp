/* map.cpp - coordinate map implementation code
 * At this time, anything having to do with rotation may be unstable.
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

#define NOMINMAX
#define _USE_MATH_DEFINES
#include <cmath>
#include "map.h"
#include <algorithm>
#include <obfuscate.h>
#include <limits>
#include <tuple>
#include "scriptstuff.h"
#include "nvgt_angelscript.h" // get_array_type()

using reactphysics3d::Vector3;

Vector3 rotate(const Vector3& p, const Vector3& o, double theta, bool maintain_z = true) {
	Vector3 r;
	// The right angles give exactly 0 here. Comparing the angle in whole degrees also took for 0 the cosine of everything up to 91 degrees and the sine up to 181, and depended on a cast of a value that can be out of an int's range.
	double c = cos(theta), s = sin(theta);
	Vector3 cs = Vector3(std::fabs(c) < 1e-6 ? 0 : c, std::fabs(s) < 1e-6 ? 0 : s, 0);
	r.x = (cs.x * (p.x - o.x)) - (cs.y * (p.y - o.y)) + o.x;
	r.y = (cs.y * (p.x - o.x)) + (cs.x * (p.y - o.y)) + o.y;
	if (maintain_z)
		r.z = p.z;
	return r;
}
Vector3 get_center(Vector3 _min, Vector3 _max) {
	if (_min == _max || _max.x - _min.x < 2 && _max.y - _min.y < 2 && _max.z - _min.z < 2)
		return _min;
	return Vector3(_min.x + (_max.x - _min.x) / 2.0, _min.y + (_max.y - _min.y) / 2.0, _min.z + (_max.z - _min.z) / 2.0);
}
Vector3 get_center(double minx, double maxx, double miny, double maxy, double minz, double maxz) {
	if (minx == maxx && miny == maxy && minz == maxz || maxx - minx < 2 && maxy - miny < 2 && maxz - minz < 2)
		return Vector3(minx, miny, minz);
	return Vector3(minx + (maxx - minx) / 2.0, miny + (maxy - miny) / 2.0, minz + (maxz - minz) / 2.0);
}

// following function in a round about way from https://stackoverflow.com/questions/10962379/how-to-check-intersection-between-2-rotated-rectangles
bool polygons_intersect(const std::vector<Vector3>& a, const std::vector<Vector3>& b) {
	for (int polyi = 0; polyi < 2; ++polyi) {
		const std::vector<Vector3>& polygon = polyi == 0 ? a : b;
		for (int i1 = 0; i1 < polygon.size(); ++i1) {
			const int i2 = (i1 + 1) % polygon.size();
			const double normalx = polygon[i2].y - polygon[i1].y;
			const double normaly = polygon[i1].x - polygon[i2].x;
			double minA = (std::numeric_limits<double>::max());
			double maxA = (std::numeric_limits<double>::lowest());
			for (int ai = 0; ai < a.size(); ++ai) {
				const double projected = normalx * a[ai].x + normaly * a[ai].y;
				if (projected < minA) minA = projected;
				if (projected > maxA) maxA = projected;
			}
			double minB = std::numeric_limits<double>::max();
			double maxB = std::numeric_limits<double>::lowest();
			for (int bi = 0; bi < b.size(); ++bi) {
				const double projected = normalx * b[bi].x + normaly * b[bi].y;
				if (projected < minB) minB = projected;
				if (projected > maxB) maxB = projected;
			}
			if (maxA <= minB || maxB <= minA) // Boxes end where the next one starts, see boxes_intersect.
				return false;
		}
	}
	return true;
}
// A box is taken as a map area is: from min up to but not including max + 1, turned by its angle about its center. The corners were each box's min plus or minus its center, which is the box's half size only for a box with one corner at the origin, so boxes far from the origin all looked as if they intersected.
static std::vector<Vector3> box_corners(float minx, float maxx, float miny, float maxy, float r) {
	Vector3 c((double(minx) + maxx + 1) / 2, (double(miny) + maxy + 1) / 2, 0), h((double(maxx) + 1 - minx) / 2, (double(maxy) + 1 - miny) / 2, 0), o(0, 0, 0);
	return {c + rotate(Vector3(-h.x, -h.y, 0), o, r), c + rotate(Vector3(-h.x, h.y, 0), o, r), c + rotate(Vector3(h.x, h.y, 0), o, r), c + rotate(Vector3(h.x, -h.y, 0), o, r)};
}
bool boxes_intersect(float minx1, float maxx1, float miny1, float maxy1, float r1, float minx2, float maxx2, float miny2, float maxy2, float r2) {
	return polygons_intersect(box_corners(minx1, maxx1, miny1, maxy1, r1), box_corners(minx2, maxx2, miny2, maxy2, r2));
}

static asITypeInfo* g_MapAreaArrayType = NULL;
static asITypeInfo* g_coordinate_map_type = nullptr; // for NotifyGarbageCollectorOfNewObject
static asITypeInfo* g_map_area_type = nullptr;

int frame_sizes[] = {8192, 256, 32, 0};
int get_frame_size(float x, float y, float z) {
	for (int i = 0; frame_sizes[i]; i++) {
		if (i == total_frame_sizes - 1 || x >= frame_sizes[i] || y >= frame_sizes[i] || z >= frame_sizes[i]) return i;
	}
	return total_frame_sizes - 1;
}

// An area is put in every frame it touches. A coordinate that is infinite, NaN or past what an int holds (reframe() walks them in ints) walked the frames without end, adding to the map until memory ran out or the heap was corrupted, and an area across much of that range took as long: such an area is refused. 16 million frames are about 10^14 square units with the largest frames.
static void check_map_area(float minx, float maxx, float miny, float maxy, float minz, float maxz) {
	bool fits = true;
	for (float v : {minx, maxx, miny, maxy, minz, maxz}) fits = fits && std::isfinite(v) && std::fabs(v) <= 1000000000.0f;
	if (fits) {
		double size = frame_sizes[get_frame_size(maxx - minx, maxy - miny, maxz - minz)];
		fits = (std::max(double(maxx) - minx, 0.0) / size + 2) * (std::max(double(maxy) - miny, 0.0) / size + 2) * (std::max(double(maxz) - minz, 0.0) / size + 2) <= 16777216.0;
	}
	if (!fits) throw std::invalid_argument("coordinate_map area out of range");
}

static bool map_area_sort(map_area* a1, map_area* a2) {
	return a1 == NULL || a2 == NULL || a1->priority < a2->priority;
}

map_area::map_area(coordinate_map* p, float minx, float maxx, float miny, float maxy, float minz, float maxz, float rotation, CScriptAny* primary_data, const std::string& data1, const std::string& data2, const std::string& data3, int priority, asINT64 flags) : parent(p), minx(minx), maxx(maxx), miny(miny), maxy(maxy), minz(minz), maxz(maxz), rotation(rotation), framesize(0), primary_data(primary_data), data1(data1), data2(data2), data3(data3), priority(priority), flags(flags), framed(false), ref_count(1) {
	center = get_center(minx, maxx, miny, maxy, minz, maxz);
	reframe();
}
void map_area::add_ref() {
	gc_flag = false;
	asAtomicInc(ref_count);
}
void map_area::release() {
	gc_flag = false;
	if (asAtomicDec(ref_count) < 1) {
		if (primary_data)
			primary_data->Release();
		if (parent) parent->areas.erase(this);
		delete this;
	}
}
void map_area::enum_references(asIScriptEngine* engine) {
	if (primary_data) engine->GCEnumCallback(primary_data);
}
void map_area::release_all_references(asIScriptEngine* engine) {
	CScriptAny* data = primary_data;
	primary_data = nullptr;
	if (data) data->Release();
}
bool map_area::is_unfiltered(asIScriptFunction* filter_callback) {
	if (filter_callback == NULL) return true;
	asIScriptContext* ACtx = asGetActiveContext();
	if (script_callbacks_stopped(ACtx)) return true; // exit() was called since the script called the coordinate_map function, by the filter for an earlier area or by another thread: no more filter calls; the result is never used.
	bool new_context = ACtx == NULL || ACtx->PushState() < 0;
	// A context of the pool for each call, given back after it, as the other callback sites do. One context kept in a static
	// for every such call was shared by the threads that got there at once and never given back (it outlived the script's
	// module, holding the last filter it ran).
	asIScriptContext* ctx = new_context ? g_ScriptEngine->RequestContext() : ACtx;
	bool ret = true;
	if (!ctx || ctx->Prepare(filter_callback) < 0 || ctx->SetArgObject(0, this) < 0 || execute_nested(ctx) != asEXECUTION_FINISHED) {
		if (new_context && ctx) g_ScriptEngine->ReturnContext(ctx);
		else if (!new_context) pop_nested_state(ctx);
		return true;
	}
	profiler_forget_last_function();
	ret = ctx->GetReturnByte() != 0;
	if (new_context) g_ScriptEngine->ReturnContext(ctx);
	else pop_nested_state(ctx);
	return ret;
}
void map_area::unframe() {
	if (!parent || !framed) return; // framesize says nothing here: 0 is the largest size, and an area that large stayed in its frames, so unframe() did nothing and set() left it where it was, or nowhere as far as a search could tell.
	std::lock_guard<std::recursive_mutex> lock(parent->frames_mtx); // release() below never lets go of the last reference, so no script runs under it
	for (map_frame* f : frames) {
		auto it = std::find(f->areas.begin(), f->areas.end(), this);
		while (it != f->areas.end()) {
			f->areas.erase(it);
			if (ref_count > 1) release();
			it = std::find(f->areas.begin(), f->areas.end(), this);
		}
	}
	framed = false;
	frames.clear();
}
void map_area::reframe() {
	if (!parent || framed) return;
	framesize = get_frame_size(maxx - minx, maxy - miny, maxz - minz); // Each time, as set() can have changed the size: check_map_area() goes by the size for the area as it is now, and a small area made large by set() kept the smallest frames, up to hundreds of millions of them.
	Vector3 MIN = Vector3(minx, miny, minz);
	Vector3 MAX = Vector3(maxx, maxy, maxz);
	std::lock_guard<std::recursive_mutex> lock(parent->frames_mtx);
	if (rotation > 0) {
		Vector3 d = MAX - MIN;
		std::vector<Vector3> points = {rotate(MIN, center, rotation), rotate(Vector3(MIN.x + d.x, MIN.y, 0), center, rotation), rotate(Vector3(MIN.x, MIN.y + d.y, 0), center, rotation), rotate(Vector3(MIN.x + d.x, MIN.y + d.y, 0), center, rotation)};
		for (int i = 0; i < points.size(); i++) {
			if (points[i].x < MIN.x) MIN.x = points[i].x - 1;
			else if (points[i].x > MAX.x) MAX.x = points[i].x + 1;
			if (points[i].y < MIN.y) MIN.y = points[i].y - 1;
			else if (points[i].y > MAX.y) MAX.y = points[i].y + 1;
		}
	}
	for (int x = MIN.x; x <= MAX.x + frame_sizes[framesize]; x += frame_sizes[framesize]) {
		for (int y = MIN.y; y <= MAX.y + frame_sizes[framesize]; y += frame_sizes[framesize]) {
			for (int z = MIN.z; z <= MAX.z + frame_sizes[framesize]; z += frame_sizes[framesize]) {
				map_frame* f = parent->get_frame(x, y, z, framesize);
				if (!f) continue;
				add_ref();
				f->areas.push_back(this);
				frames.push_back(f);
			}
		}
	}
	framed = true;
}
void map_area::set(float minx, float maxx, float miny, float maxy, float minz, float maxz, float rotation) {
	check_map_area(minx, maxx, miny, maxy, minz, maxz);
	bool was_framed = framed;
	unframe();
	this->minx = minx;
	this->maxx = maxx;
	this->miny = miny;
	this->maxy = maxy;
	this->minz = minz;
	this->maxz = maxz;
	this->rotation = rotation;
	center = get_center(minx, maxx, miny, maxy, minz, maxz);
	if (was_framed) reframe();
}
void map_area::set_area(float minx, float maxx, float miny, float maxy, float minz, float maxz) {
	set(minx, maxx, miny, maxy, minz, maxz, rotation);
}
void map_area::set_rotation(float rotation) {
	set(minx, maxx, miny, maxy, minz, maxz, rotation);
}
bool map_area::is_in_area(float x, float y, float z, float d, asIScriptFunction* filter_callback, asINT64 required_flags, asINT64 excluded_flags) {
	bool flag_filter = ((flags & required_flags) == required_flags) && ((flags & excluded_flags) == 0);
	if (!flag_filter) return false;
	if (z < minz - d || z >= maxz + d + 1) return false;
	if (d > 1 && (z < minz || z >= maxz + 1)) {
		int longest = maxx - minx;
		if (maxy - miny > longest) longest = maxy - miny;
		if (longest < 1) longest = 1;
		return x >= center.x - d - longest && x <= center.x + d + longest && y >= center.y - d - longest && y <= center.y + d + longest && is_unfiltered(filter_callback);
	}
	Vector3 border = Vector3(1, 1, 1);
	if (rotation > 0) {
		Vector3 r = rotate(Vector3(x, y, z), center, rotation);
		x = r.x;
		y = r.y;
		//border=rotate(border, Vector3(0, 0, 0), rotation);
	}
	if (x < minx - d + (border.x < 0 ? border.x : 0) || x >= maxx + d + (border.x > 0 ? border.x : 0)) return false;
	if (y < miny - d + (border.y < 0 ? border.y : 0) || y >= maxy + d + (border.y > 0 ? border.y : 0)) return false;
	if (z < minz - d + (border.z < 0 ? border.z : 0) || z >= maxz + d + (border.z > 0 ? border.z : 0)) return false;
	return is_unfiltered(filter_callback);
}
bool map_area::is_in_area_range(float minx, float maxx, float miny, float maxy, float minz, float maxz, float d, float r, asIScriptFunction* filter_callback, asINT64 required_flags, asINT64 excluded_flags) {
	bool flag_filter = ((flags & required_flags) == required_flags) && ((flags & excluded_flags) == 0);
	if (!flag_filter) return false;
	if (minx == maxx && miny == maxy && minz == maxz) return is_in_area(minx, miny, minz, d, filter_callback);
	else if (this->minx == this->maxx && this->miny == this->maxy && this->minz == this->maxz) {
		Vector3 R = Vector3(this->minx, this->maxy, this->minz);
		if (r > 0)
			R = rotate(R, get_center(minx, maxx, miny, maxy, minz, maxz), r);
		return R.x >= minx - d && R.x < maxx + d + 1.0 && R.y >= miny - d && R.y < maxy + d + 1.0 && R.z >= minz - d && R.z < maxz + d + 1.0 && is_unfiltered(filter_callback);
	}
	return this->minz >= minz - d && this->maxz < maxz + d + 1.0 && this->miny >= miny - d && this->maxy < maxy + d + 1.0 && this->minx >= minx - d && this->maxx < maxx + d + 1.0 && is_unfiltered(filter_callback);
}

// The filter callback runs script, which may add areas, or reset() the map and delete this very frame, while we iterate. So iterate over a snapshot that holds its own references: whatever the callback does to the live vector, the areas we are visiting stay valid until we are done.
static std::vector<map_area*> snapshot_areas(const std::vector<map_area*>& areas) {
	std::vector<map_area*> copy(areas);
	for (map_area* a : copy) a->add_ref();
	return copy;
}
static void release_snapshot(std::vector<map_area*>& copy) {
	for (map_area* a : copy) a->release();
}
int map_frame::add_areas_for_point(std::vector<map_area*>& local_areas, float x, float y, float z, float d, int p, asIScriptFunction* filter_callback, asINT64 flags, asINT64 excluded_flags) {
	std::vector<map_area*> snap = snapshot_areas(areas);
	for (map_area* a : snap) {
		// framed is checked after the callback, which may have removed this area from the map.
		if (a->priority >= p && a->is_in_area(x, y, z, d, filter_callback, flags, excluded_flags) && a->framed) {
			p = a->priority;
			a->add_ref(); // the result list owns a reference; the callers below release it
			local_areas.push_back(a);
		}
	}
	release_snapshot(snap);
	return p;
}
// taken holds the areas this query has already put in local_areas, so that an area spanning several frames is put there once. It was a mark on each area, cleared once the query ended, which a query run meanwhile by a filter callback on the same map read too: it skipped every area the outer query had already taken.
int map_frame::add_areas_for_range(std::vector<map_area*>& local_areas, std::unordered_set<map_area*>& taken, float minx, float maxx, float miny, float maxy, float minz, float maxz, float d, int p, asIScriptFunction* filter_callback, asINT64 flags, asINT64 excluded_flags) {
	std::vector<map_area*> snap = snapshot_areas(areas);
	for (map_area* a : snap) {
		if (!taken.contains(a) && a->priority >= p && a->is_in_area_range(minx, maxx, miny, maxy, minz, maxz, d, 0, filter_callback, flags, excluded_flags) && a->framed) {
			//p=a->priority; // Object can be reframed at the end of frame with lower priority than something that is higher in the frame, such item will not be included in list if p keeps getting reset.
			a->add_ref(); // the result list owns a reference; the callers below release it
			local_areas.push_back(a);
			taken.insert(a);
		}
	}
	release_snapshot(snap);
	return p;
}
void map_frame::reset(std::vector<map_area*>& held) {
	// An area can outlive this frame (script keeps a handle, or a filter callback reset the map mid-query), so it must not
	// keep links to frames that are about to be freed or its later unframe() writes into them. Only coordinate_map::reset
	// calls this, and it frees every frame of the map, which are all the frames any of its areas can be in, so an area's
	// links can be dropped in one go the first time one of its frames is reached. Searching the list for each frame in
	// turn instead made resetting a map cost the square of the number of frames its largest area spans.
	for (auto i : areas) {
		if (!i->frames.empty()) {
			i->frames.clear();
			i->framed = false;
		}
		held.push_back(i); // the frame's reference, let go of by coordinate_map::reset() once the frames are gone
	}
	areas.clear();
}

void coordinate_map::add_ref() {
	gc_flag = false;
	asAtomicInc(ref_count);
}
void coordinate_map::release() {
	gc_flag = false;
	if (asAtomicDec(ref_count) < 1) {
		for (map_area* a : areas) a->parent = nullptr;
		areas.clear();
		reset();
		delete this;
	}
}
void coordinate_map::enum_references(asIScriptEngine* engine) {
	std::lock_guard<std::recursive_mutex> lock(frames_mtx);
	for (int i = 0; i < total_frame_sizes; i++) {
		for (const auto& f : frames[i]) {
			for (map_area* a : f.second->areas) engine->GCEnumCallback(a); // one reference for each time the area is in a frame (see map_area::reframe)
		}
	}
}
Vector3 coordinate_map::get_frame_coordinates(int x, int y, int z, int size) {
	Vector3 r;
	r.x = 0;
	r.y = 0;
	r.z = 0;
	if (size < 0 || size >= total_frame_sizes) return r;
	r.x -= x & (frame_sizes[size] - 1);
	r.y -= y & (frame_sizes[size] - 1);
	r.z -= z & (frame_sizes[size] - 1);
	return r;
}
map_frame* coordinate_map::get_frame(int x, int y, int z, int size, bool create) {
	if (size < 0 || size >= total_frame_sizes) return NULL;
	x -= x & (frame_sizes[size] - 1);
	y -= y & (frame_sizes[size] - 1);
	z -= z & (frame_sizes[size] - 1);
	auto it = frames[size].find(hashpoint(x, y, z));
	if (it == frames[size].end()) {
		if (!create) return NULL;
		map_frame* mf = new map_frame();
		mf->size = size;
		frames[size][hashpoint(x, y, z)] = mf;
		return mf;
	}
	return it->second;
}
map_area* coordinate_map::add_area(float minx, float maxx, float miny, float maxy, float minz, float maxz, float rotation, CScriptAny* primary_data, const std::string& data1, const std::string& data2, const std::string& data3, int priority, asINT64 flags) {
	try {
		check_map_area(minx, maxx, miny, maxy, minz, maxz);
	} catch (...) {
		if (primary_data) primary_data->Release(); // The area was to own it.
		throw;
	}
	map_area* a = new map_area(this, minx, maxx, miny, maxy, minz, maxz, rotation, primary_data, data1, data2, data3, priority, flags);
	areas.insert(a);
	if (g_map_area_type) g_map_area_type->GetEngine()->NotifyGarbageCollectorOfNewObject(a, g_map_area_type);
	return a;
}
void coordinate_map::get_areas(float minx, float maxx, float miny, float maxy, float minz, float maxz, float d, std::vector<map_area*>& local_areas, bool priority_check, asIScriptFunction* filter_callback, asINT64 flags, asINT64 excluded_flags) {
	// The filter callback can let go of the last handle to this map, which was then deleted while the search went on reading its frames. AngelScript doesn't hold the object of a registered method for the call, so the search holds the map; the areas found hold references of their own.
	struct holder {
		coordinate_map* m;
		holder(coordinate_map* m) : m(m) { m->add_ref(); }
		~holder() { m->release(); }
	} hold(this);
	int p = -1;
	if (minx == maxx && miny == maxy && minz == maxz && d < 1) {
		for (int i = total_frame_sizes - 1; i >= 0; i--) {
			map_frame* f = get_frame(minx, miny, minz, i, false);
			if (!f) continue;
			p = f->add_areas_for_point(local_areas, minx, miny, minz, d, p, filter_callback, flags, excluded_flags);
			if (!priority_check) p = -1;
		}
	} else {
		std::unordered_set<map_area*> taken; // See map_frame::add_areas_for_range.
		for (int i = total_frame_sizes - 1; i >= 0; i--) {
			const int size = frame_sizes[i];
			const double x0 = float(minx - d), x1 = float(maxx + d + size), y0 = float(miny - d), y1 = float(maxy + d + size), z0 = float(minz - d), z1 = float(maxz + d + size);
			if (!(x0 <= x1 && y0 <= y1 && z0 <= z1)) continue;
			// A range past what an int holds never ended (the walk below wrapped around), and a wide one took as long as it has positions, however few frames the map has: such a range looks through the frames there are, in the same order. The callback can change the map, so they are looked up one at a time.
			bool walk = std::max({std::fabs(x0), std::fabs(x1), std::fabs(y0), std::fabs(y1), std::fabs(z0), std::fabs(z1)}) <= 2000000000.0;
			if (walk) walk = ((x1 - x0) / size + 1) * ((y1 - y0) / size + 1) * ((z1 - z0) / size + 1) <= frames[i].size() + 64.0;
			if (!walk) {
				std::vector<hashpoint> found;
				const double fx = std::floor(x0 / size) * size, fy = std::floor(y0 / size) * size, fz = std::floor(z0 / size) * size;
				for (const auto& f : frames[i]) {
					const hashpoint& h = f.first;
					if (h.x >= fx && h.x <= x1 && h.y >= fy && h.y <= y1 && h.z >= fz && h.z <= z1) found.push_back(h);
				}
				std::sort(found.begin(), found.end(), [](const hashpoint& a, const hashpoint& b) { return std::tie(a.x, a.y, a.z) < std::tie(b.x, b.y, b.z); });
				for (const hashpoint& h : found) {
					map_frame* f = get_frame(h.x, h.y, h.z, i, false);
					if (!f) continue;
					p = f->add_areas_for_range(local_areas, taken, minx, maxx, miny, maxy, minz, maxz, d, p, filter_callback, flags, excluded_flags);
					if (!priority_check) p = -1;
				}
				continue;
			}
			for (int x = x0; x <= x1; x += size) {
				for (int y = y0; y <= y1; y += size) {
					for (int z = z0; z <= z1; z += size) {
						map_frame* f = get_frame(x, y, z, i, false);
						if (!f) continue;
						p = f->add_areas_for_range(local_areas, taken, minx, maxx, miny, maxy, minz, maxz, d, p, filter_callback, flags, excluded_flags);
						if (!priority_check) p = -1;
					}
				}
			}
		}
	}
	if (priority_check && local_areas.size() > 1) {
		// Move the highest priority area to the end, where get_area looks for it. This has to swap two elements of the
		// list: swapping a local pointer with the last element instead would overwrite the last area with a second copy
		// of the highest priority one, and the area it displaced would never be released by the caller, so it stayed
		// alive with everything its primary data holds. Areas that share the highest priority make that visible,
		// because only then does the running priority check let more than the eventual winner onto the list.
		size_t highest = 0;
		for (size_t i = 1; i < local_areas.size(); i++) {
			if (local_areas[i]->priority > local_areas[highest]->priority) highest = i;
		}
		std::swap(local_areas[highest], local_areas[local_areas.size() - 1]);
	} else if (local_areas.size() > 1)
		sort(local_areas.begin(), local_areas.end(), map_area_sort);
	if (filter_callback) filter_callback->Release();
}
CScriptArray* coordinate_map::get_areas_script(float x, float y, float z, float d, asIScriptFunction* filter_callback, asINT64 flags, asINT64 excluded_flags) {
	std::vector<map_area*> local_areas;
	local_areas.reserve(20);
	if (!g_MapAreaArrayType) g_MapAreaArrayType = get_array_type("array<coordinate_map_area@>");
	CScriptArray* array = CScriptArray::Create(g_MapAreaArrayType);
	get_areas(x, x, y, y, z, z, d, local_areas, false, filter_callback, flags, excluded_flags);
	array->Reserve(local_areas.size());
	for (int i = 0; i < local_areas.size(); i++) {
		array->InsertLast(&local_areas[i]); // the array takes its own reference
		local_areas[i]->release();
	}
	return array;
}
CScriptArray* coordinate_map::get_areas_in_range_script(float minx, float maxx, float miny, float maxy, float minz, float maxz, float d, asIScriptFunction* filter_callback, asINT64 flags, asINT64 excluded_flags) {
	std::vector<map_area*> local_areas;
	local_areas.reserve(20);
	if (!g_MapAreaArrayType) g_MapAreaArrayType = get_array_type("array<coordinate_map_area@>");
	CScriptArray* array = CScriptArray::Create(g_MapAreaArrayType);
	get_areas(minx, maxx, miny, maxy, minz, maxz, d, local_areas, false, filter_callback, flags, excluded_flags);
	array->Reserve(local_areas.size());
	for (int i = 0; i < local_areas.size(); i++) {
		array->InsertLast(&local_areas[i]); // the array takes its own reference
		local_areas[i]->release();
	}
	return array;
}
map_area* coordinate_map::get_area(float x, float y, float z, int max_priority, float d, asIScriptFunction* filter_callback, asINT64 flags, asINT64 excluded_flags) {
	std::vector<map_area*> local_areas;
	get_areas(x, x, y, y, z, z, d, local_areas, max_priority < 0, filter_callback, flags, excluded_flags);
	if (local_areas.size() < 1)return NULL;
	map_area* result = NULL;
	if (max_priority < 0) result = local_areas[local_areas.size() - 1];
	else {
		for (int i = local_areas.size() - 1; i >= 0; i--) {
			if (local_areas[i]->priority >= max_priority) continue;
			result = local_areas[i];
			break;
		}
	}
	// Every entry holds a reference taken by get_areas; the chosen one is handed to the caller as its returned reference, the others are dropped.
	for (map_area* a : local_areas) if (a != result) a->release();
	return result;
}
void coordinate_map::reset() {
	// The frames' references are let go of once the frames are gone and the lock is free: letting go of an area's last reference frees its primary data, which can run a script destructor, and one that changed this map (added an area, say) while the frames were still being walked here invalidated the walk.
	std::vector<map_area*> held;
	{
		std::lock_guard<std::recursive_mutex> lock(frames_mtx);
		for (int i = 0; i < total_frame_sizes; i++) {
			for (auto f : frames[i]) {
				f.second->reset(held);
				delete f.second;
			}
			frames[i].clear();
		}
	}
	for (map_area* a : held) a->release();
}

coordinate_map* new_coordinate_map() {
	coordinate_map* m = new coordinate_map();
	if (g_coordinate_map_type) g_coordinate_map_type->GetEngine()->NotifyGarbageCollectorOfNewObject(m, g_coordinate_map_type);
	return m;
}

void RegisterScriptMap(asIScriptEngine* engine) {
	engine->SetDefaultAccessMask(NVGT_SUBSYSTEM_GENERAL);
	engine->RegisterGlobalFunction(_O("vector rotate(const vector&in point, const vector&in origin, double theta, bool maintain_z = true)"), asFUNCTION(rotate), asCALL_CDECL);
	engine->RegisterGlobalFunction(_O("bool boxes_intersect(float minx1, float maxx1, float miny1, float maxy1, float r1, float minx2, float maxx2, float miny2, float maxy2, float r2)"), asFUNCTION(boxes_intersect), asCALL_CDECL);
	engine->SetDefaultAccessMask(NVGT_SUBSYSTEM_MAP);
	int map_type_id = engine->RegisterObjectType(_O("coordinate_map"), 0, asOBJ_REF | asOBJ_GC); // See coordinate_map::enum_references().
	g_coordinate_map_type = map_type_id >= 0 ? engine->GetTypeInfoById(map_type_id) : nullptr;
	int area_type_id = engine->RegisterObjectType(_O("coordinate_map_area"), 0, asOBJ_REF | asOBJ_GC);
	g_map_area_type = area_type_id >= 0 ? engine->GetTypeInfoById(area_type_id) : nullptr;
	engine->RegisterFuncdef(_O("bool coordinate_map_filter_callback(coordinate_map_area@ area)"));
	engine->RegisterObjectBehaviour(_O("coordinate_map_area"), asBEHAVE_ADDREF, _O("void f()"), asMETHOD(map_area, add_ref), asCALL_THISCALL);
	engine->RegisterObjectBehaviour(_O("coordinate_map_area"), asBEHAVE_RELEASE, _O("void f()"), asMETHOD(map_area, release), asCALL_THISCALL);
	engine->RegisterObjectBehaviour(_O("coordinate_map_area"), asBEHAVE_GETREFCOUNT, _O("int f()"), asMETHOD(map_area, get_ref_count), asCALL_THISCALL);
	engine->RegisterObjectBehaviour(_O("coordinate_map_area"), asBEHAVE_SETGCFLAG, _O("void f()"), asMETHOD(map_area, set_gc_flag), asCALL_THISCALL);
	engine->RegisterObjectBehaviour(_O("coordinate_map_area"), asBEHAVE_GETGCFLAG, _O("bool f()"), asMETHOD(map_area, get_gc_flag), asCALL_THISCALL);
	engine->RegisterObjectBehaviour(_O("coordinate_map_area"), asBEHAVE_ENUMREFS, _O("void f(int&in)"), asMETHOD(map_area, enum_references), asCALL_THISCALL);
	engine->RegisterObjectBehaviour(_O("coordinate_map_area"), asBEHAVE_RELEASEREFS, _O("void f(int&in)"), asMETHOD(map_area, release_all_references), asCALL_THISCALL);
	engine->RegisterObjectProperty(_O("coordinate_map_area"), _O("const coordinate_map@ map"), asOFFSET(map_area, parent));
	engine->RegisterObjectProperty(_O("coordinate_map_area"), _O("const float minx"), asOFFSET(map_area, minx));
	engine->RegisterObjectProperty(_O("coordinate_map_area"), _O("const float maxx"), asOFFSET(map_area, maxx));
	engine->RegisterObjectProperty(_O("coordinate_map_area"), _O("const float miny"), asOFFSET(map_area, miny));
	engine->RegisterObjectProperty(_O("coordinate_map_area"), _O("const float maxy"), asOFFSET(map_area, maxy));
	engine->RegisterObjectProperty(_O("coordinate_map_area"), _O("const float minz"), asOFFSET(map_area, minz));
	engine->RegisterObjectProperty(_O("coordinate_map_area"), _O("const float maxz"), asOFFSET(map_area, maxz));
	engine->RegisterObjectProperty(_O("coordinate_map_area"), _O("const float rotation"), asOFFSET(map_area, rotation));
	engine->RegisterObjectProperty(_O("coordinate_map_area"), _O("any@ primary_data"), asOFFSET(map_area, primary_data));
	engine->RegisterObjectProperty(_O("coordinate_map_area"), _O("const string data1"), asOFFSET(map_area, data1));
	engine->RegisterObjectProperty(_O("coordinate_map_area"), _O("const string data2"), asOFFSET(map_area, data2));
	engine->RegisterObjectProperty(_O("coordinate_map_area"), _O("const string data3"), asOFFSET(map_area, data3));
	engine->RegisterObjectProperty(_O("coordinate_map_area"), _O("const int priority"), asOFFSET(map_area, priority));
	engine->RegisterObjectProperty(_O("coordinate_map_area"), _O("const bool framed"), asOFFSET(map_area, framed));
	engine->RegisterObjectProperty(_O("coordinate_map_area"), _O("int64 flags"), asOFFSET(map_area, flags));
	engine->RegisterObjectMethod(_O("coordinate_map_area"), _O("void unframe()"), asMETHOD(map_area, unframe), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("coordinate_map_area"), _O("void reframe()"), asMETHOD(map_area, reframe), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("coordinate_map_area"), _O("void set(float minx, float maxx, float miny, float maxy, float minz, float maxz, float theta)"), asMETHOD(map_area, set), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("coordinate_map_area"), _O("void set_area(float minx, float maxx, float miny, float maxy, float minz, float maxz)"), asMETHOD(map_area, set_area), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("coordinate_map_area"), _O("void set_rotation(float theta)"), asMETHOD(map_area, set_rotation), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("coordinate_map_area"), _O("bool is_in_area(float x, float y, float z, float d = 0.0, coordinate_map_filter_callback@+ filter_callback = null, int64 required_flags = 0, int64 excluded_flags = 0) const"), asMETHOD(map_area, is_in_area), asCALL_THISCALL);
	engine->RegisterObjectBehaviour(_O("coordinate_map"), asBEHAVE_FACTORY, _O("coordinate_map @m()"), asFUNCTION(new_coordinate_map), asCALL_CDECL);
	engine->RegisterObjectBehaviour(_O("coordinate_map"), asBEHAVE_ADDREF, _O("void f()"), asMETHOD(coordinate_map, add_ref), asCALL_THISCALL);
	engine->RegisterObjectBehaviour(_O("coordinate_map"), asBEHAVE_RELEASE, _O("void f()"), asMETHOD(coordinate_map, release), asCALL_THISCALL);
	engine->RegisterObjectBehaviour(_O("coordinate_map"), asBEHAVE_GETREFCOUNT, _O("int f()"), asMETHOD(coordinate_map, get_ref_count), asCALL_THISCALL);
	engine->RegisterObjectBehaviour(_O("coordinate_map"), asBEHAVE_SETGCFLAG, _O("void f()"), asMETHOD(coordinate_map, set_gc_flag), asCALL_THISCALL);
	engine->RegisterObjectBehaviour(_O("coordinate_map"), asBEHAVE_GETGCFLAG, _O("bool f()"), asMETHOD(coordinate_map, get_gc_flag), asCALL_THISCALL);
	engine->RegisterObjectBehaviour(_O("coordinate_map"), asBEHAVE_ENUMREFS, _O("void f(int&in)"), asMETHOD(coordinate_map, enum_references), asCALL_THISCALL);
	engine->RegisterObjectBehaviour(_O("coordinate_map"), asBEHAVE_RELEASEREFS, _O("void f(int&in)"), asMETHOD(coordinate_map, release_all_references), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("coordinate_map"), _O("coordinate_map_area@ add_area(float minx, float maxx, float miny, float maxy, float minz, float maxz, float rotation, any@ primary_data, const string&in data1, const string&in data2, const string&in data3, int priority, int64 flags = 0)"), asMETHOD(coordinate_map, add_area), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("coordinate_map"), _O("coordinate_map_area@[]@ get_areas(float x, float y, float z, float d = 0.0, coordinate_map_filter_callback@ filter_callback = null, int64 required_flags = 0, int64 excluded_flags = 0) const"), asMETHOD(coordinate_map, get_areas_script), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("coordinate_map"), _O("coordinate_map_area@[]@ get_areas(float minx, float maxx, float miny, float maxy, float minz, float maxz, float d = 0.0, coordinate_map_filter_callback@ filter_callback = null, int64 required_flags = 0, int64 excluded_flags = 0) const"), asMETHOD(coordinate_map, get_areas_in_range_script), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("coordinate_map"), _O("coordinate_map_area@ get_area(float x, float y, float z, int priority = -1, float d = 0.0, coordinate_map_filter_callback@ filter_callback = null, int64 required_flags = 0, int64 excluded_flags = 0) const"), asMETHOD(coordinate_map, get_area), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("coordinate_map"), _O("void reset()"), asMETHOD(coordinate_map, reset), asCALL_THISCALL);
}
