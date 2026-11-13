/* UI.h - header for sdl window management functions and other user interface related routines
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
#ifdef _WIN32
	#define WIN32_LEAN_AND_MEAN
	#define VC_EXTRALEAN
	#include <windows.h>
#endif
#ifndef NVGT_NATIVE_WINDOW_DEFINED
#define NVGT_NATIVE_WINDOW_DEFINED
#ifdef _WIN32
typedef HWND native_window_t;
#define NATIVE_WINDOW_SDL_PROP SDL_PROP_WINDOW_WIN32_HWND_POINTER
#elif defined(__APPLE__)
#ifndef NVGT_MOBILE
typedef void* native_window_t; // NSWindow*, cast in .mm code
#define NATIVE_WINDOW_SDL_PROP SDL_PROP_WINDOW_COCOA_WINDOW_POINTER
#else
typedef void* native_window_t; // UIWindow*, cast in .mm code
#define NATIVE_WINDOW_SDL_PROP SDL_PROP_WINDOW_UIKIT_WINDOW_POINTER
#endif
#elif defined(__ANDROID__)
typedef void* native_window_t; // ANativeWindow*
#define NATIVE_WINDOW_SDL_PROP SDL_PROP_WINDOW_ANDROID_WINDOW_POINTER
#else
typedef void* native_window_t;
#endif
#endif
#include <angelscript.h>
#include <scriptarray.h>
#include <Poco/AutoPtr.h>
#include <mutex>
#include <string>
#include <vector>
#include <SDL3/SDL.h>
#include "graphics.h"

int message_box(const std::string& title, const std::string& text, const std::vector < std::string > & buttons, unsigned int mb_flags = 0);
int alert(const std::string& title, const std::string& text, bool can_cancel = false, unsigned int flags = 0);
int question(const std::string& title, const std::string& text, bool can_cancel = false, unsigned int flags = 0);
void message(const std::string& text, const std::string& header);
bool info_box(const std::string& title, const std::string& text, const std::string& value);
bool ClipboardSetText(const std::string& text);
std::string simple_file_open_dialog(const std::string& filters = "All files:*", const std::string& default_location = "");
bool urlopen(const std::string& url);
bool is_console_available();

class game_window {
	SDL_Window* _window;
	bool _owns_window; // Set to true if we create window and false otherwise, if false destructor does not destroy SDL_Window.
	native_window_t _native_window;
	Poco::AutoPtr<graphics_renderer> _renderer;
	Poco::AutoPtr<text_font> _font;
	thread_id_t _thread; // the thread that made the object, see on_thread()
	mutable int _refcount;
	SDL_Window* win() const { return on_thread() ? _window : nullptr; }
	// What the window's thread last saw of the window (see update_state()), which the read-only queries answer on other threads: they give what the same query gave on the window's thread at that moment, for a closed window too.
	struct window_state {
		std::string title;
		unsigned int id = 0, pixel_format = 0, progress_state = 0;
		uint64_t flags = 0;
		float pixel_density = 0, display_scale = 0, opacity = 0, progress_value = 0, min_aspect = 0, max_aspect = 0;
		int x = 0, y = 0, w = 0, h = 0, pixel_w = 0, pixel_h = 0, min_w = 0, min_h = 0, max_w = 0, max_h = 0, top = 0, left = 0, bottom = 0, right = 0, surface_vsync = 0;
		bool position_ok = false, size_ok = false, pixels_ok = false, min_ok = false, max_ok = false, aspect_ok = false, borders_ok = false, surface_vsync_ok = false;
		bool keyboard_grab = false, mouse_grab = false, has_surface = false, focused = false, text_input_active = false, screen_keyboard_shown = false;
		native_window_t native_window = nullptr;
	};
	mutable std::mutex _state_mutex;
	window_state _state;
	window_state state() const { std::lock_guard<std::mutex> lock(_state_mutex); return _state; }
	bool changed(bool result) { update_state(); return result; } // after a call that can change the window, see update_state()
public:
	game_window(const std::string& title, unsigned int w, unsigned int h, unsigned int flags);
	game_window(SDL_Window* window);
	~game_window();
	void close(); // Destroys the SDL window (when this object made it) and lets go of the renderer and font, whoever holds this object.
	void duplicate() { asAtomicInc(_refcount); }
	void release(); // see game_windows_collect() in UI.cpp
	// SDL's windows, and the renderers and textures made for them, are for the thread that made them (SDL documents its video functions as main-thread only), which can also close the window at any time. A script thread using a window object made on another thread passed SDL a window that thread was destroying (a crash), and the calls SDL makes a message to the window's thread (set_title(), set_size()) waited for as long as that thread didn't handle its messages (in a join()). On any other thread the object acts as a closed window: what the script reaches fails as SDL's functions do for a null window, and its renderer and font are null.
	bool on_thread() const { return _thread == thread_current_thread_id(); }
	// On the window's thread, reads the window into what the read-only queries answer on other threads, see window_state. That thread calls it as it handles the window's events (handle_sdl_event()), after each of its own calls that can change the window, and as the window is made and closed; elsewhere it does nothing.
	void update_state();
	SDL_Window* get_sdl_window() const { return _window; } // NVGT's own use, on the window's thread (or with a check of its own)
	native_window_t get_native_window() const { return on_thread() ? _native_window : state().native_window; }
	bool is_focused() const { return on_thread() ? _window && _window == SDL_GetKeyboardFocus() : state().focused; } // is_window_active()
	bool text_input_active() const { return on_thread() ? SDL_TextInputActive(_window) : state().text_input_active; }
	bool screen_keyboard_shown() const { return on_thread() ? SDL_ScreenKeyboardShown(_window) : state().screen_keyboard_shown; }
	graphics_renderer* ensure_renderer(); // lazily create the renderer on first graphics use, so audio-only games never present an empty frame (avoids the Android eglSwapBuffers/ActivityMutex ANR)
	graphics_renderer* peek_renderer() { return _renderer.get(); } // non-creating; used by the per-frame present check so it does not itself trigger renderer creation
	graphics_renderer* get_renderer() { return ensure_renderer(); }
	text_font* get_font() { return on_thread() ? _font.get() : nullptr; }
	bool show() {
		bool was_hidden = (SDL_GetWindowFlags(win()) & SDL_WINDOW_HIDDEN) != 0;
		bool ok = SDL_ShowWindow(win());
		if (ok && was_hidden && _renderer) _renderer->require_initial_frame();
		return changed(ok);
	}
	bool hide() { return changed(SDL_HideWindow(win())); }
	bool raise() { return changed(SDL_RaiseWindow(win())); }
	bool maximize() { return changed(SDL_MaximizeWindow(win())); }
	bool minimize() { return changed(SDL_MinimizeWindow(win())); }
	bool restore() { return changed(SDL_RestoreWindow(win())); }
	bool sync() { return changed(SDL_SyncWindow(win())); }
	bool set_fullscreen(bool fullscreen) { return changed(SDL_SetWindowFullscreen(win(), fullscreen)); }
	bool set_title(const std::string& title) { return changed(SDL_SetWindowTitle(win(), title.c_str())); }
	std::string get_title() const { return on_thread() ? from_cstr(SDL_GetWindowTitle(_window)) : state().title; }
	unsigned int get_id() const { return on_thread() ? SDL_GetWindowID(_window) : state().id; }
	uint64_t get_flags() const { return on_thread() ? SDL_GetWindowFlags(_window) : state().flags; }
	float get_pixel_density() const { return on_thread() ? SDL_GetWindowPixelDensity(_window) : state().pixel_density; }
	float get_display_scale() const { return on_thread() ? SDL_GetWindowDisplayScale(_window) : state().display_scale; }
	unsigned int get_pixel_format() const { return on_thread() ? (unsigned int)SDL_GetWindowPixelFormat(_window) : state().pixel_format; }
	bool set_bordered(bool bordered) { return changed(SDL_SetWindowBordered(win(), bordered)); }
	bool set_resizable(bool resizable) { return changed(SDL_SetWindowResizable(win(), resizable)); }
	bool set_always_on_top(bool on_top) { return changed(SDL_SetWindowAlwaysOnTop(win(), on_top)); }
	bool set_fill_document(bool fill) { return changed(SDL_SetWindowFillDocument(win(), fill)); }
	bool set_modal(bool modal) { return changed(SDL_SetWindowModal(win(), modal)); }
	bool set_focusable(bool focusable) { return changed(SDL_SetWindowFocusable(win(), focusable)); }
	bool set_keyboard_grab(bool grabbed) { return changed(SDL_SetWindowKeyboardGrab(win(), grabbed)); }
	bool get_keyboard_grab() const { return on_thread() ? SDL_GetWindowKeyboardGrab(_window) : state().keyboard_grab; }
	bool set_mouse_grab(bool grabbed) { return changed(SDL_SetWindowMouseGrab(win(), grabbed)); }
	bool get_mouse_grab() const { return on_thread() ? SDL_GetWindowMouseGrab(_window) : state().mouse_grab; }
	bool set_opacity(float opacity) { return changed(SDL_SetWindowOpacity(win(), opacity)); }
	float get_opacity() const { return on_thread() ? SDL_GetWindowOpacity(_window) : state().opacity; }
	bool flash(unsigned int operation) { return SDL_FlashWindow(win(), (SDL_FlashOperation)operation); }
	bool show_system_menu(int x, int y) { return SDL_ShowWindowSystemMenu(win(), x, y); }
	bool set_icon(graphic* icon) { return icon && SDL_SetWindowIcon(win(), icon->get_surface()); }
	// &out parameters, set on every path: see graphics.cpp's getters. Defined in UI.cpp, see window_state.
	bool get_position(int& x, int& y) const;
	bool set_position(int x, int y) { return changed(SDL_SetWindowPosition(win(), x, y)); }
	bool get_size(int& w, int& h) const;
	bool set_size(int w, int h) { return changed(SDL_SetWindowSize(win(), w, h)); }
	bool get_size_in_pixels(int& w, int& h) const;
	bool get_minimum_size(int& w, int& h) const;
	bool set_minimum_size(int w, int h) { return changed(SDL_SetWindowMinimumSize(win(), w, h)); }
	bool get_maximum_size(int& w, int& h) const;
	bool set_maximum_size(int w, int h) { return changed(SDL_SetWindowMaximumSize(win(), w, h)); }
	bool get_aspect_ratio(float& min_aspect, float& max_aspect) const;
	bool set_aspect_ratio(float min_aspect, float max_aspect) { return changed(SDL_SetWindowAspectRatio(win(), min_aspect, max_aspect)); }
	bool get_borders_size(int& top, int& left, int& bottom, int& right) const;
	bool has_surface() const { return on_thread() ? SDL_WindowHasSurface(_window) : state().has_surface; }
	bool update_surface() { return changed(SDL_UpdateWindowSurface(win())); }
	bool destroy_surface() { return changed(SDL_DestroyWindowSurface(win())); }
	bool set_surface_vsync(int vsync) { return changed(SDL_SetWindowSurfaceVSync(win(), vsync)); }
	bool get_surface_vsync(int& vsync) const;
	bool set_progress_state(unsigned int state) { return changed(SDL_SetWindowProgressState(win(), (SDL_ProgressState)state)); }
	unsigned int get_progress_state() const { return on_thread() ? (unsigned int)SDL_GetWindowProgressState(_window) : state().progress_state; }
	bool set_progress_value(float value) { return changed(SDL_SetWindowProgressValue(win(), value)); }
	float get_progress_value() const { return on_thread() ? SDL_GetWindowProgressValue(_window) : state().progress_value; }
	void set_font(text_font* font) { if (!on_thread()) return; if (font) font->duplicate(); _font = font; }
	// high-level drawing, Much of this is heavily enspired and/or copied with permission from @aryanchoudharypro's NVGT graphics plugin at https://github.com/aryanchoudharypro/power-plugins-for-nvgt
	bool clear(unsigned int r, unsigned int g, unsigned int b);
	bool present() { return on_thread() && _renderer && _renderer->present(); }
	void draw_text(const std::string& text, float x, float y, unsigned int r, unsigned int g, unsigned int b);
	uint64_t measure_text(const std::string& text) const;
	void draw_text_wrapped(const std::string& text, float x, float y, int wrap_width, unsigned int r, unsigned int g, unsigned int b);
	uint64_t measure_text_wrapped(const std::string& text, int wrap_width) const;
	void draw_rect(float x, float y, float w, float h, unsigned int r, unsigned int g, unsigned int b, bool filled = false);
	void draw_circle(float cx, float cy, int radius, unsigned int r, unsigned int g, unsigned int b, bool filled = false);
	void draw_line(float x1, float y1, float x2, float y2, unsigned int r, unsigned int g, unsigned int b);
	bool render_graphic(graphic* gfx, float x, float y) { return ensure_renderer() && _renderer->render_graphic(gfx, x, y); }
	void draw_menu(CScriptArray* items, float x, float y);
};

extern Poco::AutoPtr<game_window> g_window;
Poco::AutoPtr<game_window> game_window_ref(); // g_window with a reference of its own, on any thread: for the read-only queries (see game_window::window_state)
SDL_Window* window_thread_sdl_window(); // g_window's SDL window when the calling thread made it, else null (see game_window::on_thread())
bool window_thread_free(); // false on a thread other than the one that made g_window
bool sdl_window_on_this_thread(SDL_Window* window); // whether window is a game window the calling thread made, for graphics_renderer()
void game_windows_collect(); // see there

enum system_tray_menu_item_type { SYSTEM_TRAY_ITEM, SYSTEM_TRAY_CHECKBOX, SYSTEM_TRAY_SEPARATOR, SYSTEM_TRAY_SUBMENU };

class system_tray_menu_item;
class system_tray_menu;
class system_tray;

class system_tray_menu_item {
	SDL_TrayEntry* _entry;
	Poco::AutoPtr<system_tray_menu> _submenu; // lazily created when get_submenu() is first called on a SYSTEM_TRAY_SUBMENU item
	asIScriptFunction* _callback;
	system_tray_menu_item_type _type;
	mutable int _refcount;
	bool _gc_flag = false;
	asILockableSharedBool* _weak_flag = nullptr; // see get_weakref_flag()
public:
	system_tray_menu_item(SDL_TrayEntry* entry, system_tray_menu_item_type type);
	~system_tray_menu_item(); // defined in .cpp so that system_tray_menu is complete there
	void duplicate() { _gc_flag = false; asAtomicInc(_refcount); }
	void release(); // see get_weakref_flag()
	// The garbage collector's behaviours (see system_tray_gc_mutex() in UI.cpp): a tray holds its menu, a menu its items, an item its callback (often a delegate of the object that holds the tray) and its submenu, a cycle the collector couldn't see while these weren't its types, so such an object was never freed (its destructor never ran, its tray stayed in the notification area) once the script let go of it.
	int get_ref_count() { return _refcount; }
	void set_gc_flag() { _gc_flag = true; }
	bool get_gc_flag() { return _gc_flag; }
	void enum_references(asIScriptEngine* engine);
	void release_all_references(asIScriptEngine* engine);
	// The entry registry (system_tray_items() in UI.cpp) is a weak link to the item, which a click turns strong. The collector marks this flag dead once it has found the item to be garbage, before it breaks the cycle one object at a time: a click meanwhile ran the item's callback on objects the collector was emptying. Made when first asked for, under system_tray_gc_mutex().
	asILockableSharedBool* get_weakref_flag();
	SDL_TrayEntry* get_sdl_entry() const { return _entry; }
	bool is_valid() const { return _entry != nullptr; }
	void invalidate(); // called by system_tray_menu::remove_entry and system_tray_menu::invalidate
	system_tray_menu_item_type get_type() const { return _type; }
	void set_label(const std::string& label) { if (_entry) SDL_SetTrayEntryLabel(_entry, label.c_str()); }
	std::string get_label() const { return _entry ? from_cstr(SDL_GetTrayEntryLabel(_entry)) : ""; }
	void set_checked(bool checked) { if (_entry) SDL_SetTrayEntryChecked(_entry, checked); }
	bool get_checked() const { return _entry && SDL_GetTrayEntryChecked(_entry); }
	void set_enabled(bool enabled) { if (_entry) SDL_SetTrayEntryEnabled(_entry, enabled); }
	bool get_enabled() const { return _entry && SDL_GetTrayEntryEnabled(_entry); }
	void click() { if (_entry) SDL_ClickTrayEntry(_entry); }
	void set_callback(asIScriptFunction* func);
	void invoke_callback();
	system_tray_menu* get_submenu(); // returns nullptr unless type is SYSTEM_TRAY_SUBMENU
};

class system_tray_menu {
	SDL_TrayMenu* _menu;
	std::vector<Poco::AutoPtr<system_tray_menu_item>> _items;
	mutable int _refcount;
	bool _gc_flag = false;
	system_tray_menu_item* make_entry(int pos, const char* label, SDL_TrayEntryFlags flags, system_tray_menu_item_type type);
public:
	system_tray_menu(SDL_TrayMenu* menu);
	void duplicate() { _gc_flag = false; asAtomicInc(_refcount); }
	void release() { _gc_flag = false; if (asAtomicDec(_refcount) < 1) delete this; }
	int get_ref_count() { return _refcount; } // the garbage collector's behaviours, see system_tray_menu_item
	void set_gc_flag() { _gc_flag = true; }
	bool get_gc_flag() { return _gc_flag; }
	void enum_references(asIScriptEngine* engine);
	void release_all_references(asIScriptEngine* engine);
	SDL_TrayMenu* get_sdl_menu() const { return _menu; }
	system_tray_menu_item* insert_item(const std::string& label, asIScriptFunction* callback = nullptr, bool disabled = false, int pos = -1);
	system_tray_menu_item* insert_checkbox(const std::string& label, bool checked = false, asIScriptFunction* callback = nullptr, bool disabled = false, int pos = -1);
	system_tray_menu_item* insert_submenu(const std::string& label, bool disabled = false, int pos = -1);
	system_tray_menu_item* insert_separator(int pos = -1);
	system_tray_menu_item* find_item(SDL_TrayEntry* entry);
	void remove_entry(system_tray_menu_item* item);
	void invalidate(); // SDL freed the menu: it and everything in it, see system_tray_menu_item::invalidate
	int get_entry_count() const;
	CScriptArray* get_entries();
};

class system_tray {
	SDL_Tray* _tray;
	Poco::AutoPtr<system_tray_menu> _menu; // lazily created when get_menu() is first called
	mutable int _refcount;
	bool _gc_flag = false;
	void teardown(); // invalidates the menus and destroys the SDL tray, see ~system_tray
public:
	system_tray(const std::string& tooltip, graphic* icon);
	~system_tray();
	void duplicate() { _gc_flag = false; asAtomicInc(_refcount); }
	void release() { _gc_flag = false; if (asAtomicDec(_refcount) < 1) delete this; }
	int get_ref_count() { return _refcount; } // the garbage collector's behaviours, see system_tray_menu_item
	void set_gc_flag() { _gc_flag = true; }
	bool get_gc_flag() { return _gc_flag; }
	void enum_references(asIScriptEngine* engine);
	void release_all_references(asIScriptEngine* engine);
	bool is_valid() const { return _tray != nullptr; }
	SDL_Tray* detach_sdl(); // see system_tray_quit()
	void set_icon(graphic* icon) { if (_tray) SDL_SetTrayIcon(_tray, icon ? icon->get_surface() : nullptr); }
	void set_tooltip(const std::string& tooltip) { if (_tray) SDL_SetTrayTooltip(_tray, tooltip.empty() ? nullptr : tooltip.c_str()); }
	system_tray_menu* get_menu();
};

game_window* ShowNVGTWindow(const std::string& window_title, unsigned int flags = 0);
bool DestroyNVGTWindow();
bool DestroyNVGTWindowAtExit(); // see there
// SDL's video subsystem against script threads, see UI.cpp. Taken around the clipboard calls, destroy_window() (InputQuitVideo()), InputDestroy()'s SDL_Quit() and the window thread's event pumping.
struct video_lock {
	video_lock();
	~video_lock();
	video_lock(const video_lock&) = delete;
	video_lock& operator=(const video_lock&) = delete;
};
// What the window thread's event pumping takes (and the other places that pump events). On Android SDL changes the clipboard's state on
// Java's UI thread, not in the pump, so the lock protects nothing there, and SDL_PumpEvents() waits inside while the app is paused
// (SDL_HINT_ANDROID_BLOCK_ON_PAUSE): held there, it kept every clipboard call on other threads waiting until the app came back.
#ifdef __ANDROID__
struct pump_lock {};
#else
typedef video_lock pump_lock;
#endif
void system_tray_quit(); // before SDL_Quit(), see UI.cpp
void game_windows_quit(); // likewise
bool WindowIsFocused();
int get_window_width();
int get_window_height();
void refresh_window();
void wait(int ms);
void RegisterUI(asIScriptEngine* engine);
