/* graphics.h - header defining classes and functions for graphics and other visual rendering features
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
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <angelscript.h>
#include <cmath>
#include <scriptarray.h>
#include <SDL3/SDL.h>
#include <SDL3_ttf/SDL_ttf.h>
#include <thread.h>

class game_window;
class pack_interface;

inline std::string from_cstr(const char* str) { return str ? str : ""; }
// A color, alpha or modulation value the script gives as a uint: above 255 it is 255. Each one was cut to its low byte, so 300 was 44 and
// an alpha of 1000 was 232 (set_color_mod, set_alpha_mod, set_draw_color, text colors).
inline Uint8 color_mod_byte(unsigned int v) { return Uint8(v > 255 ? 255 : v); }
inline SDL_Color to_sdl_color(unsigned int r, unsigned int g, unsigned int b) { return {color_mod_byte(r), color_mod_byte(g), color_mod_byte(b), 255}; }

class graphic {
	SDL_Surface* _surface;
	int _refcount;
public:
	graphic(SDL_Surface* surface);
	~graphic();
	void duplicate() { asAtomicInc(_refcount); }
	void release() { if (asAtomicDec(_refcount) < 1) delete this; }
	int get_width() const { return _surface ? _surface->w : 0; }
	int get_height() const { return _surface ? _surface->h : 0; }
	int get_pitch() const { return _surface ? _surface->pitch : 0; }
	bool is_valid() const { return _surface != nullptr; }
	bool lock() { return SDL_LockSurface(_surface); }
	void unlock() { SDL_UnlockSurface(_surface); }
	bool save_bmp(const std::string& file) const { return SDL_SaveBMP(_surface, file.c_str()); }
	bool save_png(const std::string& file) const { return SDL_SavePNG(_surface, file.c_str()); }
	bool set_rle(bool enabled) { return SDL_SetSurfaceRLE(_surface, enabled); }
	bool set_color_mod(unsigned int r, unsigned int g, unsigned int b) { return SDL_SetSurfaceColorMod(_surface, color_mod_byte(r), color_mod_byte(g), color_mod_byte(b)); }
	bool set_alpha_mod(unsigned int alpha) { return SDL_SetSurfaceAlphaMod(_surface, color_mod_byte(alpha)); }
	bool set_blend_mode(unsigned int mode) { return SDL_SetSurfaceBlendMode(_surface, (SDL_BlendMode)mode); }
	bool flip(unsigned int mode) { return SDL_FlipSurface(_surface, (SDL_FlipMode)mode); }
	graphic* convert(unsigned int pixel_format) const { SDL_Surface* s = SDL_ConvertSurface(_surface, (SDL_PixelFormat)pixel_format); return s ? new graphic(s) : nullptr; }
	graphic* duplicate_surface() const { SDL_Surface* s = SDL_DuplicateSurface(_surface); return s ? new graphic(s) : nullptr; }
	unsigned int get_blend_mode() const;
	bool get_color_mod(unsigned int& r, unsigned int& g, unsigned int& b) const;
	unsigned int get_alpha_mod() const;
	SDL_Surface* get_surface() const { return _surface; }
};
graphic* load_bmp(const std::string& file);
graphic* load_bmp(const std::string& file, const pack_interface* pack_file);
graphic* load_png(const std::string& file);
graphic* load_png(const std::string& file, const pack_interface* pack_file);
graphic* load_surface(const std::string& file);
graphic* load_surface(const std::string& file, const pack_interface* pack_file);
graphic* create_surface(int width, int height, unsigned int pixel_format);

class graphics_renderer;
class graphics_texture {
	SDL_Texture* _texture;
	int _width;
	int _height;
	int _refcount;
	friend class graphics_renderer;
	friend void graphics_collect();
	graphics_renderer* _owner = nullptr; // the renderer that made it, see graphics_renderer::detach()
	thread_id_t _thread; // the thread of its renderer, see game_window::on_thread()
	SDL_Texture* tex() const { return on_thread() ? _texture : nullptr; }
public:
	graphics_texture(SDL_Texture* texture);
	~graphics_texture();
	void duplicate() { asAtomicInc(_refcount); }
	void release(); // see graphics_collect()
	bool on_thread() const { return _thread == thread_current_thread_id(); }
	int get_width() const { return _width; }
	int get_height() const { return _height; }
	bool is_valid() const { return tex() != nullptr; }
	bool set_color_mod(unsigned int r, unsigned int g, unsigned int b);
	bool get_color_mod(unsigned int& r, unsigned int& g, unsigned int& b) const;
	bool set_alpha_mod(unsigned int alpha);
	unsigned int get_alpha_mod() const;
	bool set_blend_mode(unsigned int mode);
	unsigned int get_blend_mode() const;
	SDL_Texture* get_texture() const { return tex(); }
};

// The length of text that SDL_ttf's wrapping is given: up to its first NUL character. SDL_ttf 3.2's line wrapping (TTF_GetStringSizeWrapped and
// the TTF_Render*_Wrapped functions) never got past a NUL inside the length it was given (SDL_StepUTF8 doesn't advance over one), so a string
// holding one (a substring of binary data, "a\x00b") hung the script for good, whatever the wrap width. The text ends there, as a C string does.
inline size_t ttf_wrapped_text_length(const std::string& text) {
	size_t nul = text.find('\0');
	return nul == std::string::npos ? text.size() : nul;
}
// Whether a wrapped render of the text can place its lines in an int. SDL_ttf makes the surface rowHeight + lineskip * (lines - 1) high and
// puts line i at i * lineskip, in ints: when that overflowed, the surface came out a few rows high while the lines lay outside it, where
// the underline and strikethrough were drawn (an out of bounds write). A text makes at most one line more than it has bytes, so a
// render whose row height times that many lines passes 2^31 - 1 is refused, as one of no font is (an empty graphic).
inline bool ttf_wrapped_lines_fit(TTF_Font* font, const std::string& text) {
	long long skip = TTF_GetFontLineSkip(font), height = TTF_GetFontHeight(font);
	long long row = (skip > height ? skip : height) + 2LL * TTF_GetFontOutline(font) + 64;
	return row * (long long)(ttf_wrapped_text_length(text) + 1) <= 2147483647LL;
}
// Whether FreeType can take a font size of ptsize points at hdpi by vdpi dots per inch (0 for one of them takes the other, 0 for
// both 72, as SDL_ttf and FreeType do). FreeType keeps the size in pixels per em in 16 bits and works it out in a long (32 bits on
// Windows), and SDL_ttf hands it the size times 64 as an int: a size past them came out as a wrapped or overflowed scale, and rendering
// one glyph then ran for minutes with close to a gigabyte (set_size_dpi(400, 96, 2147483647), or set_size() after a large DPI), or
// was undefined (more than 33554431 points). A size of more than 65535 pixels per em is refused.
inline bool font_size_fits(float ptsize, int hdpi, int vdpi) {
	if (!(ptsize > 0) || !std::isfinite(ptsize) || hdpi < 0 || vdpi < 0) return false;
	if (hdpi == 0) hdpi = vdpi;
	if (vdpi == 0) vdpi = hdpi;
	if (hdpi == 0) hdpi = vdpi = 72;
	return double(ptsize) * double(hdpi > vdpi ? hdpi : vdpi) / 72.0 <= 65535.0;
}
class text_font {
	TTF_Font* _font;
	std::vector<text_font*> _fallback_fonts;
	int _refcount;
public:
	text_font(const std::string& name, float size, unsigned int initial_style = TTF_STYLE_NORMAL);
	~text_font();
	void duplicate() { asAtomicInc(_refcount); }
	void release() { if (asAtomicDec(_refcount) < 1) delete this; }
	bool is_valid() const { return _font != nullptr; } // False when TTF_OpenFont failed; every method below is guarded against that case.
	unsigned int get_generation() const { if (!_font) return 0; return TTF_GetFontGeneration(_font); }
	bool add_fallback_font(text_font* font);
	bool remove_fallback_font(text_font* font);
	void clear_fallback_fonts();
	// A size that isn't a finite number above 0 (or a negative DPI) is refused: SDL_ttf took NaN and infinity, and the font then
	// measured and rendered every text as a few pixels until another size was set. So is one too large for FreeType at the DPI it
	// is used with, see font_size_fits(): set_size() keeps the font's DPI, as set_size_dpi() does when given 0 for both.
	bool set_size(float ptsize) { return set_size_dpi(ptsize, 0, 0); }
	float get_size() const { if (!_font) return 0.0f; return TTF_GetFontSize(_font); }
	bool set_size_dpi(float ptsize, int hdpi, int vdpi) {
		if (!_font || !(ptsize > 0) || !std::isfinite(ptsize) || hdpi < 0 || vdpi < 0) return false;
		int h = hdpi, v = vdpi;
		if (h == 0 && v == 0 && !TTF_GetFontDPI(_font, &h, &v)) h = v = 0;
		if (!font_size_fits(ptsize, h, v)) return false;
		return TTF_SetFontSizeDPI(_font, ptsize, hdpi, vdpi);
	}
	bool get_dpi(int& hdpi, int& vdpi) const;
	void set_style(unsigned int style) { if (!_font) return; TTF_SetFontStyle(_font, (TTF_FontStyleFlags)style); }
	unsigned int get_style() const { if (!_font) return 0; return TTF_GetFontStyle(_font); }
	bool set_outline(int outline) { if (!_font || outline > 65535) return false; return TTF_SetFontOutline(_font, outline); } // SDL_ttf doubles it in an int: 2147483647 gave a crash at the next render.
	int get_outline() const { if (!_font) return 0; return TTF_GetFontOutline(_font); }
	int get_faces_count() const { if (!_font) return 0; return TTF_GetNumFontFaces(_font); }
	bool set_sdf(bool enabled) { if (!_font) return false; return TTF_SetFontSDF(_font, enabled); }
	bool get_sdf() const { if (!_font) return false; return TTF_GetFontSDF(_font); }
	int get_weight() const { if (!_font) return 0; return TTF_GetFontWeight(_font); }
	void set_wrap_alignment(unsigned int alignment) { if (!_font) return; TTF_SetFontWrapAlignment(_font, (TTF_HorizontalAlignment)alignment); }
	unsigned int get_wrap_alignment() const { if (!_font) return 0; return (unsigned int)TTF_GetFontWrapAlignment(_font); }
	int get_height() const { if (!_font) return 0; return TTF_GetFontHeight(_font); }
	int get_ascent() const { if (!_font) return 0; return TTF_GetFontAscent(_font); }
	int get_descent() const { if (!_font) return 0; return TTF_GetFontDescent(_font); }
	// SDL_ttf takes any line skip: a negative one put the lines of a wrapped text above the surface made for them, where the underline and
	// strikethrough were drawn (line_skip = -2147483648 with FONT_STYLE_UNDERLINE and a text wrapped to 21 lines wrote out of bounds and
	// crashed). One below 0 or above 65535 is refused, and the font keeps the one it has; see also ttf_wrapped_lines_fit().
	void set_line_skip(int skip) { if (!_font || skip < 0 || skip > 65535) return; TTF_SetFontLineSkip(_font, skip); }
	int get_line_skip() const { if (!_font) return 0; return TTF_GetFontLineSkip(_font); }
	void set_kerning(bool enabled) { if (!_font) return; TTF_SetFontKerning(_font, enabled); }
	bool get_kerning() const { if (!_font) return false; return TTF_GetFontKerning(_font); }
	bool is_fixed_width() const { if (!_font) return false; return TTF_FontIsFixedWidth(_font); }
	bool is_scalable() const { if (!_font) return false; return TTF_FontIsScalable(_font); }
	std::string get_family_name() const { if (!_font) return std::string(); return from_cstr(TTF_GetFontFamilyName(_font)); }
	std::string get_style_name() const { if (!_font) return std::string(); return from_cstr(TTF_GetFontStyleName(_font)); }
	bool set_direction(unsigned int dir) { if (!_font) return false; return TTF_SetFontDirection(_font, (TTF_Direction)dir); }
	unsigned int get_direction() const { if (!_font) return 0; return (unsigned int)TTF_GetFontDirection(_font); }
	bool set_script(unsigned int script) { if (!_font) return false; return TTF_SetFontScript(_font, script); }
	unsigned int get_script() const { if (!_font) return 0; return TTF_GetFontScript(_font); }
	bool set_language(const std::string& language_bcp47) { if (!_font) return false; return TTF_SetFontLanguage(_font, language_bcp47.c_str()); }
	bool has_glyph(unsigned int codepoint) { if (!_font) return false; return TTF_FontHasGlyph(_font, codepoint); }
	graphic* render_text_solid(const std::string& text, unsigned int r, unsigned int g, unsigned int b) { if (!_font) return new graphic(nullptr); return new graphic(TTF_RenderText_Solid(_font, text.c_str(), text.size(), to_sdl_color(r, g, b))); }
	graphic* render_text_solid_wrapped(const std::string& text, int wrap_width, unsigned int r, unsigned int g, unsigned int b) { if (!_font || !ttf_wrapped_lines_fit(_font, text)) return new graphic(nullptr); return new graphic(TTF_RenderText_Solid_Wrapped(_font, text.c_str(), ttf_wrapped_text_length(text), to_sdl_color(r, g, b), wrap_width)); }
	graphic* render_text_blended(const std::string& text, unsigned int r, unsigned int g, unsigned int b) { if (!_font) return new graphic(nullptr); return new graphic(TTF_RenderText_Blended(_font, text.c_str(), text.size(), to_sdl_color(r, g, b))); }
	graphic* render_text_blended_wrapped(const std::string& text, int wrap_width, unsigned int r, unsigned int g, unsigned int b) { if (!_font || !ttf_wrapped_lines_fit(_font, text)) return new graphic(nullptr); return new graphic(TTF_RenderText_Blended_Wrapped(_font, text.c_str(), ttf_wrapped_text_length(text), to_sdl_color(r, g, b), wrap_width)); }
	graphic* render_text_shaded(const std::string& text, unsigned int fg_r, unsigned int fg_g, unsigned int fg_b, unsigned int bg_r, unsigned int bg_g, unsigned int bg_b) { if (!_font) return new graphic(nullptr); return new graphic(TTF_RenderText_Shaded(_font, text.c_str(), text.size(), to_sdl_color(fg_r, fg_g, fg_b), to_sdl_color(bg_r, bg_g, bg_b))); }
	graphic* render_text_shaded_wrapped(const std::string& text, int wrap_width, unsigned int fg_r, unsigned int fg_g, unsigned int fg_b, unsigned int bg_r, unsigned int bg_g, unsigned int bg_b) { if (!_font || !ttf_wrapped_lines_fit(_font, text)) return new graphic(nullptr); return new graphic(TTF_RenderText_Shaded_Wrapped(_font, text.c_str(), ttf_wrapped_text_length(text), to_sdl_color(fg_r, fg_g, fg_b), to_sdl_color(bg_r, bg_g, bg_b), wrap_width)); }
	graphic* render_text_lcd(const std::string& text, unsigned int fg_r, unsigned int fg_g, unsigned int fg_b, unsigned int bg_r, unsigned int bg_g, unsigned int bg_b) { if (!_font) return new graphic(nullptr); return new graphic(TTF_RenderText_LCD(_font, text.c_str(), text.size(), to_sdl_color(fg_r, fg_g, fg_b), to_sdl_color(bg_r, bg_g, bg_b))); }
	graphic* render_text_lcd_wrapped(const std::string& text, int wrap_width, unsigned int fg_r, unsigned int fg_g, unsigned int fg_b, unsigned int bg_r, unsigned int bg_g, unsigned int bg_b) { if (!_font || !ttf_wrapped_lines_fit(_font, text)) return new graphic(nullptr); return new graphic(TTF_RenderText_LCD_Wrapped(_font, text.c_str(), ttf_wrapped_text_length(text), to_sdl_color(fg_r, fg_g, fg_b), to_sdl_color(bg_r, bg_g, bg_b), wrap_width)); }
	graphic* render_glyph_solid(unsigned int ch, unsigned int r, unsigned int g, unsigned int b) { if (!_font) return new graphic(nullptr); return new graphic(TTF_RenderGlyph_Solid(_font, ch, to_sdl_color(r, g, b))); }
	graphic* render_glyph_blended(unsigned int ch, unsigned int r, unsigned int g, unsigned int b) { if (!_font) return new graphic(nullptr); return new graphic(TTF_RenderGlyph_Blended(_font, ch, to_sdl_color(r, g, b))); }
	graphic* render_glyph_shaded(unsigned int ch, unsigned int fg_r, unsigned int fg_g, unsigned int fg_b, unsigned int bg_r, unsigned int bg_g, unsigned int bg_b) { if (!_font) return new graphic(nullptr); return new graphic(TTF_RenderGlyph_Shaded(_font, ch, to_sdl_color(fg_r, fg_g, fg_b), to_sdl_color(bg_r, bg_g, bg_b))); }
	graphic* render_glyph_lcd(unsigned int ch, unsigned int fg_r, unsigned int fg_g, unsigned int fg_b, unsigned int bg_r, unsigned int bg_g, unsigned int bg_b) { if (!_font) return new graphic(nullptr); return new graphic(TTF_RenderGlyph_LCD(_font, ch, to_sdl_color(fg_r, fg_g, fg_b), to_sdl_color(bg_r, bg_g, bg_b))); }
	graphic* get_glyph_image(unsigned int ch) const;
	bool get_glyph_metrics(unsigned int ch, int& minx, int& maxx, int& miny, int& maxy, int& advance) const;
	bool get_kerning_size(unsigned int prev_ch, unsigned int ch, int& kerning) const;
	bool get_string_size(const std::string& text, int& w, int& h) const;
	bool get_string_size_wrapped(const std::string& text, int wrap_width, int& w, int& h) const;
	bool measure_string(const std::string& text, int max_width, int& measured_width, int& measured_length) const;
};
text_font* get_font(const std::string& name, float size, unsigned int initial_style = TTF_STYLE_NORMAL, bool allow_caching = true);
unsigned int font_string_to_tag(const std::string& str);
std::string font_tag_to_string(unsigned int tag);

class graphics_renderer {
	SDL_Renderer* _renderer;
	int _refcount;
	bool _dirty;
	bool _presented_once;
	friend class graphics_texture;
	friend void graphics_collect();
	std::unordered_set<graphics_texture*> _textures; // made by create_texture() and not let go of yet
	thread_id_t _thread; // the thread that made it, which is its window's (see game_window::on_thread()): on any other thread it acts as a renderer of a closed window
	SDL_Renderer* rend() const { return on_thread() ? _renderer : nullptr; }
public:
	// SDL destroys a window's renderer, and every texture made by it, with the window: a renderer or texture the script still held kept the freed pointer, and a renderer or texture made later (show_window() again) could get its address, which the old object then drew on and, when let go of, destroyed. game_window::close() has every renderer of its window let go of its SDL renderer and textures first.
	void detach();
	static void window_closing(SDL_Window* window);
	graphics_renderer();
	graphics_renderer(game_window* window);
	~graphics_renderer();
	void duplicate() { asAtomicInc(_refcount); }
	void release(); // see graphics_collect()
	bool on_thread() const { return _thread == thread_current_thread_id(); }
	bool is_valid() const { return rend() != nullptr; }
	bool has_presented() const { return _presented_once; }
	bool has_pending_frame() const { return _dirty; }
	void require_initial_frame() { _presented_once = false; }
	void mark_dirty() { _dirty = true; }
	std::string get_name() const { return from_cstr(SDL_GetRendererName(rend())); }
	bool clear() { bool ok = SDL_RenderClear(rend()); if (ok) mark_dirty(); return ok; }
	bool present() { bool ok = SDL_RenderPresent(rend()); if (ok) { _dirty = false; _presented_once = true; } return ok; }
	bool present_if_dirty() { return !_dirty || present(); }
	bool draw_point(float x, float y) { bool ok = SDL_RenderPoint(rend(), x, y); if (ok) mark_dirty(); return ok; }
	bool draw_line(float x1, float y1, float x2, float y2); // see graphics.cpp
	bool set_draw_color(unsigned int r, unsigned int g, unsigned int b, unsigned int a) { return SDL_SetRenderDrawColor(rend(), color_mod_byte(r), color_mod_byte(g), color_mod_byte(b), color_mod_byte(a)); }
	bool set_scale(float sx, float sy) { return SDL_SetRenderScale(rend(), sx, sy); }
	bool set_vsync(int vsync) { return SDL_SetRenderVSync(rend(), vsync); }
	bool flush() { SDL_Renderer* r = rend(); return r && SDL_FlushRenderer(r); } // Without a window there is no renderer, and unlike the other calls SDL_FlushRenderer() doesn't check for that.
	bool set_color_scale(float scale) { return SDL_SetRenderColorScale(rend(), scale); }
	bool set_draw_blend_mode(unsigned int mode) { return SDL_SetRenderDrawBlendMode(rend(), (SDL_BlendMode)mode); }
	bool viewport_set() const { return SDL_RenderViewportSet(rend()); }
	bool clip_enabled() const { return SDL_RenderClipEnabled(rend()); }
	bool get_draw_color(unsigned int& r, unsigned int& g, unsigned int& b, unsigned int& a) const;
	bool get_scale(float& sx, float& sy) const;
	bool get_vsync(int& vsync) const;
	float get_color_scale() const;
	unsigned int get_draw_blend_mode() const;
	bool get_output_size(int& w, int& h) const;
	bool get_current_output_size(int& w, int& h) const;
	bool draw_rect(float x, float y, float w, float h);
	bool fill_rect(float x, float y, float w, float h);
	bool render_graphic(graphic* gfx, float dst_x, float dst_y);
	bool render_graphic_ex(graphic* gfx, float src_x, float src_y, float src_w, float src_h, float dst_x, float dst_y, float dst_w, float dst_h);
	graphics_texture* create_texture(graphic* gfx);
	bool render_texture(graphics_texture* tex, float dst_x, float dst_y);
	bool render_texture_ex(graphics_texture* tex, float src_x, float src_y, float src_w, float src_h, float dst_x, float dst_y, float dst_w, float dst_h);
	bool render_texture_rotated(graphics_texture* tex, float dst_x, float dst_y, double angle, int flip);
	bool render_texture_rotated_ex(graphics_texture* tex, float src_x, float src_y, float src_w, float src_h, float dst_x, float dst_y, float dst_w, float dst_h, double angle, float center_x, float center_y, int flip);
	bool set_logical_presentation(int w, int h, unsigned int mode);
	bool get_logical_presentation(int& w, int& h, unsigned int& mode) const;
	bool set_viewport(int x, int y, int w, int h);
	bool get_viewport(int& x, int& y, int& w, int& h) const;
	bool set_clip_rect(int x, int y, int w, int h);
	bool get_clip_rect(int& x, int& y, int& w, int& h) const;
	SDL_Renderer* get_renderer() const { return rend(); }
};
void graphics_collect(); // see there

void RegisterGraphics(asIScriptEngine* engine);
