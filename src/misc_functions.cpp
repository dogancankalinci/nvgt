/* misc_functions.cpp - code for any wrapped functions that we don't currently have a better place for
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
#include <string>
#include <algorithm>
#include <limits>
#include <bit>
#include <cstdint>
#include <vector>
#include <regex>
#include <math.h>
#ifdef _WIN32
	#define WIN32_LEAN_AND_MEAN
	#include <windows.h>
	#include <direct.h>
#else
	#include <unistd.h>
#endif
#include <Poco/AutoPtr.h>
#include <Poco/Exception.h>
#include <Poco/TextConverter.h>
#include <Poco/TextIterator.h>
#include <Poco/UnicodeConverter.h>
#include <Poco/UTF8Encoding.h>
#include <ctime>
#include <sstream>
#include <istream>
#include <deque>
#include <memory>
#include <mutex>
#include <thread>
#include <chrono>
#include <cerrno>
#include <cstring>
#include <angelscript.h>
#include <scriptarray.h>
#include <SDL3/SDL.h>
#include <tinyexpr.h>
#include <dbgtools.h>
#include "datastreams.h"
#include "nvgt_angelscript.h"
#include "nvgt.h"
#include "UI.h" // wait
#include "bl_number_to_words.h"
#include "obfuscate.h"
#include "input.h"
#include "misc_functions.h"
#include <fast_float/fast_float.h>
#include <system_error>

bool ChDir(const std::string& d) {
	#ifdef _WIN32
	return _chdir(d.c_str()) == 0;
	#else
	return chdir(d.c_str()) == 0;
	#endif
}
asBYTE character_to_ascii(const std::string& character) {
	if (character == "") return 0;
	return character[0];
}
std::string ascii_to_character(asBYTE ascii) {
	return std::string(1, ascii);
}
// next ffunction mostly from the cpptotp project:
std::string base32_normalize(const std::string& unnorm) {
	std::string ret;
	for (char c : unnorm) {
		if (c == ' ' || c == '\n' || c == '-') {
			// skip separators
		} else if (std::islower(c)) {
			// make uppercase
			char u = std::toupper(c);
			ret.push_back(u);
		} else
			ret.push_back(c);
	}
	while (ret.size() % 8 != 0)
		ret.push_back('=');
	return ret;
}
asQWORD timestamp() {
	return time(0);
}
std::string get_command_line() {
	return g_CommandLine;
}
template <typename T> T GenericRound(T n, int p) {
	T P = std::pow(static_cast<T>(10), std::abs(p));
	T result = (p > 0)? (std::round(n * P) / P) : (p < 0)? (std::round(n / P) * P) : std::round(n);
	return (result == static_cast<T>(0)) ? static_cast<T>(0) : result;
}
float fRound(float n, int p)   { return GenericRound<float>(n, p); }
double Round(double n, int p)  { return GenericRound<double>(n, p); }
enum process_flags {
	PROCESS_PIPE_STDIN = 1,        // connect stdin to a writable datastream
	PROCESS_PIPE_STDOUT = 2,       // connect stdout to a readable datastream
	PROCESS_PIPE_STDERR = 4,       // connect stderr to a readable datastream
	PROCESS_STDERR_TO_STDOUT = 8,  // redirect stderr into stdout (ignored if PROCESS_PIPE_STDERR is set)
	PROCESS_BACKGROUND = 16,       // run process detached from the console
	PROCESS_WAIT = 32,             // block until the process exits (used by the bool run() overload)
	PROCESS_FAIL_EXCEPTION = 64,   // throw a Poco::RuntimeException containing SDL_GetError() if the process fails to launch
	PROCESS_CAPTURE = 128,         // convenience flag: forces PROCESS_PIPE_STDOUT | PROCESS_PIPE_STDERR
};

// close_cb of a process's stdin datastream. Closing it closes the pipe, which is how a child that reads its input to the end learns it has all of it: before, the pipe stayed open until the process object went, so `p.stdin.close(); p.read()` with such a child (sort, a filter) waited for good. The stream's buffer is flushed and let go of first; SDL_CloseIO then also makes the SDL_Process forget the stream (its cleanup callback), so that SDL_DestroyProcess doesn't close it again.
static void process_stdin_close_cb(datastream* ds) {
	sdl_file_ios* fs = static_cast<sdl_file_ios*>(ds->user);
	if (!fs) return;
	SDL_IOStream* io = fs->nativeHandle();
	fs->detach();
	if (io) SDL_CloseIO(io);
}

// A process's stdout or stderr pipe, shared with the datastream the script may hold on it. The SDL_IOStream (non-blocking) belongs to the SDL_Process; io is nulled when the process object lets go of it. A child stops once it has written what a pipe holds until someone reads it, so wait(), read() and running move what it writes into pending, which read(), stdout and stderr serve before the pipe: otherwise a talkative child never ended (PROCESS_WAIT, wait() and the legacy run(..., true, ...) never returned), also where run() adds the pipes itself because no console is available. What pending holds unread is capped at max_pending: past it nothing more is moved, so a child whose output nobody reads stalls writing as it did before this buffer (rather than the script's memory growing for as long as the child writes), and goes on once read(), stdout or stderr take some of it; nothing is dropped.
struct process_pipe {
	static constexpr size_t max_pending = 64 * 1024 * 1024;
	std::mutex mtx;
	SDL_IOStream* io;
	std::deque<std::string> pending; // chunks as drain() moved them; the first is read from pending_pos (so taking a little at a time never moves what is left)
	size_t pending_pos = 0;
	size_t pending_size = 0; // bytes in pending not read yet
	bool ended = false; // every writer closed the pipe, or reading it failed
	explicit process_pipe(SDL_IOStream* io) : io(io) {}
	size_t read_device(char* buffer, size_t length) { // mtx held; never blocks
		if (!io || ended) return 0;
		size_t n = SDL_ReadIO(io, buffer, length);
		if (n == 0 && SDL_GetIOStatus(io) != SDL_IO_STATUS_NOT_READY) ended = true;
		return n;
	}
	bool drain() { // true if anything was moved
		std::lock_guard<std::mutex> lock(mtx);
		char buffer[16384];
		bool moved = false;
		size_t n;
		while (pending_size < max_pending && (n = read_device(buffer, std::min(sizeof(buffer), max_pending - pending_size))) > 0) {
			pending.emplace_back(buffer, n);
			pending_size += n;
			moved = true;
		}
		return moved;
	}
	size_t read(char* buffer, size_t length) {
		std::lock_guard<std::mutex> lock(mtx);
		if (pending_size) {
			const std::string& chunk = pending.front();
			size_t n = std::min(length, chunk.size() - pending_pos);
			memcpy(buffer, chunk.data() + pending_pos, n);
			pending_pos += n;
			pending_size -= n;
			if (pending_pos == chunk.size()) { pending.pop_front(); pending_pos = 0; }
			return n;
		}
		return read_device(buffer, length);
	}
	bool done() { std::lock_guard<std::mutex> lock(mtx); return !io || ended; }
};
class process_output_buf : public std::streambuf {
	std::shared_ptr<process_pipe> pipe;
	char buffer[4096];
protected:
	int_type underflow() override {
		if (gptr() < egptr()) return traits_type::to_int_type(*gptr());
		size_t n = pipe->read(buffer, sizeof(buffer));
		if (!n) return traits_type::eof(); // nothing yet, or the end: as the SDL stream wrapper did (the datastream sets skip_eof)
		setg(buffer, buffer, buffer + n);
		return traits_type::to_int_type(*gptr());
	}
public:
	explicit process_output_buf(std::shared_ptr<process_pipe> p) : pipe(std::move(p)) { setg(buffer, buffer, buffer); }
	void take_unread(std::string& out) { out.append(gptr(), egptr()); setg(buffer, buffer, buffer); }
};
class process_output_stream : public std::istream {
	process_output_buf buf;
public:
	explicit process_output_stream(std::shared_ptr<process_pipe> p) : std::istream(nullptr), buf(std::move(p)) { rdbuf(&buf); }
	void take_unread(std::string& out) { buf.take_unread(out); }
};

// A process let go of while its child may still write to its stdout/stderr pipes: SDL_DestroyProcess closed them under the child, whose next write then failed (SIGPIPE ends a POSIX child), as the legacy bool run() did to every child at once. A thread of its own now reads and discards what the child writes until every writer has closed the pipes; it makes no SDL call, as it may still run while SDL shuts down. The SDL_Process is destroyed afterwards by the next run() or process release (on exit, the system reclaims it).
#ifdef _WIN32
typedef HANDLE process_native_pipe;
#else
typedef int process_native_pipe;
#endif
struct process_orphans {
	std::mutex mtx;
	std::vector<SDL_Process*> done;
};
static process_orphans& get_process_orphans() {
	static process_orphans* orphans = new process_orphans(); // never destroyed: a drain thread may outlive static destruction
	return *orphans;
}
static void process_destroy_orphans() {
	std::vector<SDL_Process*> done;
	{
		process_orphans& o = get_process_orphans();
		std::lock_guard<std::mutex> lock(o.mtx);
		done.swap(o.done);
	}
	for (SDL_Process* proc : done) SDL_DestroyProcess(proc);
}
static int process_discard(process_native_pipe h) { // reads what the pipe holds now: 1 something read, 0 nothing yet, -1 the pipe ended
	char buffer[16384];
	int result = 0;
	for (;;) {
		#ifdef _WIN32
		DWORD n = 0;
		if (!ReadFile(h, buffer, sizeof(buffer), &n, nullptr)) return GetLastError() == ERROR_NO_DATA ? result : -1;
		if (n == 0) return result;
		#else
		ssize_t n = ::read(h, buffer, sizeof(buffer));
		if (n < 0 && errno == EINTR) continue;
		if (n < 0) return errno == EAGAIN || errno == EWOULDBLOCK ? result : -1;
		if (n == 0) return -1;
		#endif
		result = 1;
	}
}
static bool process_drain_orphan(SDL_Process* proc, std::vector<process_native_pipe> pipes) {
	try {
		std::thread([proc, pipes]() mutable {
			unsigned delay = 1;
			while (!pipes.empty()) {
				bool got = false;
				for (size_t i = 0; i < pipes.size();) {
					int r = process_discard(pipes[i]);
					if (r < 0) { pipes.erase(pipes.begin() + i); continue; }
					if (r > 0) got = true;
					i++;
				}
				if (pipes.empty()) break;
				if (got) delay = 1;
				else {
					std::this_thread::sleep_for(std::chrono::milliseconds(delay));
					delay = std::min(delay * 2, 50u);
				}
			}
			process_orphans& o = get_process_orphans();
			std::lock_guard<std::mutex> lock(o.mtx);
			o.done.push_back(proc);
		}).detach();
		return true;
	} catch (const std::exception&) { return false; } // no thread: the pipes close as before
}
static bool process_native_handle(SDL_IOStream* io, process_native_pipe& h) {
	SDL_PropertiesID props = SDL_GetIOProperties(io);
	#ifdef _WIN32
	h = static_cast<HANDLE>(SDL_GetPointerProperty(props, SDL_PROP_IOSTREAM_WINDOWS_HANDLE_POINTER, nullptr));
	return h && h != INVALID_HANDLE_VALUE;
	#else
	h = static_cast<int>(SDL_GetNumberProperty(props, SDL_PROP_IOSTREAM_FILE_DESCRIPTOR_NUMBER, -1));
	return h >= 0;
	#endif
}

class process {
	SDL_Process* _proc;
	std::shared_ptr<process_pipe> _out;
	std::shared_ptr<process_pipe> _err;
	Poco::AutoPtr<datastream> _stdin_ds;
	Poco::AutoPtr<datastream> _stdout_ds;
	Poco::AutoPtr<datastream> _stderr_ds;
	mutable int _refcount;
	static bool drain(const std::shared_ptr<process_pipe>& pipe) { return pipe && pipe->drain(); }
	bool drain_both() { bool out = drain(_out); return drain(_err) || out; }
	datastream* make_output_stream(const std::shared_ptr<process_pipe>& pipe) {
		datastream* ds = new datastream(new process_output_stream(pipe), nullptr, "", Poco::BinaryReader::NATIVE_BYTE_ORDER, nullptr);
		ds->binary = false;
		ds->skip_eof = true;
		return ds;
	}
	void detach_stdin() {
		sdl_file_ios* fs = _stdin_ds && _stdin_ds->get_ostr() ? dynamic_cast<sdl_file_ios*>(_stdin_ds->get_ostr()) : nullptr;
		if (fs) fs->detach();
	}
public:
	process(SDL_Process* proc) : _proc(proc), _refcount(1) {
		SDL_PropertiesID props = SDL_GetProcessProperties(proc);
		if (SDL_IOStream* io = static_cast<SDL_IOStream*>(SDL_GetPointerProperty(props, SDL_PROP_PROCESS_STDOUT_POINTER, nullptr))) _out = std::make_shared<process_pipe>(io);
		if (SDL_IOStream* io = static_cast<SDL_IOStream*>(SDL_GetPointerProperty(props, SDL_PROP_PROCESS_STDERR_POINTER, nullptr))) _err = std::make_shared<process_pipe>(io);
	}
	~process() {
		// Let go of every stdio wrapper before the SDL process goes; SDL_DestroyProcess frees the underlying SDL_IOStreams. A stdout/stderr datastream the script still holds serves what was moved off the pipe, then ends.
		detach_stdin();
		std::vector<process_native_pipe> open_pipes;
		for (std::shared_ptr<process_pipe>* pipe : {&_out, &_err}) {
			if (!*pipe) continue;
			std::lock_guard<std::mutex> lock((*pipe)->mtx);
			process_native_pipe h;
			if ((*pipe)->io && !(*pipe)->ended && process_native_handle((*pipe)->io, h)) open_pipes.push_back(h);
			(*pipe)->io = nullptr;
		}
		if (_proc && !open_pipes.empty()) {
			if (SDL_IOStream* in = static_cast<SDL_IOStream*>(SDL_GetPointerProperty(SDL_GetProcessProperties(_proc), SDL_PROP_PROCESS_STDIN_POINTER, nullptr))) SDL_CloseIO(in); // the child's input ends now, as it did when the process was destroyed here
			if (process_drain_orphan(_proc, std::move(open_pipes))) _proc = nullptr;
		}
		if (_proc) SDL_DestroyProcess(_proc);
		process_destroy_orphans();
	}
	void duplicate() { asAtomicInc(_refcount); }
	void release() { if (asAtomicDec(_refcount) < 1) delete this; }
	bool is_valid() const { return _proc != nullptr; }
	Sint64 get_pid() const {
		if (!_proc) return -1;
		return SDL_GetNumberProperty(SDL_GetProcessProperties(_proc), SDL_PROP_PROCESS_PID_NUMBER, -1);
	}
	bool kill(bool force = true) { return _proc && SDL_KillProcess(_proc, force); }
	bool running() {
		if (!_proc) return false;
		drain_both(); // a script polling this would otherwise wait for good on a child stalled writing
		return !SDL_WaitProcess(_proc, false, nullptr);
	}
	int wait() {
		int code = -1;
		if (!_proc) return code;
		if (!_out && !_err) {
			SDL_WaitProcess(_proc, true, &code);
			return code;
		}
		for (unsigned delay = 1; !SDL_WaitProcess(_proc, false, &code);) {
			if (drain_both()) delay = 1;
			else {
				SDL_Delay(delay);
				delay = std::min(delay * 2, 20u);
			}
		}
		drain_both(); // what was written just before the end
		return code;
	}
	std::string read() {
		if (!_proc || !_out) return "";
		// stdout to its end: first what the script's stdout datastream took off the pipe and hasn't read (read() used to skip it), then what wait() and running moved off it. stderr is drained meanwhile: a child stalled writing to it would never end its stdout.
		std::string result;
		if (_stdout_ds) if (process_output_stream* os = dynamic_cast<process_output_stream*>(_stdout_ds->get_istr())) os->take_unread(result);
		char buffer[16384];
		for (unsigned delay = 1;;) {
			size_t n = _out->read(buffer, sizeof(buffer));
			if (n) {
				result.append(buffer, n);
				delay = 1;
				continue;
			}
			if (_out->done()) break;
			if (drain(_err)) delay = 1;
			else {
				SDL_Delay(delay);
				delay = std::min(delay * 2, 20u);
			}
		}
		wait();
		return result;
	}
	datastream* get_stdin() {
		if (!_proc) return nullptr;
		if (!_stdin_ds) {
			SDL_IOStream* io = static_cast<SDL_IOStream*>(SDL_GetPointerProperty(SDL_GetProcessProperties(_proc), SDL_PROP_PROCESS_STDIN_POINTER, nullptr));
			if (!io) return nullptr;
			sdl_file_output_stream* os = new sdl_file_output_stream(io);
			datastream* ds = new datastream(nullptr, os, "", Poco::BinaryReader::NATIVE_BYTE_ORDER, nullptr);
			ds->user = static_cast<sdl_file_ios*>(os);
			ds->set_close_callback(process_stdin_close_cb);
			ds->binary = false;
			ds->skip_eof = true;
			ds->autoflush = true;
			_stdin_ds = ds;
		}
		return _stdin_ds.get();
	}
	datastream* get_stdout() {
		if (!_proc || !_out) return nullptr;
		if (!_stdout_ds) _stdout_ds = make_output_stream(_out);
		return _stdout_ds.get();
	}
	datastream* get_stderr() {
		if (!_proc || !_err) return nullptr;
		if (!_stderr_ds) _stderr_ds = make_output_stream(_err);
		return _stderr_ds.get();
	}
};

process* run(const std::vector<std::string>& args, int flags, const std::string& workdir) {
	if (args.empty()) return nullptr;
	process_destroy_orphans();
	// Expand convenience flags and auto-pipe stdout/stderr when no console is available (e.g. GUI subsystem on Windows, where DuplicateHandle on invalid stdio handles would otherwise cause CreateProcessWithProperties to fail).
	if ((flags & PROCESS_CAPTURE) || !is_console_available()) flags |= PROCESS_PIPE_STDOUT | PROCESS_PIPE_STDERR;
	std::vector<const char*> argv;
	argv.reserve(args.size() + 1);
	for (const auto& a : args) argv.push_back(a.c_str());
	argv.push_back(nullptr);
	SDL_PropertiesID props = SDL_CreateProperties();
	if (!props) return nullptr;
	SDL_SetPointerProperty(props, SDL_PROP_PROCESS_CREATE_ARGS_POINTER, argv.data());
	if (!workdir.empty()) SDL_SetStringProperty(props, SDL_PROP_PROCESS_CREATE_WORKING_DIRECTORY_STRING, workdir.c_str());
	if (flags & PROCESS_PIPE_STDIN) SDL_SetNumberProperty(props, SDL_PROP_PROCESS_CREATE_STDIN_NUMBER, SDL_PROCESS_STDIO_APP);
	if (flags & PROCESS_PIPE_STDOUT) SDL_SetNumberProperty(props, SDL_PROP_PROCESS_CREATE_STDOUT_NUMBER, SDL_PROCESS_STDIO_APP);
	if (flags & PROCESS_PIPE_STDERR) SDL_SetNumberProperty(props, SDL_PROP_PROCESS_CREATE_STDERR_NUMBER, SDL_PROCESS_STDIO_APP);
	if ((flags & PROCESS_STDERR_TO_STDOUT) && !(flags & PROCESS_PIPE_STDERR)) SDL_SetBooleanProperty(props, SDL_PROP_PROCESS_CREATE_STDERR_TO_STDOUT_BOOLEAN, true);
	if (flags & PROCESS_BACKGROUND) SDL_SetBooleanProperty(props, SDL_PROP_PROCESS_CREATE_BACKGROUND_BOOLEAN, true);
	SDL_Process* proc = SDL_CreateProcessWithProperties(props);
	SDL_DestroyProperties(props);
	if (!proc) {
		if (flags & PROCESS_FAIL_EXCEPTION) throw Poco::RuntimeException("process launch failed", SDL_GetError());
		return nullptr;
	}
	process* result = new process(proc);
	if (flags & PROCESS_WAIT) result->wait();
	return result;
}

static process* run_script(CScriptArray* args, int flags = 0, const std::string& workdir = "") {
	if (!args) return nullptr;
	std::vector<std::string> vargs;
	vargs.reserve(args->GetSize());
	for (asUINT i = 0; i < args->GetSize(); i++) vargs.push_back(*static_cast<std::string*>(args->At(i)));
	return run(vargs, flags, workdir);
}

bool run(const std::string& filename, const std::string& cmdline, bool wait_for_completion, bool background) {
	std::vector<std::string> args;
	args.push_back(filename);
	if (!cmdline.empty()) {
		std::istringstream iss(cmdline);
		std::string token;
		while (iss >> token) args.push_back(token);
	}
	int flags = (wait_for_completion ? PROCESS_WAIT : 0) | (background ? PROCESS_BACKGROUND : 0);
	Poco::AutoPtr<process> proc(run(args, flags, ""));
	return proc != nullptr;
}
// The parser and the evaluation recurse for each level of parentheses and each operator in a chain, and an expression is often the user's or the data's: 10000 opening parentheses (20 KB) overflowed the stack, which ends the program. A longer or deeper expression gives NaN, as one that doesn't parse does.
double tinyexpr(const std::string& expr) {
	int depth = 0, deepest = 0;
	for (char c : expr) {
		if (c == '(') deepest = std::max(deepest, ++depth);
		else if (c == ')') depth--;
	}
	if (expr.size() > 4096 || deepest > 256) return std::numeric_limits<double>::quiet_NaN();
	return te_interp(expr.c_str(), NULL);
}

std::string number_to_words(asINT64 number, bool include_and) {
	uint64_t magnitude = number < 0 ? 0 - uint64_t(number) : uint64_t(number);
	std::string output(128, '\0');
	size_t size = bl_number_to_words(magnitude, &output[0], 96, include_and);
	if (size > 96) {
		output.resize(size);
		size = bl_number_to_words(magnitude, &output[0], size, include_and);
	}
	output.resize(size - 1); // It appears bl_number_to_words includes a trailing null byte in it's size calculation.
	return number < 0 ? "negative " + output : output;
}
int get_last_error() {
	int e = g_LastError;
	g_LastError = 0;
	return e;
}
asQWORD get_process_id() {
	#ifdef _WIN32
	return GetCurrentProcessId();
	#else
	return getpid();
	#endif
}

double range_convert(double old_value, double old_min, double old_max, double new_min, double new_max) {
	return ((old_value - old_min) / (old_max - old_min)) * (new_max - new_min) + new_min;
}
float range_convert(float old_value, float old_min, float old_max, float new_min, float new_max) {
	return ((old_value - old_min) / (old_max - old_min)) * (new_max - new_min) + new_min;
}
float range_convert_midpoint(float old_value, float old_min, float old_midpoint, float old_max, float new_min, float new_midpoint, float new_max) {
	if (old_value < old_midpoint) return range_convert(old_value, old_min, old_midpoint, new_min, new_midpoint);
	else return range_convert(old_value, old_midpoint, old_max, new_midpoint, new_max);
}
std::string float_to_bytes(float f) {
	return std::string((char*)&f, 4);
}
// Copied out of the string: read in place through a float or double pointer, the bytes of a short string (kept inside the string
// object, at an odd address with libc++) were read with an instruction that needs an aligned address, ldrd for a double on
// armeabi-v7a, which faults there unless the kernel fixes the access up (AArch32 tasks on arm64 kernels before 6.1 got SIGBUS).
float bytes_to_float(const std::string& s) {
	if (s.size() != 4) return 0;
	float f;
	memcpy(&f, s.data(), sizeof(f));
	return f;
}
std::string double_to_bytes(double d) {
	return std::string((char*)&d, 8);
}
double bytes_to_double(const std::string& s) {
	if (s.size() != 8) return 0;
	double d;
	memcpy(&d, s.data(), sizeof(d)); // see bytes_to_float()
	return d;
}

std::string string_to_upper_case(std::string s) {
	for (int i = 0; i < (int)s.length(); i++)
		s[i] = toupper(s[i]);
	return s;
}

//Following function originally from https://stackoverflow.com/questions/642213/how-to-implement-a-natural-sort-algorithm-in-c
// Compares as before (runs of digits by their value, other characters case-insensitively at the first that differs), but:
// - equal strings compare false: both ending together returned true, so x < x held, which a sort's comparison must never give;
// - a run of digits is compared whatever its length: read into an int, a longer one failed to parse, compared equal to any other such run
//   and lost the rest of the string (a99999999999b and a100000000000a were "equal" and both then empty);
// - the rest of the string after a number was read with getline(), which stopped at a newline and dropped what followed;
// - isdigit() was given negative values for bytes above 127 (UTF-8), which is undefined.
static bool natural_is_digit(char c) { return c >= '0' && c <= '9'; }
bool natural_number_sort(const std::string& first, const std::string& second) {
	size_t i = 0, j = 0;
	const size_t m = first.size(), n = second.size();
	while (true) {
		if (i >= m) return j < n;
		if (j >= n) return false;
		bool da = natural_is_digit(first[i]), db = natural_is_digit(second[j]);
		if (da && !db) return true;
		if (!da && db) return false;
		if (!da) {
			if (first[i] != second[j])
				return string_to_upper_case(first.substr(i)) < string_to_upper_case(second.substr(j));
			i++;
			j++;
			continue;
		}
		size_t ea = i, eb = j;
		while (ea < m && natural_is_digit(first[ea])) ea++;
		while (eb < n && natural_is_digit(second[eb])) eb++;
		size_t za = i, zb = j; // the value's first significant digit
		while (za < ea - 1 && first[za] == '0') za++;
		while (zb < eb - 1 && second[zb] == '0') zb++;
		if (ea - za != eb - zb) return ea - za < eb - zb;
		int c = first.compare(za, ea - za, second, zb, eb - zb);
		if (c) return c < 0;
		i = ea;
		j = eb;
	}
}

refstring* new_refstring() {
	return new refstring();
}

template<typename T> typename T::size_type LevenshteinDistance(const T& source, const T& target, typename T::size_type insert_cost = 1, typename T::size_type delete_cost = 1, typename T::size_type replace_cost = 1) {
	if (source.size() > target.size())
		return LevenshteinDistance(target, source, delete_cost, insert_cost, replace_cost);
	using TSizeType = typename T::size_type;
	const TSizeType min_size = source.size(), max_size = target.size();
	std::vector<TSizeType> lev_dist(min_size + 1);
	lev_dist[0] = 0;
	for (TSizeType i = 1; i <= min_size; ++i)
		lev_dist[i] = lev_dist[i - 1] + delete_cost;
	for (TSizeType j = 1; j <= max_size; ++j) {
		TSizeType previous_diagonal = lev_dist[0], previous_diagonal_save;
		lev_dist[0] += insert_cost;
		for (TSizeType i = 1; i <= min_size; ++i) {
			previous_diagonal_save = lev_dist[i];
			if (source[i - 1] == target[j - 1])
				lev_dist[i] = previous_diagonal;
			else
				lev_dist[i] = std::min(std::min(lev_dist[i - 1] + delete_cost, lev_dist[i] + insert_cost), previous_diagonal + replace_cost);
			previous_diagonal = previous_diagonal_save;
		}
	}
	return lev_dist[min_size];
}
int string_distance(const std::string& a, const std::string& b, unsigned int insert_cost = 1, unsigned int delete_cost = 1, unsigned int replace_cost = 1) {
	return LevenshteinDistance<std::string>(a, b, insert_cost, delete_cost, replace_cost);
}
int utf8prev(const std::string& text, int offset = 0) {
	if (offset < 1 || offset > text.size()) return offset - 1;
	offset--;
	char b = text[offset];
	while ((b & (1 << 7)) != 0 && (b & (1 << 6)) == 0) { // UTF8 continuation char
		offset--;
		if (offset < 0) break;
		b = text[offset];
	}
	return offset;
}
int utf8size(const std::string& character) {
	if (character.size() < 1) return 0;
	char b = character[0];
	if (b & 1 << 7) {
		if (b & 1 << 6) {
			if (b & 1 << 5) {
				if (b & 1 << 4) {
					return 4; // because bit pattern 1111
				}
				return 3; // because bit pattern 111
			}
			return 2; // because bit pattern 11
		}
		return 1; // apparently stuck in the middle of a character
	}
	return 1; // char is less than 128
}
int utf8next(const std::string& text, int offset = 0) {
	if (offset < 0) return offset - 1;
	if (offset >= text.size()) return offset + 1;
	return offset + utf8size(text.substr(offset, 1));
}

/**
 * Checks whether a string is valid UTF-8.
 * Can also prohibit strings containing ASCII special characters.
 * Used internally by pack file, sound service.
 * written by Caturria.
 */
bool is_valid_utf8(const std::string &text, bool ban_ascii_special) {
	Poco::UTF8Encoding encoding;
	Poco::TextIterator i(text, encoding);
	Poco::TextIterator end(text);
	while (i != end) {
		// Reject entirely invalid characters:
		if (*i == -1)
			return false;
		// Also reject ASCII 0 - 31 and 127 as these are not printable characters:
		if ((*i < 32 || *i == 127) && ban_ascii_special)
			return false;
		i++;
	}
	return true;
}
CScriptArray* get_preferred_locales() {
	asITypeInfo* arrayType = get_array_type("array<string>");
	CScriptArray* array = CScriptArray::Create(arrayType);
	int count;
	SDL_Locale** locales = SDL_GetPreferredLocales(&count);
	if (!locales) return array;
	for (int i = 0; i < count; i++) {
		std::string tmp = locales[i]->language;
		if (locales[i]->country) tmp += std::string("-") + locales[i]->country;
		array->Resize(array->GetSize() + 1);
		((std::string*)(array->At(array->GetSize() - 1)))->assign(tmp);
	}
	SDL_free(locales);
	return array;
}

float parse_float(const std::string& val) {
	float res = 0.0;
	const auto[valPtr, valEc] = fast_float::from_chars(val.data(), val.data() + val.size(), res);
	if (valEc != std::errc()) return 0.0;
	return res;
}
double parse_double(const std::string& val) {
	double res = 0.0;
	const auto[valPtr, valEc] = fast_float::from_chars(val.data(), val.data() + val.size(), res);
	if (valEc != std::errc()) return 0.0;
	return res;
}

// Small wrapper which allows statically typed read-write access to an arbitrary memory buffer from scripts.
// It should be implicitly understood by the scripter that this interface is low level, contains minimal handholding and is not subject to sandboxing!
const void* script_memory_buffer::at(size_t index) const {
	if (!fits()) throw std::out_of_range("memory buffer address or size out of range on this platform");
	if (!ptr) throw std::invalid_argument("memory buffer null pointer access");
	int typesize = g_ScriptEngine->GetSizeOfPrimitiveType(subtypeid);
	if (size && index >= size) throw std::out_of_range("index out of bounds");
	return (void*)(((char*)ptr) + (index * typesize));
}
void* script_memory_buffer::at(size_t index) { return const_cast<void*>(const_cast<const script_memory_buffer*>(this)->at(index)); }
CScriptArray* script_memory_buffer::to_array() const {
	if (!fits()) throw std::out_of_range("memory buffer address or size out of range on this platform");
	// The array type is the one this template instance's conversion returns. It was looked up by name on the engine, which sees no type of a module: for a script enum the lookup failed and the array was made with no type (a crash at `E[]@ a = buffer;`). And a type found by name was cached with no reference: array<uint16>, which nothing registered names, went when the module that used it was discarded, and the next conversion used the freed type.
	asIScriptFunction* conversion = subtype->GetMethodByName("opImplConv");
	asITypeInfo* array_type = conversion ? g_ScriptEngine->GetTypeInfoById(conversion->GetReturnTypeId()) : nullptr;
	if (!array_type) return nullptr;
	CScriptArray* array = CScriptArray::Create(array_type, size);
	if (!array) return nullptr;
	std::memcpy(array->GetBuffer(), ptr, size * g_ScriptEngine->GetSizeOfPrimitiveType(subtypeid));
	return array;
}
script_memory_buffer& script_memory_buffer::from_array(CScriptArray* array) {
	if (!fits()) throw std::out_of_range("memory buffer address or size out of range on this platform");
	if (!array) std::memset(ptr, 0, size * g_ScriptEngine->GetSizeOfPrimitiveType(subtypeid));
	else std::memcpy(ptr, array->GetBuffer(), (array->GetSize() < size? array->GetSize() : size) * g_ScriptEngine->GetSizeOfPrimitiveType(subtypeid));
	return *this;
}
int script_memory_buffer::get_element_size() const {return g_ScriptEngine->GetSizeOfPrimitiveType(subtypeid); }
// The script's address, size and index are uint64 while ptr and size are a pointer and a size_t, 4 bytes on 32-bit targets: the
// properties read and wrote 8 bytes over a 4-byte member (size came back with the next member in its upper half), opIndex(uint64)
// passed its index where at(size_t) didn't look for it (armeabi-v7a puts a 64-bit argument in an even register pair, so at() got the
// register skipped before it, 0 or garbage), and the constructor took its size from the upper half of the address (0, which turned
// the bounds check off). The properties now sit on 64-bit members that hold ptr and size in their low half (see the struct), so
// scripts can still use them as variables (b.address += 4); the index and the constructor's values are converted here, and a value
// that doesn't fit is refused.
static_assert(std::endian::native == std::endian::little, "script_memory_buffer keeps ptr and size in the low half of a uint64");
static size_t memory_buffer_size_t(asQWORD value, const char* what) {
	if (value > asQWORD(SIZE_MAX)) throw std::out_of_range(std::string(what) + " out of range on this platform");
	return size_t(value);
}
void script_memory_buffer::make(script_memory_buffer* mem, asITypeInfo* subtype, asQWORD ptr, asQWORD size) { new(mem) script_memory_buffer(subtype, (void*)memory_buffer_size_t(ptr, "address"), memory_buffer_size_t(size, "size")); }
void* script_memory_buffer::at_script(script_memory_buffer* mem, asQWORD index) { return mem->at(memory_buffer_size_t(index, "index")); }
void script_memory_buffer::copy(script_memory_buffer* mem, asITypeInfo* subtype, const script_memory_buffer& other) { new(mem) script_memory_buffer(other); }
void script_memory_buffer::destroy(script_memory_buffer* mem) { mem->~script_memory_buffer(); }
bool script_memory_buffer::verify(asITypeInfo *subtype, bool& no_gc) {
	if (subtype->GetSubTypeId() & asTYPEID_MASK_OBJECT ) return false;
	return no_gc = true;
}
void script_memory_buffer::angelscript_register(asIScriptEngine* engine) {
	engine->RegisterObjectType("memory_buffer<class T>", sizeof(script_memory_buffer), asOBJ_VALUE | asOBJ_TEMPLATE | asGetTypeTraits<script_memory_buffer>());
	engine->RegisterObjectBehaviour("memory_buffer<T>", asBEHAVE_CONSTRUCT, "void f(int&in subtype, uint64 ptr, uint64 size)", asFUNCTION(make), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectBehaviour("memory_buffer<T>", asBEHAVE_CONSTRUCT, "void f(int&in subtype, const memory_buffer<T>&in other)", asFUNCTION(copy), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectBehaviour("memory_buffer<T>", asBEHAVE_TEMPLATE_CALLBACK, "bool f(int&in subtype, bool&out no_gc)", asFUNCTION(verify), asCALL_CDECL);
	engine->RegisterObjectBehaviour("memory_buffer<T>", asBEHAVE_DESTRUCT, "void f()", asFUNCTION(destroy), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectProperty("memory_buffer<T>", "uint64 address", asOFFSET(script_memory_buffer, address_bits));
	engine->RegisterObjectProperty("memory_buffer<T>", "uint64 size", asOFFSET(script_memory_buffer, size_bits));
	engine->RegisterObjectMethod("memory_buffer<T>", "T& opIndex(uint64 index)", asFUNCTION(at_script), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("memory_buffer<T>", "const T& opIndex(uint64 index) const", asFUNCTION(at_script), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("memory_buffer<T>", "array<T>@ opImplConv() const", asMETHOD(script_memory_buffer, to_array), asCALL_THISCALL);
	engine->RegisterObjectMethod("memory_buffer<T>", "memory_buffer<T>& opAssign(array<T>@+ array)", asMETHOD(script_memory_buffer, from_array), asCALL_THISCALL);
	engine->RegisterObjectMethod("memory_buffer<T>", "int get_element_size() const property", asMETHOD(script_memory_buffer, get_element_size), asCALL_THISCALL);
}
// Returned as the script's uint64 (see memory_buffer above): as a void*, a 32-bit target returned 4 bytes and the script read the
// other 4 from whatever the function left in the register next to them.
asQWORD string_get_address(std::string& str) {
	if (str.size() < 1) return 0;
	return asQWORD(uintptr_t(&str[0]));
}

// malloc() and the rest take and return size_t and void*, 4 bytes on 32-bit targets, where they were bound to the script's uint64
// directly: calloc() took its count from the upper half of the unit size (0), realloc() its size from the upper half of the address
// (0, which freed the block), and each returned address came with whatever was in the register next to it as its upper half. A size
// that doesn't fit a size_t can't be allocated (0, as malloc() fails); an address that doesn't fit a pointer is refused.
static asQWORD script_memory_allocate(asQWORD size) { return size > asQWORD(SIZE_MAX) ? 0 : asQWORD(uintptr_t(malloc(size_t(size)))); }
static asQWORD script_memory_allocate_units(asQWORD unit_size, asQWORD unit_count) { return unit_size > asQWORD(SIZE_MAX) || unit_count > asQWORD(SIZE_MAX) ? 0 : asQWORD(uintptr_t(calloc(size_t(unit_size), size_t(unit_count)))); }
static asQWORD script_memory_reallocate(asQWORD ptr, asQWORD size) { void* p = (void*)memory_buffer_size_t(ptr, "address"); return size > asQWORD(SIZE_MAX) ? 0 : asQWORD(uintptr_t(realloc(p, size_t(size)))); }
static void script_memory_free(asQWORD ptr) { free((void*)memory_buffer_size_t(ptr, "address")); }

// The script reads a bool (one byte); dbgtools returns an int, on Windows IsDebuggerPresent()'s BOOL, documented only as nonzero.
bool is_debugger_present() {
	return debugger_present() != 0;
}
void RegisterMiscFunctions(asIScriptEngine* engine) {
	engine->SetDefaultAccessMask(NVGT_SUBSYSTEM_OS);
	engine->RegisterGlobalFunction(_O("bool chdir(const string& in directory)"), asFUNCTION(ChDir), asCALL_CDECL);
	engine->SetDefaultAccessMask(NVGT_SUBSYSTEM_DATA);
	engine->RegisterGlobalFunction(_O("uint8 character_to_ascii(const string&in character)"), asFUNCTION(character_to_ascii), asCALL_CDECL);
	engine->RegisterGlobalFunction(_O("string ascii_to_character(uint8 character_code)"), asFUNCTION(ascii_to_character), asCALL_CDECL);
	engine->RegisterGlobalFunction(_O("string string_base32_normalize(const string& in base32encoded)"), asFUNCTION(base32_normalize), asCALL_CDECL);
	engine->SetDefaultAccessMask(NVGT_SUBSYSTEM_DATETIME);
	engine->RegisterGlobalFunction(_O("uint64 get_TIME_STAMP() property"), asFUNCTION(timestamp), asCALL_CDECL);
	engine->SetDefaultAccessMask(NVGT_SUBSYSTEM_OS);
	engine->RegisterGlobalFunction(_O("string[]@ get_preferred_locales()"), asFUNCTION(get_preferred_locales), asCALL_CDECL);
	engine->RegisterGlobalFunction(_O("string get_COMMAND_LINE() property"), asFUNCTION(get_command_line), asCALL_CDECL);
	engine->RegisterEnum(_O("process_flags"));
	engine->RegisterEnumValue(_O("process_flags"), _O("PROCESS_PIPE_STDIN"), PROCESS_PIPE_STDIN);
	engine->RegisterEnumValue(_O("process_flags"), _O("PROCESS_PIPE_STDOUT"), PROCESS_PIPE_STDOUT);
	engine->RegisterEnumValue(_O("process_flags"), _O("PROCESS_PIPE_STDERR"), PROCESS_PIPE_STDERR);
	engine->RegisterEnumValue(_O("process_flags"), _O("PROCESS_STDERR_TO_STDOUT"), PROCESS_STDERR_TO_STDOUT);
	engine->RegisterEnumValue(_O("process_flags"), _O("PROCESS_BACKGROUND"), PROCESS_BACKGROUND);
	engine->RegisterEnumValue(_O("process_flags"), _O("PROCESS_WAIT"), PROCESS_WAIT);
	engine->RegisterEnumValue(_O("process_flags"), _O("PROCESS_FAIL_EXCEPTION"), PROCESS_FAIL_EXCEPTION);
	engine->RegisterEnumValue(_O("process_flags"), _O("PROCESS_CAPTURE"), PROCESS_CAPTURE);
	engine->RegisterObjectType(_O("process"), 0, asOBJ_REF);
	engine->RegisterObjectBehaviour(_O("process"), asBEHAVE_ADDREF, _O("void f()"), asMETHOD(process, duplicate), asCALL_THISCALL);
	engine->RegisterObjectBehaviour(_O("process"), asBEHAVE_RELEASE, _O("void f()"), asMETHOD(process, release), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("process"), _O("bool get_valid() const property"), asMETHOD(process, is_valid), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("process"), _O("int64 get_pid() const property"), asMETHOD(process, get_pid), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("process"), _O("bool get_running() const property"), asMETHOD(process, running), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("process"), _O("bool kill(bool force = true)"), asMETHOD(process, kill), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("process"), _O("int wait()"), asMETHOD(process, wait), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("process"), _O("string read()"), asMETHOD(process, read), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("process"), _O("datastream@+ get_stdin() property"), asMETHOD(process, get_stdin), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("process"), _O("datastream@+ get_stdout() property"), asMETHOD(process, get_stdout), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("process"), _O("datastream@+ get_stderr() property"), asMETHOD(process, get_stderr), asCALL_THISCALL);
	engine->RegisterGlobalFunction(_O("process@ run(const string[]& in args, int flags = 0, const string& in workdir = \"\")"), asFUNCTION(run_script), asCALL_CDECL);
	engine->RegisterGlobalFunction(_O("bool run(const string& in filename, const string& in arguments, bool wait_for_completion, bool background)"), asFUNCTIONPR(run, (const std::string&, const std::string&, bool, bool), bool), asCALL_CDECL);
	engine->RegisterGlobalFunction(_O("bool is_debugger_present()"), asFUNCTION(is_debugger_present), asCALL_CDECL);
	engine->RegisterGlobalFunction(_O("int get_last_error()"), asFUNCTION(get_last_error), asCALL_CDECL);
	engine->RegisterGlobalFunction(_O("uint64 get_process_id()"), asFUNCTION(get_process_id), asCALL_CDECL);
	engine->SetDefaultAccessMask(NVGT_SUBSYSTEM_GENERAL);
	engine->RegisterGlobalFunction(_O("double round(double number, int place)"), asFUNCTION(Round), asCALL_CDECL);
	engine->RegisterGlobalFunction(_O("double tinyexpr(const string &in expression)"), asFUNCTION(tinyexpr), asCALL_CDECL);
	engine->SetDefaultAccessMask(NVGT_SUBSYSTEM_DATA);
	engine->RegisterGlobalFunction(_O("string number_to_words(int64 number, bool include_and = true)"), asFUNCTION(number_to_words), asCALL_CDECL);
	engine->RegisterGlobalFunction(_O("uint string_distance(const string&in string1, const string&in string2, uint insert_cost = 1, uint delete_cost = 1, uint replace_cost = 1)"), asFUNCTION(string_distance), asCALL_CDECL);
	engine->RegisterGlobalFunction(_O("string float_to_bytes(float number)"), asFUNCTION(float_to_bytes), asCALL_CDECL);
	engine->RegisterGlobalFunction(_O("float bytes_to_float(const string&in data)"), asFUNCTION(bytes_to_float), asCALL_CDECL);
	engine->RegisterGlobalFunction(_O("string double_to_bytes(double number)"), asFUNCTION(double_to_bytes), asCALL_CDECL);
	engine->RegisterGlobalFunction(_O("double bytes_to_double(const string&in data)"), asFUNCTION(bytes_to_double), asCALL_CDECL);
	engine->RegisterGlobalFunction(_O("bool natural_number_sort(const string&in string1, const string&in string2)"), asFUNCTION(natural_number_sort), asCALL_CDECL);
	engine->RegisterGlobalFunction(_O("int utf8prev(const string&in text, int cursor)"), asFUNCTION(utf8prev), asCALL_CDECL);
	engine->RegisterGlobalFunction(_O("int utf8next(const string&in text, int cursor)"), asFUNCTION(utf8next), asCALL_CDECL);
	engine->RegisterGlobalFunction(_O("int utf8size(const string&in character)"), asFUNCTION(utf8size), asCALL_CDECL);
	engine->RegisterGlobalFunction(_O("bool utf8valid(const string&in text, bool ban_ascii_special = true)"), asFUNCTION(is_valid_utf8), asCALL_CDECL);
	engine->SetDefaultAccessMask(NVGT_SUBSYSTEM_GENERAL);
	engine->RegisterObjectType(_O("refstring"), 0, asOBJ_REF);
	engine->RegisterObjectBehaviour(_O("refstring"), asBEHAVE_FACTORY, _O("refstring @s()"), asFUNCTION(new_refstring), asCALL_CDECL);
	engine->RegisterObjectBehaviour(_O("refstring"), asBEHAVE_ADDREF, _O("void f()"), asMETHOD(refstring, AddRef), asCALL_THISCALL);
	engine->RegisterObjectBehaviour(_O("refstring"), asBEHAVE_RELEASE, _O("void f()"), asMETHOD(refstring, Release), asCALL_THISCALL);
	engine->RegisterObjectProperty(_O("refstring"), _O("string str"), asOFFSET(refstring, str));
	engine->RegisterGlobalFunction(_O("uint64 memory_allocate(uint64 size)"), asFUNCTION(script_memory_allocate), asCALL_CDECL);
	engine->RegisterGlobalFunction(_O("uint64 memory_allocate_units(uint64 unit_size, uint64 unit_count)"), asFUNCTION(script_memory_allocate_units), asCALL_CDECL);
	engine->RegisterGlobalFunction(_O("uint64 memory_reallocate(uint64 ptr, uint64 size)"), asFUNCTION(script_memory_reallocate), asCALL_CDECL);
	engine->RegisterGlobalFunction(_O("void memory_free(uint64 ptr)"), asFUNCTION(script_memory_free), asCALL_CDECL);
	engine->RegisterGlobalFunction("float parse_float(const string &in number)", asFUNCTION(parse_float), asCALL_CDECL);
	engine->RegisterGlobalFunction("double parse_double(const string &in number)", asFUNCTION(parse_double), asCALL_CDECL);
	engine->RegisterEnum("system_power_state");
	engine->RegisterEnumValue("system_power_state", "POWER_STATE_ERROR", SDL_POWERSTATE_ERROR);
	engine->RegisterEnumValue("system_power_state", "POWER_STATE_UNKNOWN", SDL_POWERSTATE_UNKNOWN);
	engine->RegisterEnumValue("system_power_state", "POWER_STATE_ON_BATTERY", SDL_POWERSTATE_ON_BATTERY);
	engine->RegisterEnumValue("system_power_state", "POWER_STATE_NO_BATTERY", SDL_POWERSTATE_NO_BATTERY);
	engine->RegisterEnumValue("system_power_state", "POWER_STATE_CHARGING", SDL_POWERSTATE_CHARGING);
	engine->RegisterEnumValue("system_power_state", "POWER_STATE_CHARGED", SDL_POWERSTATE_CHARGED);
	engine->RegisterGlobalFunction("system_power_state system_power_info(int&out seconds = void, int&out percent = void)", asFUNCTION(SDL_GetPowerInfo), asCALL_CDECL);
	engine->SetDefaultAccessMask(NVGT_SUBSYSTEM_RAW_MEMORY);
	script_memory_buffer::angelscript_register(engine);
	engine->RegisterObjectMethod("string", "uint64 get_address() const property", asFUNCTION(string_get_address), asCALL_CDECL_OBJFIRST);
}
