/* linux.cpp - module containing functions only applicable to Linux and Unix platforms
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

#if !defined(__ANDROID__) && (defined(__linux__) || defined(__unix__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__DragonFly__))
#include "linux.h"
#include "tts.h"
#include "UI.h"
#include <algorithm>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <map>
#include <memory>
#include <mutex>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <Poco/SharedLibrary.h>
#include <stdexcept>
using namespace std;

#define spd_get_default_address (*spd_get_default_address)
#define spd_open2 (*spd_open2)
#define spd_close (*spd_close)
#define spd_say (*spd_say)
#define spd_stop (*spd_stop)
#define spd_cancel (*spd_cancel)
#define spd_set_notification_on (*spd_set_notification_on)
#define spd_get_language (*spd_get_language)
#include <speech-dispatcher/libspeechd.h>
#undef spd_get_default_address
#undef spd_open2
#undef spd_close
#undef spd_say
#undef spd_stop
#undef spd_cancel
#undef spd_set_notification_on
#undef spd_get_language

static Poco::SharedLibrary g_speechd_lib;
static bool g_speechd_lib_loaded = false;

static bool load_speechd_library() {
	if (g_speechd_lib_loaded) return true;
	try {
		try {
			g_speechd_lib.load("libspeechd.so.2");
		} catch (Poco::Exception&) {
			g_speechd_lib.load("libspeechd.so");
		}
		*(void**)&spd_get_default_address = g_speechd_lib.getSymbol("spd_get_default_address");
		*(void**)&spd_open2 = g_speechd_lib.getSymbol("spd_open2");
		*(void**)&spd_close = g_speechd_lib.getSymbol("spd_close");
		*(void**)&spd_say = g_speechd_lib.getSymbol("spd_say");
		*(void**)&spd_stop = g_speechd_lib.getSymbol("spd_stop");
		*(void**)&spd_cancel = g_speechd_lib.getSymbol("spd_cancel");
		try {
			*(void**)&spd_set_notification_on = g_speechd_lib.getSymbol("spd_set_notification_on");
		} catch (Poco::Exception&) {} // Then nothing reports when speech ends.
		try {
			*(void**)&spd_get_language = g_speechd_lib.getSymbol("spd_get_language");
		} catch (Poco::Exception&) {} // Then the language is unknown.
		g_speechd_lib_loaded = true;
		return true;
	} catch (Poco::Exception&) {
		return false;
	}
}

// libspeechd writes to its socket with write(), and a write after the server went away raises SIGPIPE, which ends the process. Every call into it is made with SIGPIPE blocked in the calling thread, and a SIGPIPE the call raised, which is directed at that thread, is taken off before the old mask returns.
class speechd_call_guard {
	sigset_t old_mask;
	bool was_pending;
public:
	speechd_call_guard() {
		sigset_t sigpipe, pending;
		sigemptyset(&sigpipe);
		sigaddset(&sigpipe, SIGPIPE);
		pthread_sigmask(SIG_BLOCK, &sigpipe, &old_mask);
		sigpending(&pending);
		was_pending = sigismember(&pending, SIGPIPE);
	}
	~speechd_call_guard() {
		sigset_t sigpipe, pending;
		sigemptyset(&sigpipe);
		sigaddset(&sigpipe, SIGPIPE);
		sigpending(&pending);
		if (!was_pending && sigismember(&pending, SIGPIPE)) {
			int signal_number;
			sigwait(&sigpipe, &signal_number);
		}
		pthread_sigmask(SIG_SETMASK, &old_mask, nullptr);
	}
};

static unsigned long long monotonic_milliseconds() {
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
	return (unsigned long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

// The server reports the start, end or cancellation of each message to callbacks that get no context, on libspeechd's event thread. Message numbers come from the server, unique across its connections, so one table serves every engine, each of which has a connection of its own, and records whose message each one is. They are unique only while one server runs, though: after it restarts, an engine that hasn't noticed its connection is gone still holds old numbers, and a report that arrives for a message of a dropped connection lands among the early ones. So a number said again takes the pending entry over, and an early report counts only for two seconds, as it only bridges spd_say sending a message and returning its number.
struct speechd_message {
	const speechd_engine *engine;
	unsigned long long said, begun; // When spd_say returned its number, and when the server reported it starting, 0 until then.
	size_t length;
};
struct speechd_early_report {
	unsigned long long at;
	bool ended;
};
static std::mutex g_speechd_messages_mutex;
static std::map<int, speechd_message> g_speechd_pending; // Said, and neither ended nor cancelled yet.
static std::map<int, speechd_early_report> g_speechd_early; // Begun or ended before spd_say returned their number.
static unsigned long long g_speechd_last_report = 0; // When the server last reported on a message in the table.
static void speechd_note_early(int msg_id, unsigned long long now, bool ended) {
	for (auto it = g_speechd_early.begin(); it != g_speechd_early.end();) {
		if (now - it->second.at >= 2000) it = g_speechd_early.erase(it);
		else ++it;
	}
	speechd_early_report &report = g_speechd_early[msg_id];
	if (!report.ended) report = {now, ended};
}
// A connection's messages are spoken in the order they were said, so once the server reports on one, the same engine's earlier messages it never reported ending were lost, as when an output module dies.
static void speechd_drop_earlier(std::map<int, speechd_message>::iterator reported) {
	const speechd_engine *engine = reported->second.engine;
	for (auto it = g_speechd_pending.begin(); it != reported;) {
		if (it->second.engine == engine) it = g_speechd_pending.erase(it);
		else ++it;
	}
}
static void speechd_message_begun(size_t msg_id, size_t client_id, SPDNotificationType state) {
	std::lock_guard<std::mutex> lock(g_speechd_messages_mutex);
	unsigned long long now = monotonic_milliseconds();
	auto it = g_speechd_pending.find((int)msg_id);
	if (it == g_speechd_pending.end()) return speechd_note_early((int)msg_id, now, false);
	g_speechd_last_report = now;
	if (!it->second.begun) it->second.begun = now;
	speechd_drop_earlier(it);
}
static void speechd_message_ended(size_t msg_id, size_t client_id, SPDNotificationType state) {
	std::lock_guard<std::mutex> lock(g_speechd_messages_mutex);
	unsigned long long now = monotonic_milliseconds();
	auto it = g_speechd_pending.find((int)msg_id);
	if (it == g_speechd_pending.end()) return speechd_note_early((int)msg_id, now, true);
	g_speechd_last_report = now;
	speechd_drop_earlier(it);
	g_speechd_pending.erase(it);
}
// The server says nothing more of a message when its output module dies, or it reloads its configuration, while the message is spoken, and none of the same engine's follows to show it was lost. So a message stops counting once it has taken far longer than speaking its text can: from its start, or for one not reported starting, from when it was said or the server last reported on a message, whichever is later, and only while no started message is still within its time, as it may be waiting for that one. Expects g_speechd_messages_mutex held.
static unsigned long long speechd_message_time(size_t length) { return 30000 + 200ULL * length; }
static void speechd_drop_lost(unsigned long long now) {
	bool speaking = false;
	for (const auto &message : g_speechd_pending) {
		if (message.second.begun && now - message.second.begun < speechd_message_time(message.second.length)) speaking = true;
	}
	for (auto it = g_speechd_pending.begin(); it != g_speechd_pending.end();) {
		const speechd_message &message = it->second;
		unsigned long long since = message.begun? message.begun : std::max(message.said, g_speechd_last_report);
		if ((message.begun || !speaking) && now - since >= speechd_message_time(message.length)) it = g_speechd_pending.erase(it);
		else ++it;
	}
}
static bool speechd_message_pending(int msg_id) {
	std::lock_guard<std::mutex> lock(g_speechd_messages_mutex);
	speechd_drop_lost(monotonic_milliseconds());
	return g_speechd_pending.count(msg_id) > 0;
}

speechd_engine::speechd_engine() : tts_engine_impl("Speech Dispatcher"), connection(nullptr), loaded(false), notifying(false), last_open(0), socket_inode(0) {
	if (!load_speechd_library()) return;
	loaded = open_connection();
}

speechd_engine::~speechd_engine() {
	std::lock_guard<std::mutex> lock(state_mutex);
	drop_connection();
}

bool speechd_engine::open_connection() {
	last_open = monotonic_milliseconds();
	// When it fails, libspeechd writes a message through the error pointer without checking it for null, so one must be given. Without an address spd_open2 looks up, and frees, the default one itself.
	char *error = nullptr;
	SPDConnection *opened;
	{
		speechd_call_guard guard;
		opened = spd_open2("NVGT", nullptr, nullptr, SPD_MODE_THREADED, nullptr, true, &error);
	}
	free(error);
	if (!opened) return false;
	opened->callback_begin = speechd_message_begun;
	opened->callback_end = opened->callback_cancel = speechd_message_ended;
	{
		speechd_call_guard guard;
		notifying = spd_set_notification_on && spd_set_notification_on(opened, SPD_END) == 0 && spd_set_notification_on(opened, SPD_CANCEL) == 0;
		if (!notifying || spd_set_notification_on(opened, SPD_BEGIN) != 0) opened->callback_begin = nullptr; // Starts only make lost messages found sooner.
	}
	if (!notifying) opened->callback_end = opened->callback_cancel = nullptr; // Ends that can't all be reported are not tracked.
	struct stat socket_status;
	socket_inode = fstat(opened->socket, &socket_status) == 0? (unsigned long long)socket_status.st_ino : 0;
	connection = opened;
	return true;
}

// libspeechd reports nothing when the server goes away; its event thread just closes the socket, and newer versions set it to -1. So the socket is checked instead: reading end of file, or failing other than for want of data, means the connection is gone. Older versions leave the number set, which a file opened since can have taken, so the socket must also still be the one the connection opened.
static bool speechd_socket_closed(int fd, unsigned long long inode) {
	if (fd < 0) return true;
	struct stat socket_status;
	if (fstat(fd, &socket_status) != 0 || (unsigned long long)socket_status.st_ino != inode) return true;
	char byte;
	ssize_t result = recv(fd, &byte, 1, MSG_PEEK | MSG_DONTWAIT);
	return result == 0 || (result < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR);
}
bool speechd_engine::connection_closed() { return speechd_socket_closed(((SPDConnection*)connection)->socket, socket_inode); }

// Messages of a connection that is dropped will never be reported, so they stop counting. A connection whose socket libspeechd already set to -1 is closed; one whose socket it closed without that (libspeechd before 0.9), or is about to close, is left alone, because spd_close would close that descriptor again, and by then the number may belong to another file.
void speechd_engine::drop_connection() {
	if (!connection) return;
	SPDConnection *dropped = (SPDConnection*)connection;
	connection = nullptr;
	if (dropped->socket < 0 || !speechd_socket_closed(dropped->socket, socket_inode)) {
		speechd_call_guard guard;
		spd_close(dropped);
	}
	forget_messages();
}

// Stops counting this engine's messages as pending, once its connection is gone or spd_cancel took them back. The server reports a cancellation later, on the event thread, and the engine is not to report speech it stopped in between; an end that comes after this lands among the early ones and expires.
void speechd_engine::forget_messages() {
	std::lock_guard<std::mutex> lock(g_speechd_messages_mutex);
	for (auto it = g_speechd_pending.begin(); it != g_speechd_pending.end();) {
		if (it->second.engine == this) it = g_speechd_pending.erase(it);
		else ++it;
	}
}

// Whether there is a working connection, after dropping one whose server went away and, at most every three seconds, opening a new one, which also starts the server again when it can.
bool speechd_engine::connected() {
	if (connection && !connection_closed()) return true;
	drop_connection();
	if (monotonic_milliseconds() - last_open < 3000) return false;
	return open_connection();
}

bool speechd_engine::is_available() { return loaded; }

bool speechd_engine::speak(const std::string &text, bool interrupt, bool blocking) {
	if (!loaded || text.empty()) return false;
	int msg_id;
	{
		std::lock_guard<std::mutex> lock(state_mutex);
		if (!connected()) return false;
		SPDConnection *speaking_connection = (SPDConnection*)connection;
		{
			speechd_call_guard guard;
			if (interrupt && spd_cancel(speaking_connection) == 0) forget_messages(); // Stops the message being spoken and drops the queued ones; a stop before it would let the next queued one start for a moment.
			// Priority message for all of it: one of priority important cancels what other connections are speaking, the user's screen reader's included, and holds up their speech after it. Interrupting stops this connection's own speech, above.
			msg_id = spd_say(speaking_connection, SPD_MESSAGE, text.c_str());
		}
		if (msg_id < 0) return false;
		if (!notifying) return true; // Nothing would say when it ended, so a blocking call can't wait either.
		std::lock_guard<std::mutex> messages_lock(g_speechd_messages_mutex);
		unsigned long long now = monotonic_milliseconds();
		auto early = g_speechd_early.find(msg_id);
		speechd_early_report report = early != g_speechd_early.end() && now - early->second.at < 2000? early->second : speechd_early_report{0, false};
		if (early != g_speechd_early.end()) g_speechd_early.erase(early);
		if (!report.ended) {
			auto said = g_speechd_pending.insert_or_assign(msg_id, speechd_message{this, now, report.at, text.size()}).first;
			if (report.at) {
				g_speechd_last_report = now;
				speechd_drop_earlier(said);
			}
		}
	}
	if (!blocking) return true;
	// The message stops pending when it ends, is cancelled, is lost, or its connection is dropped, here or by another thread.
	while (speechd_message_pending(msg_id)) {
		{
			std::lock_guard<std::mutex> lock(state_mutex);
			if (!connection || connection_closed()) {
				drop_connection();
				break;
			}
		}
		wait(10);
	}
	return true;
}

bool speechd_engine::is_speaking() {
	std::lock_guard<std::mutex> lock(state_mutex);
	if (!connection || !notifying) return false;
	if (connection_closed()) {
		drop_connection();
		return false;
	}
	std::lock_guard<std::mutex> messages_lock(g_speechd_messages_mutex);
	speechd_drop_lost(monotonic_milliseconds());
	for (const auto &message : g_speechd_pending) if (message.second.engine == this) return true;
	return false;
}

bool speechd_engine::stop() {
	if (!loaded) return false;
	std::lock_guard<std::mutex> lock(state_mutex);
	if (!connection || connection_closed()) {
		drop_connection(); // Nothing is speaking on a connection that is gone.
		return true;
	}
	speechd_call_guard guard;
	if (spd_cancel((SPDConnection*)connection) != 0) return false;
	forget_messages();
	return true;
}

// The language the server speaks, such as "en-us", lowercased as other platforms report theirs; empty when it can't be asked.
std::string speechd_engine::get_voice_language(int index) {
	if (index != 0 || !spd_get_language) return "";
	std::lock_guard<std::mutex> lock(state_mutex);
	if (!connected()) return "";
	char *language;
	{
		speechd_call_guard guard;
		language = spd_get_language((SPDConnection*)connection);
	}
	std::string result = language? language : "";
	free(language);
	for (char &c : result) c = tolower((unsigned char)c);
	return result;
}

void register_native_tts() { tts_engine_register("speechd", []() -> shared_ptr<tts_engine> { return make_shared<speechd_engine>(); }); }

// Speech Dispatcher's one voice, made on first use. Script threads can use it while the program shuts down and lets it go, so each call takes a reference of its own, under the lock, which also keeps two threads speaking for the first time at once from each making a voice; once it has been let go, it isn't made again, as nothing would let the new one go.
static tts_voice* g_screen_reader_voice = nullptr;
static bool g_screen_reader_unloaded = false;
static std::mutex g_screen_reader_mutex;
class screen_reader_voice {
	tts_voice *voice;
public:
	screen_reader_voice(bool make = true) {
		std::lock_guard<std::mutex> lock(g_screen_reader_mutex);
		if (!g_screen_reader_voice && make && !g_screen_reader_unloaded) g_screen_reader_voice = new tts_voice("speechd");
		voice = g_screen_reader_voice;
		if (voice) voice->AddRef();
	}
	~screen_reader_voice() { if (voice) voice->Release(); }
	screen_reader_voice(const screen_reader_voice &) = delete;
	screen_reader_voice &operator=(const screen_reader_voice &) = delete;
	tts_voice *operator->() const { return voice; }
	// Speech Dispatcher counts as a screen reader when NVGT could connect to it, which is what its one voice stands for and which is tried once per run, for any speech. Every call answers the same: the voice list is built the first time.
	bool usable() const { return voice && voice->get_voice_count() > 0; }
};

bool screen_reader_is_speaking() {
	screen_reader_voice voice(false);
	return voice.usable() && voice->get_speaking();
}

bool screen_reader_load() { return screen_reader_voice().usable(); }

void screen_reader_unload() {
	tts_voice *voice;
	{
		std::lock_guard<std::mutex> lock(g_screen_reader_mutex);
		voice = g_screen_reader_voice;
		g_screen_reader_voice = nullptr;
		g_screen_reader_unloaded = true;
	}
	if (voice) voice->Release();
}

std::string screen_reader_detect() { return screen_reader_voice().usable()? "Speech Dispatcher" : ""; }

bool screen_reader_has_speech() { return screen_reader_voice().usable(); }

bool screen_reader_has_braille() { return false; }

bool screen_reader_speak(const std::string& text, bool interrupt) {
	screen_reader_voice voice;
	if (!voice.usable()) return false;
	if (text.empty()) return !interrupt || voice->stop(); // As on the other platforms, empty text only interrupts.
	return voice->speak(text, interrupt);
}

bool screen_reader_output(const std::string& text, bool interrupt) { return screen_reader_speak(text, interrupt); }

bool screen_reader_braille(const std::string& text) { return false; }

bool screen_reader_silence() {
	screen_reader_voice voice;
	return voice.usable() && voice->stop();
}

unsigned long long system_running_milliseconds() {
	struct timespec ts;
	if (clock_gettime(CLOCK_BOOTTIME, &ts) != 0) return 0;
	return (unsigned long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

#endif
