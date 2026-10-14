/* linux.h - header containing functions only applicable to Linux and Unix platforms
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
#include <mutex>
#include <string>
#include "tts.h"

bool screen_reader_is_speaking();

class speechd_engine : public tts_engine_impl {
	std::mutex state_mutex; // Guards the members below, which every script thread speaking on the shared engine uses; the private methods expect it held.
	void* connection; // The SPDConnection, null while there is none.
	bool loaded; // A first connection succeeded; the engine stays available while it reconnects after that.
	bool notifying; // The server reports when the messages of this connection end or are cancelled.
	unsigned long long last_open; // When a connection was last opened or tried, in monotonic milliseconds.
	bool open_connection();
	bool connection_closed();
	void drop_connection();
	bool connected();
public:
	speechd_engine();
	virtual ~speechd_engine();
	virtual bool is_available() override;
	virtual bool speak(const std::string &text, bool interrupt = false, bool blocking = false) override;
	virtual bool is_speaking() override;
	virtual bool stop() override;
	virtual std::string get_voice_language(int index) override;
};
