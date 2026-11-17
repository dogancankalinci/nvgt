/* mail.cpp - SMTP mail wrapper implementation for NVGT
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

#include "mail.h"

#include <Poco/Environment.h>
#include <Poco/Exception.h>
#include <Poco/Net/FilePartSource.h>
#include <Poco/Net/MailMessage.h>
#include <Poco/Net/MailRecipient.h>
#include <Poco/Net/NetException.h>
#include <Poco/Net/SMTPClientSession.h>
#include <Poco/Net/SecureSMTPClientSession.h>
#include <Poco/Net/SecureStreamSocket.h>
#include <Poco/Net/SocketAddress.h>
#include <Poco/Net/StringPartSource.h>
#include <Poco/Path.h>
#include <Poco/RegularExpression.h>
#include <angelscript.h>
#include <scriptarray.h>
#include "nvgt_angelscript.h" // get_array_type()

#include <sstream>
#include <vector>

using namespace Poco;
using namespace Poco::Net;

// Note: Not using poco_shared here because these objects are meant to be
// used as value types that get composed into messages, not long-lived shared objects.
// The mail_message class manages its own Poco objects internally.

// Header values, names and addresses go into the message (and the sender and recipient addresses into the SMTP commands) unchanged, so a
// CR or LF in one started a new header line (a Bcc, for instance) or a new SMTP command (an extra RCPT TO: a recipient the script never
// added). Such values are refused: the setter leaves the message as it was and last_error says why. NUL bytes are refused too.
static bool mail_value_ok(const std::string& value) {
	return value.find_first_of(std::string("\r\n\0", 3)) == std::string::npos;
}
// A header name is printable ASCII without a colon (RFC 5322 field name).
static bool mail_header_name_ok(const std::string& name) {
	if (name.empty()) return false;
	for (unsigned char c : name) {
		if (c < 33 || c > 126 || c == ':') return false;
	}
	return true;
}

// Wrapper for mail recipient
class mail_recipient {
private:
	int m_refcount;

public:
	MailRecipient::RecipientType type;
	std::string address;
	std::string real_name;

	mail_recipient() : m_refcount(1), type(MailRecipient::PRIMARY_RECIPIENT) {}
	mail_recipient(int recipient_type, const std::string& addr, const std::string& name = "")
		: m_refcount(1), type(static_cast<MailRecipient::RecipientType>(recipient_type)), address(addr), real_name(name) {}

	void add_ref() {
		asAtomicInc(m_refcount);
	}
	void release() {
		if (asAtomicDec(m_refcount) < 1) delete this;
	}
};

// Wrapper for mail message
class mail_message {
private:
	int m_refcount;
	MailMessage m_message;
	std::string m_last_error;
	bool m_has_html_content;
	std::string m_html_content;
	std::string m_plain_content;
	std::string m_text_content; // See set_content().
	std::string m_text_type;
	bool m_has_text_content = false; // set_content() was called
	bool m_text_pending = false; // and its part isn't in m_message yet

	friend class smtp_client;

	// Records the refusal in m_last_error when the value has a CR, LF or NUL byte (see mail_value_ok()).
	bool value_ok(const std::string& value, const char* what) {
		if (mail_value_ok(value)) return true;
		m_last_error = std::string("The ") + what + " must not contain CR, LF or NUL characters";
		return false;
	}
	bool header_ok(const std::string& name, const std::string& value) {
		if (!mail_header_name_ok(name)) {
			m_last_error = "Header names must be printable ASCII characters without spaces or colons";
			return false;
		}
		return value_ok(value, "header value");
	}

public:
	mail_message() : m_refcount(1), m_has_html_content(false) {}

	void add_ref() {
		asAtomicInc(m_refcount);
	}
	void release() {
		if (asAtomicDec(m_refcount) < 1) delete this;
	}

	void set_sender(const std::string& address) {
		if (!value_ok(address, "sender")) return;
		try {
			m_message.setSender(address);
			m_last_error.clear();
		} catch (const Exception& e) {
			m_last_error = e.displayText();
		}
	}

	std::string get_sender() const {
		return m_message.getSender();
	}

	void add_recipient(const mail_recipient& recipient) {
		if (!value_ok(recipient.address, "recipient address") || !value_ok(recipient.real_name, "recipient name")) return;
		try {
			m_message.addRecipient(MailRecipient(recipient.type, recipient.address, recipient.real_name));
			m_last_error.clear();
		} catch (const Exception& e) {
			m_last_error = e.displayText();
		}
	}

	void add_recipient_simple(const std::string& address, int type = MailRecipient::PRIMARY_RECIPIENT) {
		if (!value_ok(address, "recipient address")) return;
		try {
			m_message.addRecipient(MailRecipient(static_cast<MailRecipient::RecipientType>(type), address));
			m_last_error.clear();
		} catch (const Exception& e) {
			m_last_error = e.displayText();
		}
	}

	CScriptArray* get_recipients() const {
		asIScriptContext* ctx = asGetActiveContext();
		asIScriptEngine* engine = ctx->GetEngine();
		asITypeInfo* arrayType = get_array_type("array<mail_recipient@>");
		CScriptArray* arr = CScriptArray::Create(arrayType);
		const MailMessage::Recipients& recipients = m_message.recipients();
		for (const auto& r : recipients) {
			mail_recipient* mr = new mail_recipient(r.getType(), r.getAddress(), r.getRealName());
			arr->InsertLast(&mr);
			mr->release();
		}
		return arr;
	}

	void set_subject(const std::string& subject) {
		if (!value_ok(subject, "subject")) return;
		m_message.setSubject(subject);
		m_last_error.clear();
	}

	std::string get_subject() const {
		return m_message.getSubject();
	}

	// The content is kept here and added to the message as a part when it is sent (see finalize_html_content()), as HTML content is. It was
	// added as a part at once: content then read back "" (so did a message from parse_email_message()), and each call added another part,
	// so a message whose content was set twice was sent with both.
	void set_content(const std::string& content, const std::string& content_type = "text/plain") {
		if (!value_ok(content_type, "content type")) return;
		m_text_content = content;
		m_text_type = content_type;
		m_has_text_content = true;
		m_text_pending = true;
		m_last_error.clear();
	}

	std::string get_content() const {
		return m_has_text_content ? m_text_content : m_message.getContent();
	}

	void set_html_content(const std::string& html, const std::string& plain_alternative = "") {
		m_has_html_content = true;
		m_html_content = html;
		m_plain_content = plain_alternative.empty() ? "This message requires HTML support to view." : plain_alternative;
		m_last_error.clear();
	}

	void set_priority(int priority) {
		try {
			// Set X-Priority header (1=Highest, 5=Lowest)
			m_message.set("X-Priority", std::to_string(priority));
			// Also set Importance header for better compatibility
			std::string importance;
			switch (priority) {
				case 1:
				case 2:
					importance = "High";
					break;
				case 4:
				case 5:
					importance = "Low";
					break;
				default:
					importance = "Normal";
					break;
			}
			m_message.set("Importance", importance);
			m_last_error.clear();
		} catch (const Exception& e) {
			m_last_error = e.displayText();
		}
	}

	int get_priority() const {
		std::string priority_str = m_message.get("X-Priority", "3");
		try {
			return std::stoi(priority_str);
		} catch (...) {
			return 3;  // Default to normal priority
		}
	}

	void add_header(const std::string& name, const std::string& value) {
		if (!header_ok(name, value)) return;
		try {
			m_message.add(name, value);
			m_last_error.clear();
		} catch (const Exception& e) {
			m_last_error = e.displayText();
		}
	}

	std::string get_header(const std::string& name) const {
		return m_message.get(name, "");
	}

	// A header that is set replaces the one there: added (add_header()), the reply_to property set twice gave the message two Reply-To
	// headers and read back the first, and set_read_receipt() likewise.
	void set_header(const std::string& name, const std::string& value) {
		if (!header_ok(name, value)) return;
		try {
			m_message.set(name, value);
			m_last_error.clear();
		} catch (const Exception& e) {
			m_last_error = e.displayText();
		}
	}

	void set_reply_to(const std::string& address) {
		set_header("Reply-To", address);
	}

	std::string get_reply_to() const {
		return get_header("Reply-To");
	}

	void set_read_receipt(const std::string& address) {
		set_header("Disposition-Notification-To", address);
		set_header("Return-Receipt-To", address);
	}

	std::string get_message_id() const {
		return m_message.get("Message-ID", "");
	}

	void set_message_id(const std::string& id) {
		if (!value_ok(id, "message ID")) return;
		try {
			m_message.set("Message-ID", id);
			m_last_error.clear();
		} catch (const Exception& e) {
			m_last_error = e.displayText();
		}
	}

	void set_in_reply_to(const std::string& message_id) {
		if (!value_ok(message_id, "In-Reply-To value")) return;
		try {
			m_message.set("In-Reply-To", message_id);
			m_last_error.clear();
		} catch (const Exception& e) {
			m_last_error = e.displayText();
		}
	}

	std::string get_in_reply_to() const {
		return m_message.get("In-Reply-To", "");
	}

	void set_references(const std::string& references) {
		if (!value_ok(references, "References value")) return;
		try {
			m_message.set("References", references);
			m_last_error.clear();
		} catch (const Exception& e) {
			m_last_error = e.displayText();
		}
	}

	std::string get_references() const {
		return m_message.get("References", "");
	}

	void set_return_receipt_to(const std::string& address) {
		if (!value_ok(address, "Return-Receipt-To address")) return;
		try {
			m_message.set("Return-Receipt-To", address);
			m_last_error.clear();
		} catch (const Exception& e) {
			m_last_error = e.displayText();
		}
	}

	std::string get_return_receipt_to() const {
		return m_message.get("Return-Receipt-To", "");
	}

	void set_disposition_notification_to(const std::string& address) {
		if (!value_ok(address, "Disposition-Notification-To address")) return;
		try {
			m_message.set("Disposition-Notification-To", address);
			m_last_error.clear();
		} catch (const Exception& e) {
			m_last_error = e.displayText();
		}
	}

	std::string get_disposition_notification_to() const {
		return m_message.get("Disposition-Notification-To", "");
	}

	bool add_attachment_file(const std::string& name, const std::string& path) {
		if (!value_ok(name, "attachment name") || !value_ok(path, "attachment path")) return false; // The file's name is a header parameter.
		try {
			m_message.addAttachment(name, new FilePartSource(path));
			m_last_error.clear();
			return true;
		} catch (const Exception& e) {
			m_last_error = e.displayText();
			return false;
		}
	}

	bool add_attachment_string(const std::string& name, const std::string& content, const std::string& media_type = "application/octet-stream") {
		if (!value_ok(name, "attachment name") || !value_ok(media_type, "media type")) return false;
		try {
			m_message.addAttachment(name, new StringPartSource(content, media_type));
			m_last_error.clear();
			return true;
		} catch (const Exception& e) {
			m_last_error = e.displayText();
			return false;
		}
	}

	void set_date(const Timestamp& ts) {
		m_message.setDate(ts);
	}

	std::string add_inline_attachment_file(const std::string& path, const std::string& content_id = "") {
		if (!value_ok(path, "attachment path") || !value_ok(content_id, "content ID")) return "";
		try {
			std::string cid = content_id.empty() ? Path(path).getFileName() + "@nvgt.mail" : content_id;
			FilePartSource* fps = new FilePartSource(path);
			// For inline attachments, we use addPart with CONTENT_INLINE disposition
			// and set the Content-ID header via the part name
			m_message.addPart("cid:" + cid, fps, MailMessage::CONTENT_INLINE, MailMessage::ENCODING_BASE64);
			m_last_error.clear();
			return cid;
		} catch (const Exception& e) {
			m_last_error = e.displayText();
			return "";
		}
	}

	std::string add_inline_attachment_string(const std::string& content, const std::string& media_type, const std::string& content_id) {
		if (!value_ok(media_type, "media type") || !value_ok(content_id, "content ID")) return "";
		try {
			std::string cid = content_id.empty() ? "inline@nvgt.mail" : content_id;
			StringPartSource* sps = new StringPartSource(content, media_type);
			// For inline attachments, we use addPart with CONTENT_INLINE disposition
			// and set the Content-ID header via the part name
			m_message.addPart("cid:" + cid, sps, MailMessage::CONTENT_INLINE, MailMessage::ENCODING_BASE64);
			m_last_error.clear();
			return cid;
		} catch (const Exception& e) {
			m_last_error = e.displayText();
			return "";
		}
	}

	// Finalize the content and the HTML content for sending, each added once.
	void finalize_html_content() {
		if (m_text_pending) {
			// For messages with attachments, we need to use addContent instead of setContent
			// to properly create a multipart message
			try {
				m_message.addContent(new StringPartSource(m_text_content, m_text_type));
			} catch (const Exception& e) {
				// If addContent fails (e.g., content already set), fall back to setContent
				m_message.setContentType(m_text_type);
				m_message.setContent(m_text_content);
			}
			m_text_pending = false;
		}
		if (!m_has_html_content) return;
		try {
			// Create multipart/alternative for HTML and plain text
			m_message.setContentType("multipart/alternative");
			// Add plain text part
			if (!m_plain_content.empty())
				m_message.addContent(new StringPartSource(m_plain_content, "text/plain"));
			// Add HTML part
			m_message.addContent(new StringPartSource(m_html_content, "text/html"));
			m_has_html_content = false;  // Prevent double processing
		} catch (const Exception& e) {
			m_last_error = e.displayText();
		}
	}

	std::string get_last_error() const {
		return m_last_error;
	}

	const MailMessage& get_message() const {
		return m_message;
	}
};

// SMTP client wrapper
class smtp_client {
private:
	int m_refcount;
	SMTPClientSession* m_session;
	std::string m_host;
	int m_port;
	bool m_use_ssl;
	std::string m_last_error;
	int m_timeout;
	std::string m_server_capabilities;
	bool m_is_authenticated;

public:
	smtp_client() : m_refcount(1), m_session(nullptr), m_port(25), m_use_ssl(false), m_timeout(30000), m_is_authenticated(false) {}
	~smtp_client() {
		close();
	}

	void add_ref() {
		asAtomicInc(m_refcount);
	}
	void release() {
		if (asAtomicDec(m_refcount) < 1) delete this;
	}

	void set_host(const std::string& host) {
		m_host = host;
	}
	std::string get_host() const {
		return m_host;
	}

	void set_port(int port) {
		m_port = port;
	}
	int get_port() const {
		return m_port;
	}

	void set_use_ssl(bool use_ssl) {
		m_use_ssl = use_ssl;
	}
	bool get_use_ssl() const {
		return m_use_ssl;
	}

	bool connect() {
		try {
			close();  // Close any existing connection
			if (m_port < 1 || m_port > 65535) { // It was cut to 16 bits: port 65561 connected to port 25.
				m_last_error = "Invalid port";
				return false;
			}
			// With use_ssl, port 465 is TLS from the first byte (RFC 8314), and any other port starts TLS with STARTTLS (RFC 3207) before
			// anything else is sent; the connection fails when the server refuses it. TLS was started only by login() and only on port 587, and
			// a refused STARTTLS was ignored, so on any other port, with a server that didn't offer it (or a man in the middle that removed it)
			// and for a message sent without login(), the password and the message went out unencrypted although use_ssl was set; port 465
			// couldn't connect at all.
			bool implicit_tls = m_use_ssl && m_port == 465;
			if (implicit_tls)
				m_session = new SMTPClientSession(SecureStreamSocket(SocketAddress(m_host, static_cast<Poco::UInt16>(m_port)), m_host));
			else if (m_use_ssl)
				m_session = new SecureSMTPClientSession(m_host, m_port);
			else
				m_session = new SMTPClientSession(m_host, m_port);
			// The timeout applies to the greeting too: it was set after it, so connect() waited for a server that didn't answer for Poco's
			// default 30 seconds. Milliseconds to microseconds in 64 bits: in int, 2147484 ms (35.8 minutes) or more overflowed (undefined; in
			// practice a negative or unrelated timeout).
			m_session->setTimeout(Poco::Timespan(Poco::Timespan::TimeDiff(m_timeout) * 1000));
			// EHLO names this computer (Poco's login() sends the local host name, as login(method, ...) does). It named the server
			// ("EHLO smtp.example.com"), which servers that check the greeting take for a forged one.
			m_session->login();
			if (m_use_ssl && !implicit_tls) {
				if (!static_cast<SecureSMTPClientSession*>(m_session)->startTLS()) {
					close();
					m_last_error = "The server refused STARTTLS";
					return false;
				}
				m_session->login(); // The greeting again over TLS: what the server said before it doesn't count (RFC 3207 4.2).
			}
			m_last_error.clear();
			return true;
		} catch (const Exception& e) {
			m_last_error = e.displayText();
			close();
			return false;
		}
	}

	bool login(const std::string& username, const std::string& password, int auth_method = SMTPClientSession::AUTH_LOGIN) {
		if (!m_session) {
			m_last_error = "Not connected";
			return false;
		}
		try {
			// With use_ssl, connect() has started TLS already.
			m_session->login(static_cast<SMTPClientSession::LoginMethod>(auth_method), username, password);
			m_is_authenticated = true;
			m_last_error.clear();
			return true;
		} catch (const Exception& e) {
			m_last_error = e.displayText();
			return false;
		}
	}

	// OAuth2 login
	bool login_oauth2(const std::string& username, const std::string& access_token) {
		if (!m_session) {
			m_last_error = "Not connected";
			return false;
		}
		try {
			// OAuth2 uses XOAUTH2 method
			m_session->login(SMTPClientSession::AUTH_XOAUTH2, username, access_token);
			m_is_authenticated = true;
			m_last_error.clear();
			return true;
		} catch (const Exception& e) {
			m_last_error = e.displayText();
			return false;
		}
	}

	// Note: Authentication method detection is not supported by Poco's SMTP implementation.
	// The library expects you to know the server's authentication requirements in advance.
	// You can try different auth methods (LOGIN, PLAIN, CRAM_MD5, etc.) until one succeeds.

	bool send_message(mail_message* msg) {
		if (!m_session) {
			m_last_error = "Not connected";
			return false;
		}
		if (!msg) {
			m_last_error = "Invalid message";
			return false;
		}
		try {
			// Handle HTML content if set
			msg->finalize_html_content(); // adds the content too, see there
			m_session->sendMessage(msg->get_message());
			m_last_error.clear();
			return true;
		} catch (const Exception& e) {
			m_last_error = e.displayText();
			return false;
		}
	}

	void close() {
		if (m_session) {
			try {
				m_session->close();
			} catch (...) {
			}
			delete m_session;
			m_session = nullptr;
			m_is_authenticated = false;
			m_server_capabilities.clear();
		}
	}

	bool is_connected() const {
		return m_session != nullptr;
	}

	bool is_authenticated() const {
		return m_is_authenticated;
	}

	std::string get_last_error() const {
		return m_last_error;
	}

	void set_timeout(int timeout_ms) {
		m_timeout = timeout_ms;
	}
	int get_timeout() const {
		return m_timeout;
	}

	std::string query_server_capabilities() {
		if (!m_session) {
			m_last_error = "Not connected";
			return "";
		}
		try {
			std::string response;
			m_session->sendCommand("EHLO " + Poco::Environment::nodeName(), response); // This computer's name, see connect().
			m_server_capabilities = response;
			m_last_error.clear();
			return response;
		} catch (const Exception& e) {
			m_last_error = e.displayText();
			return "";
		}
	}

	std::string get_server_capabilities() const {
		return m_server_capabilities;
	}

	bool send_messages(CScriptArray* messages) {
		if (!m_session) {
			m_last_error = "Not connected";
			return false;
		}
		if (!messages) {
			m_last_error = "Invalid message array";
			return false;
		}
		try {
			for (asUINT i = 0; i < messages->GetSize(); i++) {
				mail_message* msg = *(mail_message**)messages->At(i);
				if (msg) {
					// Handle HTML content if set
					msg->finalize_html_content(); // adds the content too, see there
					m_session->sendMessage(msg->get_message());
				}
			}
			m_last_error.clear();
			return true;
		} catch (const Exception& e) {
			m_last_error = e.displayText();
			return false;
		}
	}
};

bool validate_email_address(const std::string& email) {
	// Basic email validation regex pattern
	// This pattern covers most common email formats, but is most certainly not fully aligned with what is/is not legal
	static const std::string pattern =
	    "^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9]"
	    "(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
	    "(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$";
	try {
		Poco::RegularExpression regex(pattern);
		return regex.match(email);
	} catch (...) {
		return false;
	}
}

mail_message* parse_email_message(const std::string& raw_message) {
	// This is very much incomplete
	// Should probably find a library for this?
	mail_message* msg = new mail_message();
	try {
		std::istringstream iss(raw_message);
		MailMessage pocoMsg;
		pocoMsg.read(iss);
		msg->set_sender(pocoMsg.getSender());
		msg->set_subject(pocoMsg.getSubject());
		msg->set_content(pocoMsg.getContent(), pocoMsg.getContentType());
		const MailMessage::Recipients& recipients = pocoMsg.recipients();
		for (const auto& r : recipients) {
			mail_recipient recipient(r.getType(), r.getAddress(), r.getRealName());
			msg->add_recipient(recipient);
		}
		if (pocoMsg.has("Message-ID"))
			msg->set_message_id(pocoMsg.get("Message-ID"));
		if (pocoMsg.has("In-Reply-To"))
			msg->set_in_reply_to(pocoMsg.get("In-Reply-To"));
		if (pocoMsg.has("References"))
			msg->set_references(pocoMsg.get("References"));
		if (pocoMsg.has("Reply-To"))
			msg->set_reply_to(pocoMsg.get("Reply-To"));
	} catch (const Exception& e) {
		msg->set_subject("");
		// Note: We can't set the error directly, so the message will have empty fields on parse error
		// Not great, hence needing a library
		// But seeing as we can't even receive Email right now, it'll do.
	}
	return msg;
}

mail_recipient* mail_recipient_factory() {
	return new mail_recipient();
}

mail_recipient* mail_recipient_factory_full(int type, const std::string& address, const std::string& real_name) {
	return new mail_recipient(type, address, real_name);
}

mail_message* mail_message_factory() {
	return new mail_message();
}

smtp_client* smtp_client_factory() {
	return new smtp_client();
}

void RegisterMail(asIScriptEngine* engine) {
	engine->RegisterEnum("mail_recipient_type");
	engine->RegisterEnumValue("mail_recipient_type", "RECIPIENT_TO", MailRecipient::PRIMARY_RECIPIENT);
	engine->RegisterEnumValue("mail_recipient_type", "RECIPIENT_CC", MailRecipient::CC_RECIPIENT);
	engine->RegisterEnumValue("mail_recipient_type", "RECIPIENT_BCC", MailRecipient::BCC_RECIPIENT);
	engine->RegisterEnum("smtp_auth_method");
	engine->RegisterEnumValue("smtp_auth_method", "SMTP_AUTH_NONE", SMTPClientSession::AUTH_NONE);
	engine->RegisterEnumValue("smtp_auth_method", "SMTP_AUTH_LOGIN", SMTPClientSession::AUTH_LOGIN);
	engine->RegisterEnumValue("smtp_auth_method", "SMTP_AUTH_PLAIN", SMTPClientSession::AUTH_PLAIN);
	engine->RegisterEnumValue("smtp_auth_method", "SMTP_AUTH_CRAM_MD5", SMTPClientSession::AUTH_CRAM_MD5);
	engine->RegisterEnumValue("smtp_auth_method", "SMTP_AUTH_CRAM_SHA1", SMTPClientSession::AUTH_CRAM_SHA1);
	engine->RegisterEnumValue("smtp_auth_method", "SMTP_AUTH_XOAUTH2", SMTPClientSession::AUTH_XOAUTH2);
	engine->RegisterEnumValue("smtp_auth_method", "SMTP_AUTH_NTLM", SMTPClientSession::AUTH_NTLM);
	engine->RegisterEnum("mail_priority");
	engine->RegisterEnumValue("mail_priority", "MAIL_PRIORITY_HIGHEST", 1);
	engine->RegisterEnumValue("mail_priority", "MAIL_PRIORITY_HIGH", 2);
	engine->RegisterEnumValue("mail_priority", "MAIL_PRIORITY_NORMAL", 3);
	engine->RegisterEnumValue("mail_priority", "MAIL_PRIORITY_LOW", 4);
	engine->RegisterEnumValue("mail_priority", "MAIL_PRIORITY_LOWEST", 5);
	engine->RegisterObjectType("mail_recipient", 0, asOBJ_REF);
	engine->RegisterObjectBehaviour("mail_recipient", asBEHAVE_FACTORY, "mail_recipient@ f()", asFUNCTION(mail_recipient_factory), asCALL_CDECL);
	engine->RegisterObjectBehaviour("mail_recipient", asBEHAVE_FACTORY, "mail_recipient@ f(mail_recipient_type type, const string &in address, const string &in real_name = \"\")", asFUNCTION(mail_recipient_factory_full), asCALL_CDECL);
	engine->RegisterObjectBehaviour("mail_recipient", asBEHAVE_ADDREF, "void f()", asMETHOD(mail_recipient, add_ref), asCALL_THISCALL);
	engine->RegisterObjectBehaviour("mail_recipient", asBEHAVE_RELEASE, "void f()", asMETHOD(mail_recipient, release), asCALL_THISCALL);
	engine->RegisterObjectProperty("mail_recipient", "mail_recipient_type type", asOFFSET(mail_recipient, type));
	engine->RegisterObjectProperty("mail_recipient", "string address", asOFFSET(mail_recipient, address));
	engine->RegisterObjectProperty("mail_recipient", "string real_name", asOFFSET(mail_recipient, real_name));
	engine->RegisterObjectType("mail_message", 0, asOBJ_REF);
	engine->RegisterObjectBehaviour("mail_message", asBEHAVE_FACTORY, "mail_message@ f()", asFUNCTION(mail_message_factory), asCALL_CDECL);
	engine->RegisterObjectBehaviour("mail_message", asBEHAVE_ADDREF, "void f()", asMETHOD(mail_message, add_ref), asCALL_THISCALL);
	engine->RegisterObjectBehaviour("mail_message", asBEHAVE_RELEASE, "void f()", asMETHOD(mail_message, release), asCALL_THISCALL);
	engine->RegisterObjectMethod("mail_message", "void set_sender(const string &in address)", asMETHOD(mail_message, set_sender), asCALL_THISCALL);
	engine->RegisterObjectMethod("mail_message", "string get_sender() const property", asMETHOD(mail_message, get_sender), asCALL_THISCALL);
	engine->RegisterObjectMethod("mail_message", "void add_recipient(const mail_recipient &in recipient)", asMETHOD(mail_message, add_recipient), asCALL_THISCALL);
	engine->RegisterObjectMethod("mail_message", "void add_recipient(const string &in address, mail_recipient_type type = RECIPIENT_TO)", asMETHOD(mail_message, add_recipient_simple), asCALL_THISCALL);
	engine->RegisterObjectMethod("mail_message", "array<mail_recipient@>@ get_recipients() const", asMETHOD(mail_message, get_recipients), asCALL_THISCALL);
	engine->RegisterObjectMethod("mail_message", "void set_subject(const string &in subject)", asMETHOD(mail_message, set_subject), asCALL_THISCALL);
	engine->RegisterObjectMethod("mail_message", "string get_subject() const property", asMETHOD(mail_message, get_subject), asCALL_THISCALL);
	engine->RegisterObjectMethod("mail_message", "void set_content(const string &in content, const string &in content_type = \"text/plain\")", asMETHOD(mail_message, set_content), asCALL_THISCALL);
	engine->RegisterObjectMethod("mail_message", "string get_content() const property", asMETHOD(mail_message, get_content), asCALL_THISCALL);
	engine->RegisterObjectMethod("mail_message", "bool add_attachment_file(const string &in name, const string &in path)", asMETHOD(mail_message, add_attachment_file), asCALL_THISCALL);
	engine->RegisterObjectMethod("mail_message", "bool add_attachment_string(const string &in name, const string &in content, const string &in media_type = \"application/octet-stream\")", asMETHOD(mail_message, add_attachment_string), asCALL_THISCALL);
	engine->RegisterObjectMethod("mail_message", "void set_html_content(const string &in html, const string &in plain_alternative = \"\")", asMETHOD(mail_message, set_html_content), asCALL_THISCALL);
	engine->RegisterObjectMethod("mail_message", "void set_priority(mail_priority priority)", asMETHOD(mail_message, set_priority), asCALL_THISCALL);
	engine->RegisterObjectMethod("mail_message", "int get_priority() const property", asMETHOD(mail_message, get_priority), asCALL_THISCALL);
	engine->RegisterObjectMethod("mail_message", "void add_header(const string &in name, const string &in value)", asMETHOD(mail_message, add_header), asCALL_THISCALL);
	engine->RegisterObjectMethod("mail_message", "string get_header(const string &in name) const", asMETHOD(mail_message, get_header), asCALL_THISCALL);
	engine->RegisterObjectMethod("mail_message", "void set_reply_to(const string &in address) property", asMETHOD(mail_message, set_reply_to), asCALL_THISCALL);
	engine->RegisterObjectMethod("mail_message", "string get_reply_to() const property", asMETHOD(mail_message, get_reply_to), asCALL_THISCALL);
	engine->RegisterObjectMethod("mail_message", "void set_read_receipt(const string &in address)", asMETHOD(mail_message, set_read_receipt), asCALL_THISCALL);
	engine->RegisterObjectMethod("mail_message", "string get_message_id() const property", asMETHOD(mail_message, get_message_id), asCALL_THISCALL);
	engine->RegisterObjectMethod("mail_message", "void set_message_id(const string &in message_id) property", asMETHOD(mail_message, set_message_id), asCALL_THISCALL);
	engine->RegisterObjectMethod("mail_message", "string add_inline_attachment_file(const string &in path, const string &in content_id = \"\")", asMETHOD(mail_message, add_inline_attachment_file), asCALL_THISCALL);
	engine->RegisterObjectMethod("mail_message", "string add_inline_attachment_string(const string &in content, const string &in media_type, const string &in content_id)", asMETHOD(mail_message, add_inline_attachment_string), asCALL_THISCALL);
	engine->RegisterObjectMethod("mail_message", "string get_last_error() const property", asMETHOD(mail_message, get_last_error), asCALL_THISCALL);
	engine->RegisterObjectMethod("mail_message", "void set_in_reply_to(const string &in message_id) property", asMETHOD(mail_message, set_in_reply_to), asCALL_THISCALL);
	engine->RegisterObjectMethod("mail_message", "string get_in_reply_to() const property", asMETHOD(mail_message, get_in_reply_to), asCALL_THISCALL);
	engine->RegisterObjectMethod("mail_message", "void set_references(const string &in references) property", asMETHOD(mail_message, set_references), asCALL_THISCALL);
	engine->RegisterObjectMethod("mail_message", "string get_references() const property", asMETHOD(mail_message, get_references), asCALL_THISCALL);
	engine->RegisterObjectMethod("mail_message", "void set_return_receipt_to(const string &in address) property", asMETHOD(mail_message, set_return_receipt_to), asCALL_THISCALL);
	engine->RegisterObjectMethod("mail_message", "string get_return_receipt_to() const property", asMETHOD(mail_message, get_return_receipt_to), asCALL_THISCALL);
	engine->RegisterObjectMethod("mail_message", "void set_disposition_notification_to(const string &in address) property", asMETHOD(mail_message, set_disposition_notification_to), asCALL_THISCALL);
	engine->RegisterObjectMethod("mail_message", "string get_disposition_notification_to() const property", asMETHOD(mail_message, get_disposition_notification_to), asCALL_THISCALL);
	engine->RegisterObjectType("smtp_client", 0, asOBJ_REF);
	engine->RegisterObjectBehaviour("smtp_client", asBEHAVE_FACTORY, "smtp_client@ f()", asFUNCTION(smtp_client_factory), asCALL_CDECL);
	engine->RegisterObjectBehaviour("smtp_client", asBEHAVE_ADDREF, "void f()", asMETHOD(smtp_client, add_ref), asCALL_THISCALL);
	engine->RegisterObjectBehaviour("smtp_client", asBEHAVE_RELEASE, "void f()", asMETHOD(smtp_client, release), asCALL_THISCALL);
	engine->RegisterObjectMethod("smtp_client", "void set_host(const string &in host) property", asMETHOD(smtp_client, set_host), asCALL_THISCALL);
	engine->RegisterObjectMethod("smtp_client", "string get_host() const property", asMETHOD(smtp_client, get_host), asCALL_THISCALL);
	engine->RegisterObjectMethod("smtp_client", "void set_port(int port) property", asMETHOD(smtp_client, set_port), asCALL_THISCALL);
	engine->RegisterObjectMethod("smtp_client", "int get_port() const property", asMETHOD(smtp_client, get_port), asCALL_THISCALL);
	engine->RegisterObjectMethod("smtp_client", "void set_use_ssl(bool enabled) property", asMETHOD(smtp_client, set_use_ssl), asCALL_THISCALL);
	engine->RegisterObjectMethod("smtp_client", "bool get_use_ssl() const property", asMETHOD(smtp_client, get_use_ssl), asCALL_THISCALL);
	engine->RegisterObjectMethod("smtp_client", "bool connect()", asMETHOD(smtp_client, connect), asCALL_THISCALL);
	engine->RegisterObjectMethod("smtp_client", "bool login(const string &in username, const string &in password, smtp_auth_method method = SMTP_AUTH_LOGIN)", asMETHOD(smtp_client, login), asCALL_THISCALL);
	engine->RegisterObjectMethod("smtp_client", "bool login_oauth2(const string &in username, const string &in access_token)", asMETHOD(smtp_client, login_oauth2), asCALL_THISCALL);
	engine->RegisterObjectMethod("smtp_client", "bool send_message(mail_message@+ message)", asMETHOD(smtp_client, send_message), asCALL_THISCALL);
	engine->RegisterObjectMethod("smtp_client", "void close()", asMETHOD(smtp_client, close), asCALL_THISCALL);
	engine->RegisterObjectMethod("smtp_client", "bool get_is_connected() const property", asMETHOD(smtp_client, is_connected), asCALL_THISCALL);
	engine->RegisterObjectMethod("smtp_client", "bool get_is_authenticated() const property", asMETHOD(smtp_client, is_authenticated), asCALL_THISCALL);
	engine->RegisterObjectMethod("smtp_client", "string get_last_error() const property", asMETHOD(smtp_client, get_last_error), asCALL_THISCALL);
	engine->RegisterObjectMethod("smtp_client", "void set_timeout(int timeout) property", asMETHOD(smtp_client, set_timeout), asCALL_THISCALL);
	engine->RegisterObjectMethod("smtp_client", "int get_timeout() const property", asMETHOD(smtp_client, get_timeout), asCALL_THISCALL);
	engine->RegisterObjectMethod("smtp_client", "string query_server_capabilities()", asMETHOD(smtp_client, query_server_capabilities), asCALL_THISCALL);
	engine->RegisterObjectMethod("smtp_client", "string get_server_capabilities() const property", asMETHOD(smtp_client, get_server_capabilities), asCALL_THISCALL);
	engine->RegisterObjectMethod("smtp_client", "bool send_messages(array<mail_message@>@+ messages)", asMETHOD(smtp_client, send_messages), asCALL_THISCALL);
	engine->RegisterGlobalFunction("bool validate_email_address(const string &in address)", asFUNCTION(validate_email_address), asCALL_CDECL);
	engine->RegisterGlobalFunction("mail_message@ parse_email_message(const string &in data)", asFUNCTION(parse_email_message), asCALL_CDECL);
}
