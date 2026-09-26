/* apple.mm - code only compiled on all apple platforms
 * Thanks to Gruia Chiscop for the initial AVSpeechSynthesizer support!
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

#import <AVFoundation/AVFoundation.h>
#import <Foundation/Foundation.h>
#if TARGET_OS_IOS
#import <UIKit/UIKit.h>
#import <QuartzCore/QuartzCore.h>
#else
#import <AppKit/AppKit.h>
#endif
#include <memory>
#include <vector>
#include <string>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <angelscript.h>
#include <scriptarray.h>
#include <TargetConditionals.h>
#include <Poco/Event.h>
#include <Poco/Mutex.h>
#include <Poco/Thread.h>
#include "apple.h"
#include "UI.h"
#include "xplatform.h"

void register_native_tts() { tts_engine_register("avspeech", []() -> std::shared_ptr<tts_engine> { return std::make_shared<AVTTSVoice>(); }); }

// AVTTSVoice::impl class created by Gruia Chiscop on 6/6/24.
class AVTTSVoice::Impl {
public:
	// Values a script set. Nothing is written to an utterance unless its flag is set, so an untouched utterance speaks with the system's own defaults; the default* fields hold what those defaults are, for the getters.
	float rate, volume, pitch;
	float defaultRate, defaultVolume, defaultPitch;
	bool rateSet = false, volumeSet = false, pitchSet = false;
	AVSpeechSynthesizer* synth;
	AVSpeechSynthesisVoice* currentVoice; // Only non-nil once a voice was chosen; while nil, the system's default voice speaks.
	NSArray<AVSpeechSynthesisVoice *> *voices;
	Impl() : currentVoice(nil) {
		voices = [[AVSpeechSynthesisVoice speechVoices] retain];
		readDefaults();
		synth = [[AVSpeechSynthesizer alloc] init];
	}
	Impl(const std::string& language) : currentVoice(nil) {
		voices = [[AVSpeechSynthesisVoice speechVoices] retain];
		NSString *nslanguage = [NSString stringWithUTF8String:language.c_str()];
		currentVoice = [AVSpeechSynthesisVoice voiceWithLanguage:nslanguage]; // nil if there is none, which leaves the system default voice in charge.
		readDefaults();
		synth = [[AVSpeechSynthesizer alloc] init];
	}
	~Impl() {
		if (voices) [voices release];
	}
	void readDefaults() {
		AVSpeechUtterance* utterance = [[AVSpeechUtterance alloc] initWithString:@""];
		defaultRate = rate = utterance.rate;
		defaultVolume = volume = utterance.volume;
		defaultPitch = pitch = utterance.pitchMultiplier;
		[utterance release];
	}
	// Writes only what a script set onto an utterance.
	void apply(AVSpeechUtterance* utterance) const {
		if (rateSet) utterance.rate = rate;
		if (volumeSet) utterance.volume = volume;
		if (pitchSet) utterance.pitchMultiplier = pitch;
		if (currentVoice) utterance.voice = currentVoice;
	}
	// The voice that actually speaks: the chosen one, otherwise the system default, which Apple documents as the default voice for the system's language and region.
	AVSpeechSynthesisVoice* effectiveVoice() const { return currentVoice? currentVoice : [AVSpeechSynthesisVoice voiceWithLanguage:nil]; }
	int effectiveVoiceIndex() const {
		@autoreleasepool {
			AVSpeechSynthesisVoice* voice = effectiveVoice();
			if (!voice) return -1;
			for (NSUInteger i = 0; i < voices.count; i++) {
				if ([voices[i].identifier isEqualToString:voice.identifier]) return (int)i;
			}
			return -1;
		}
	}
	void resetRate() { rate = defaultRate; rateSet = false; }
	void resetVolume() { volume = defaultVolume; volumeSet = false; }
	void resetPitch() { pitch = defaultPitch; pitchSet = false; }
	void resetVoice() { currentVoice = nil; }
	bool speak(const std::string& text, bool interrupt) {
		if ((interrupt || text.empty()) && synth.isSpeaking)[synth stopSpeakingAtBoundary:AVSpeechBoundaryImmediate];
		if (text.empty()) return interrupt;
		NSString *nstext = [NSString stringWithUTF8String:text.c_str()];
		AVSpeechUtterance *utterance = [[AVSpeechUtterance alloc] initWithString:nstext];
		apply(utterance);
		[synth speakUtterance:utterance];
		return synth.isSpeaking;
	}
	bool speakWait(const std::string& text, bool interrupt) {
		bool result = speak(text, interrupt);
		if (!result) return result;
		while (synth.isSpeaking) wait(5);
		return result;
	}
	bool stopSpeech() { return [synth stopSpeakingAtBoundary:AVSpeechBoundaryImmediate]; }
	bool pauseSpeech() {
		if (!synth.isPaused && synth.isSpeaking) return [synth pauseSpeakingAtBoundary:AVSpeechBoundaryImmediate];
		return false;
	}
	bool isPaused() const { return synth.isPaused; }
	bool isSpeaking() const { return synth.isSpeaking; }
	std::string getCurrentVoice() const {
		@autoreleasepool {
			AVSpeechSynthesisVoice* voice = effectiveVoice();
			return voice && voice.name? std::string([voice.name UTF8String]) : std::string();
		}
	}
	CScriptArray* getAllVoices() const {
		asITypeInfo* arrayTipe = asGetActiveContext()->GetEngine()->GetTypeInfoByDecl("array<string>");
		CScriptArray* voiceNames = CScriptArray::Create(arrayTipe, (int)0);
		for (AVSpeechSynthesisVoice *voice in voices) {
			std::string voiceName([voice.name UTF8String]);
			voiceNames->Resize(voiceNames->GetSize() + 1);
			*(std::string*)voiceNames->At(voiceNames->GetSize() - 1) = voiceName;
		}
		return voiceNames;
	}
	CScriptArray* getVoicesByLanguage(const std::string& language) const {
		NSString *nslanguage = [NSString stringWithUTF8String:language.c_str()];
		asITypeInfo* arrayTipe = asGetActiveContext()->GetEngine()->GetTypeInfoByDecl("array<string>");
		CScriptArray* voiceNames = CScriptArray::Create(arrayTipe, (int)0);
		for (AVSpeechSynthesisVoice *voice in voices) {
			if (![voice.language isEqualToString:nslanguage]) continue;
			std::string voiceName([voice.name UTF8String]);
			voiceNames->Resize(voiceNames->GetSize() + 1);
			*(std::string*)voiceNames->At(voiceNames->GetSize() - 1) = voiceName;
		}
		return voiceNames;
	}
	void selectVoiceByName(const std::string& name) {
		NSString *nsname = [NSString stringWithUTF8String:name.c_str()];
		for (AVSpeechSynthesisVoice *voice in voices) {
			if (![voice.name isEqualToString:nsname]) continue;
			currentVoice = voice;
			break;
		}
	}
	void selectVoiceByLanguage(const std::string& language) {
		NSString *nslanguage = [NSString stringWithUTF8String:language.c_str()];
		for (AVSpeechSynthesisVoice *voice in voices) {
			if (![voice.language isEqualToString:nslanguage]) continue;
			currentVoice = voice;
			break;
		}
	}
	std::string getCurrentLanguage() const {
		@autoreleasepool {
			AVSpeechSynthesisVoice* voice = effectiveVoice();
			return voice && voice.language? std::string([voice.language UTF8String]) : std::string();
		}
	}
	NSUInteger getVoicesCount() const { return voices.count; }
	int getVoiceIndex(const std::string& name) {
		AVSpeechSynthesisVoice *voice = getVoiceObject([NSString stringWithUTF8String:name.c_str()]);
		if (!voice) return -1;
		NSUInteger result = [voices indexOfObject:voice];
		return result == NSNotFound? -1 : result;
	}
	bool setVoiceByIndex(NSUInteger index) {
		AVSpeechSynthesisVoice *oldVoice = currentVoice;
		@try {
			currentVoice = [voices objectAtIndex:index];
			return true;
		} @catch (NSException *exception) {
			currentVoice = oldVoice;
			return false;
		}
	}
	std::string getVoiceName(NSUInteger index) {
		@try { return [[voices objectAtIndex:index].name UTF8String]; }
		@catch (NSException *exception) { return ""; }
	}
	std::string getVoiceLanguage(NSUInteger index) {
		@try {
			AVSpeechSynthesisVoice *voice = [voices objectAtIndex:index];
			std::string lang([voice.language UTF8String]);
			std::transform(lang.begin(), lang.end(), lang.begin(), ::tolower);
			return lang;
		} @catch (NSException *exception) { return ""; }
	}
private:
	AVSpeechSynthesisVoice *getVoiceObject(NSString *name) {
		for (AVSpeechSynthesisVoice *v in voices) {
			if ([v.name isEqualToString:name]) return v;
		}
		return nil;
	}
};

AVTTSVoice::AVTTSVoice() : tts_engine_impl("avspeech"), impl(new Impl()), RefCount(1) {}
AVTTSVoice::~AVTTSVoice() { delete impl; }

bool AVTTSVoice::speak(const std::string& text, bool interrupt, bool blocking) {
	if (blocking) return impl->speakWait(text, interrupt);
	return impl->speak(text, interrupt);
}

bool AVTTSVoice::speakWait(const std::string& text, bool interrupt) {
	return impl->speakWait(text, interrupt);
}

bool AVTTSVoice::pauseSpeech() {
	return impl->pauseSpeech();
}

bool AVTTSVoice::stopSpeech() {
	return impl->stopSpeech();
}

std::string AVTTSVoice::getCurrentVoice() const {
	return impl->getCurrentVoice();
}
CScriptArray* AVTTSVoice::getAllVoices() const {
	return impl->getAllVoices();
}
CScriptArray* AVTTSVoice::getVoicesByLanguage(const std::string& language) const {
	return impl->getVoicesByLanguage(language);
}

void AVTTSVoice::setVoiceByLanguage(const std::string& language) {
	impl->selectVoiceByLanguage(language);
}
void AVTTSVoice::setVoiceByName(const std::string& name) {
	impl->selectVoiceByName(name);
}
float AVTTSVoice::get_rate() { return impl->rate; }
float AVTTSVoice::get_pitch() { return impl->pitch; }
float AVTTSVoice::get_volume() { return impl->volume; }
bool AVTTSVoice::isPaused() const { return impl->isPaused(); }
bool AVTTSVoice::is_speaking() { return impl->isSpeaking(); }
void AVTTSVoice::set_rate(float rate) { impl->rate = rate; impl->rateSet = true; }
void AVTTSVoice::set_pitch(float pitch) { impl->pitch = pitch; impl->pitchSet = true; }
void AVTTSVoice::set_volume(float volume) { impl->volume = volume; impl->volumeSet = true; }
bool AVTTSVoice::reset_rate() { if (!impl) return false; impl->resetRate(); return true; }
bool AVTTSVoice::reset_pitch() { if (!impl) return false; impl->resetPitch(); return true; }
bool AVTTSVoice::reset_volume() { if (!impl) return false; impl->resetVolume(); return true; }
bool AVTTSVoice::reset_voice() { if (!impl) return false; impl->resetVoice(); return true; }
std::string AVTTSVoice::getCurrentLanguage() const {
	return impl->getCurrentLanguage();
}
uint64_t AVTTSVoice::getVoicesCount() const {
	return impl->getVoicesCount();
}

int AVTTSVoice::getVoiceIndex(const std::string& name) const {
	return impl->getVoiceIndex(name);
}

bool AVTTSVoice::setVoiceByIndex(uint64_t index) {
	return impl->setVoiceByIndex(index);
}
std::string AVTTSVoice::getVoiceName(uint64_t index) {
	return impl->getVoiceName(index);
}

bool AVTTSVoice::is_available() { return impl != nullptr; }
tts_pcm_generation_state AVTTSVoice::get_pcm_generation_state() { return !running_on_mobile()? PCM_PREFERRED : PCM_SUPPORTED; }
bool AVTTSVoice::stop() { return impl ? impl->stopSpeech() : false; }

bool AVTTSVoice::get_rate_range(float& minimum, float& midpoint, float& maximum) { minimum = AVSpeechUtteranceMinimumSpeechRate; midpoint = AVSpeechUtteranceDefaultSpeechRate; maximum = AVSpeechUtteranceMaximumSpeechRate; return true; }
bool AVTTSVoice::get_pitch_range(float& minimum, float& midpoint, float& maximum) { minimum = 0.2; midpoint = 1; maximum = 4; return true; }
bool AVTTSVoice::get_volume_range(float& minimum, float& midpoint, float& maximum) { minimum = 0; midpoint = 0.5; maximum = 1; return true; }

int AVTTSVoice::get_voice_count() { return impl ? static_cast<int>(impl->getVoicesCount()) : 0; }

std::string AVTTSVoice::get_voice_name(int index) {
	if (!impl || index < 0 || index >= get_voice_count()) return "";
	return impl->getVoiceName(static_cast<uint64_t>(index));
}
std::string AVTTSVoice::get_voice_language(int index) {
	if (!impl || index < 0 || index >= get_voice_count()) return "";
	return impl->getVoiceLanguage(static_cast<uint64_t>(index));
}

bool AVTTSVoice::set_voice(int voice_index) {
	if (!impl || voice_index < 0 || voice_index >= get_voice_count()) return false;
	return impl->setVoiceByIndex(static_cast<uint64_t>(voice_index));
}

int AVTTSVoice::get_current_voice() {
	if (!impl) return -1;
	return impl->effectiveVoiceIndex();
}

tts_audio_data* AVTTSVoice::speak_to_pcm(const std::string &text) {
	if (!impl || text.empty()) return nullptr;
	if (@available(iOS 13.0, macOS 10.15, *)) {} else return nullptr;
	__block NSMutableData *audioData = [[NSMutableData alloc] init];
	__block BOOL synthesisDone = NO;
	__block AVAudioFormat *targetFormat = nil;
	__block AVAudioConverter *converter = nil;
	NSString *nstext = [NSString stringWithUTF8String:text.c_str()];
	AVSpeechUtterance *utterance = [[AVSpeechUtterance alloc] initWithString:nstext];
	impl->apply(utterance);
	[impl->synth writeUtterance:utterance toBufferCallback:^(AVAudioBuffer * _Nonnull buffer) {
		@autoreleasepool {
			if (![buffer isKindOfClass:[AVAudioPCMBuffer class]]) return;
			AVAudioPCMBuffer *pcmBuffer = (AVAudioPCMBuffer *)buffer;
			if (pcmBuffer.frameLength == 0) { synthesisDone = YES; return; }
			if (!converter) {
				AVAudioFormat *sourceFormat = pcmBuffer.format;
				if (!sourceFormat) return;
				targetFormat = [[AVAudioFormat alloc] initWithCommonFormat:AVAudioPCMFormatInt16 sampleRate:sourceFormat.sampleRate channels:sourceFormat.channelCount interleaved:YES];
				if (!targetFormat) return;
				converter = [[AVAudioConverter alloc] initFromFormat:sourceFormat toFormat:targetFormat];
				if (!converter) { [targetFormat release]; targetFormat = nil; return; }
			}
			AVAudioPCMBuffer *convertedBuffer = [[AVAudioPCMBuffer alloc] initWithPCMFormat:targetFormat frameCapacity:pcmBuffer.frameLength];
			if (!convertedBuffer) return;
			__block BOOL inputProvided = NO;
			AVAudioConverterInputBlock inputBlock = ^AVAudioBuffer *(AVAudioPacketCount inNumberOfPackets, AVAudioConverterInputStatus *outStatus) {
				if (inputProvided) { *outStatus = AVAudioConverterInputStatus_NoDataNow; return nil; }
				inputProvided = YES;
				*outStatus = AVAudioConverterInputStatus_HaveData;
				return pcmBuffer;
			};
			NSError *error = nil;
			AVAudioConverterOutputStatus status = [converter convertToBuffer:convertedBuffer error:&error withInputFromBlock:inputBlock];
			if (status == AVAudioConverterOutputStatus_HaveData && convertedBuffer.frameLength > 0) {
				NSUInteger bytesToAppend = convertedBuffer.frameLength * targetFormat.channelCount * sizeof(int16_t);
				[audioData appendBytes:convertedBuffer.int16ChannelData[0] length:bytesToAppend];
			}
		}
	}];
	NSDate *timeout = [NSDate dateWithTimeIntervalSinceNow:10.0];
	while (!synthesisDone && [[NSDate date] compare:timeout] == NSOrderedAscending) [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.01]];
	if (converter) [converter release];
	if (targetFormat) [targetFormat release];
	if (!synthesisDone || audioData.length == 0) return nullptr;
	unsigned int sampleRate = targetFormat ? (unsigned int)targetFormat.sampleRate : 22050;
	unsigned int channelCount = targetFormat ? (unsigned int)targetFormat.channelCount : 1;
	[audioData retain];
	return new tts_audio_data(this, (void*)audioData.bytes, (unsigned int)audioData.length, sampleRate, channelCount, 16, (void*)audioData);
}

void AVTTSVoice::free_pcm(tts_audio_data* data) {
	if (data && data->context) {
		NSMutableData* audioData = (NSMutableData*)data->context;
		[audioData release];
		data->context = nullptr;
	}
	tts_engine_impl::free_pcm(data);
}

AVTTSVoice* init() {
	return new AVTTSVoice;
}

bool voice_over_announce(const std::string& message) {
	NSString* nsmsg = [NSString stringWithUTF8String:message.c_str()];
#if TARGET_OS_IOS
	UIAccessibilityPostNotification(UIAccessibilityAnnouncementNotification, nsmsg);
	return UIAccessibilityIsVoiceOverRunning();
#else
	NSWindow* win = g_window? (NSWindow*)g_window->get_native_window() : nullptr;
	NSAccessibilityPostNotificationWithUserInfo([NSApp keyWindow], NSAccessibilityAnnouncementRequestedNotification, @{NSAccessibilityAnnouncementKey: nsmsg, NSAccessibilityPriorityKey: @(NSAccessibilityPriorityHigh)});
	return [NSApp keyWindow] == win;
#endif
}

std::string speech_text = "";
Poco::FastMutex speech_text_mutex;
Poco::Event speech_new_event;
Poco::Thread speech_thread;
bool speech_shutdown = false;
// So this really sucks, and if someone can come along and make this nonsense unneeded, it would be very very appreciated. So the apple documentation taunts us telling us that we can pass speech notification priorities to NSAccessibilityPostNotificationWithUserInfo to control speech interrupt, and quite simply it doesn't work. While this doesn't at all make non-interrupting speech events actually work, it does make it possible to queue multiple speak calls together with only the first being interrupting.
void vo_speech_thread(void* extra) {
	speech_new_event.wait();
	if (speech_shutdown) {
		speech_shutdown = false;
		return;
	}
	while (speech_new_event.tryWait(10)) continue;
	Poco::FastMutex::ScopedLock exclusive(speech_text_mutex);
	voice_over_announce(speech_text);
	speech_text = "";
}

#if TARGET_OS_IOS
// UIAccessibilityTraitAllowsDirectInteraction only hands touches to us while VoiceOver's cursor is
// actually sitting on the element. Any time it sits elsewhere -- the status bar, a notification
// banner, or wherever it lands when the app returns to the foreground or dismisses the keyboard --
// VoiceOver swallows every swipe and tap, and a self voicing game looks frozen even though it is
// still speaking perfectly well. Posting a screen change with the view as its argument moves the
// cursor back onto us, which is what makes direct interaction actually unconditional.
// Cleared while the app deliberately hands the cursor away: the on screen keyboard needs it during
// text input, and taking it back there would make typing impossible.
static bool g_ios_direct_interaction = true;
static NSTimeInterval g_ios_last_focus_grab = 0;

static void ios_focus_game_view() {
	if (!g_window) return;
	UIView* view = ((UIWindow*)g_window->get_native_window()).rootViewController.view;
	if (!view) return;
	UIAccessibilityPostNotification(UIAccessibilityScreenChangedNotification, view);
}
#endif

void voice_over_window_created(game_window* window) {
	#if TARGET_OS_IOS
		UIWindow* win = (UIWindow*)window->get_native_window();
		UIView* view = win.rootViewController.view;
		view.isAccessibilityElement = YES;
		view.accessibilityTraits |= UIAccessibilityTraitAllowsDirectInteraction;
		// Direct interaction keeps VoiceOver silent on this element, so with no label there is nothing
		// at all to tell the player that the cursor has landed on the game.
		if (!view.accessibilityLabel) {
			NSString* name = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleDisplayName"];
			if (!name) name = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleName"];
			if (name) view.accessibilityLabel = name;
		}
		ios_focus_game_view();
		// Coming back from the background drops the cursor wherever UIKit likes, so claim it again.
		static BOOL observing_activation = NO;
		if (!observing_activation) {
			observing_activation = YES;
			[[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidBecomeActiveNotification object:nil queue:[NSOperationQueue mainQueue] usingBlock:^(NSNotification* notification) { ios_focus_game_view(); }];
		}
		// The cursor can also drift off mid session -- a tap on the status bar, a notification banner,
		// anything the system focuses -- and direct interaction stops passing touches the instant it
		// does, so the game goes deaf while it is still speaking and looks frozen. Take it back
		// whenever it lands elsewhere, except where we gave it up on purpose: during text input, while
		// an alert (apple_input_box) is up, and while we are not the active app.
		static BOOL observing_focus = NO;
		if (!observing_focus) {
			observing_focus = YES;
			[[NSNotificationCenter defaultCenter] addObserverForName:UIAccessibilityElementFocusedNotification object:nil queue:[NSOperationQueue mainQueue] usingBlock:^(NSNotification* notification) {
				if (!g_ios_direct_interaction || !g_window) return;
				if ([UIApplication sharedApplication].applicationState != UIApplicationStateActive) return;
				UIWindow* focus_win = (UIWindow*)g_window->get_native_window();
				if (!focus_win || focus_win.rootViewController.presentedViewController) return;
				UIView* focus_view = focus_win.rootViewController.view;
				if (!focus_view || notification.userInfo[UIAccessibilityFocusedElementKey] == focus_view) return;
				// If something insists on stealing focus back, lose the fight quietly rather than spin.
				NSTimeInterval now = [NSDate timeIntervalSinceReferenceDate];
				if (now - g_ios_last_focus_grab < 0.25) return;
				g_ios_last_focus_grab = now;
				ios_focus_game_view();
			}];
		}
	#else
		NSWindow* win = (NSWindow*)window->get_native_window();
		NSAccessibilityPostNotification(win, NSAccessibilityApplicationActivatedNotification);
		NSAccessibilityPostNotification(win, NSAccessibilityApplicationShownNotification);
		NSAccessibilityPostNotification(win, NSAccessibilityWindowCreatedNotification);
		NSAccessibilityPostNotification(win, NSAccessibilityFocusedWindowChangedNotification);
	#endif
}

void ios_set_direct_interaction(bool enabled) {
	#if TARGET_OS_IOS
		g_ios_direct_interaction = enabled;
		if (!g_window) return;
		UIView* view = ((UIWindow*)g_window->get_native_window()).rootViewController.view;
		if (enabled) {
			view.accessibilityTraits |= UIAccessibilityTraitAllowsDirectInteraction;
			// The on screen keyboard has just gone away and took the cursor with it; take it back.
			ios_focus_game_view();
		} else
			view.accessibilityTraits &= ~UIAccessibilityTraitAllowsDirectInteraction;
	#endif
}

#if TARGET_OS_IOS
// VoiceOver lives in its own process and asks us about every touch and every keyboard key (what is
// under the finger, does it allow direct interaction, what is it called), one question at a time,
// and UIKit answers each of them on the main thread's run loop. The script owns the main thread, so
// that run loop only turns inside SDL_PumpEvents, for a couple of microseconds per wait(). Through
// the rest of every frame -- the sleep in wait() and, for a game that draws, the wait for the next
// display refresh inside the Metal present -- VoiceOver's questions sit in the queue, each one costs
// up to a frame, and with VoiceOver on every gesture, menu item and key arrives late. The two
// functions below do that same waiting inside the run loop instead, so questions are answered as
// they arrive.
static CADisplayLink* g_refresh_link = nil;
static bool g_refresh_ticked = false;
@interface NVGTRefreshTarget : NSObject
- (void)tick:(CADisplayLink*)link;
@end
@implementation NVGTRefreshTarget
- (void)tick:(CADisplayLink*)link { g_refresh_ticked = true; }
@end
#endif

void apple_run_loop_sleep(int ms) {
	#if TARGET_OS_IOS
		CFAbsoluteTime deadline = CFAbsoluteTimeGetCurrent() + ms / 1000.0;
		CFTimeInterval left;
		while ((left = deadline - CFAbsoluteTimeGetCurrent()) > 0) {
			// Finished means the mode has nothing in it that could wake us; sleep the rest rather than spin.
			if (CFRunLoopRunInMode(kCFRunLoopDefaultMode, left, false) == kCFRunLoopRunFinished) {
				Poco::Thread::sleep((long)(left * 1000));
				return;
			}
		}
	#else
		Poco::Thread::sleep(ms);
	#endif
}

void apple_wait_for_display_refresh() {
	#if TARGET_OS_IOS
		// The display link is paused while we are in the background; keep the old behaviour there.
		if (![NSThread isMainThread] || [UIApplication sharedApplication].applicationState != UIApplicationStateActive) return;
		if (!g_refresh_link) {
			// The display link retains its target, so ours can be released straight away.
			NVGTRefreshTarget* target = [[NVGTRefreshTarget alloc] init];
			g_refresh_link = [[CADisplayLink displayLinkWithTarget:target selector:@selector(tick:)] retain];
			[target release];
			[g_refresh_link addToRunLoop:[NSRunLoop mainRunLoop] forMode:NSRunLoopCommonModes];
		}
		// Presenting just after a refresh finds a drawable already free, so the present that follows no
		// longer blocks in nextDrawable. If a refresh went by while the script was busy, present at once.
		// Short slices notice the tick within a couple of milliseconds even where the run loop doesn't
		// count it as a handled source, and the deadline keeps a tick that never comes from hanging us.
		CFAbsoluteTime deadline = CFAbsoluteTimeGetCurrent() + 0.05;
		CFTimeInterval left;
		while (!g_refresh_ticked && (left = deadline - CFAbsoluteTimeGetCurrent()) > 0) {
			if (CFRunLoopRunInMode(kCFRunLoopDefaultMode, left < 0.002 ? left : 0.002, true) == kCFRunLoopRunFinished) break;
		}
		g_refresh_ticked = false;
	#endif
}

bool voice_over_is_running() {
	#if TARGET_OS_IOS
		return UIAccessibilityIsVoiceOverRunning();
	#else
		return [[NSWorkspace sharedWorkspace] isVoiceOverEnabled];
	#endif
}

bool voice_over_speak(const std::string& message, bool interrupt) {
	if (!voice_over_is_running()) return false;
	if (!speech_thread.isRunning()) speech_thread.start(vo_speech_thread);
	Poco::FastMutex::ScopedLock exclusive(speech_text_mutex);
	if (interrupt || speech_text == "") speech_text = message;
	else {
		speech_text += " . ";
		speech_text += message;
	}
	speech_new_event.set();
	#if TARGET_OS_IOS
		return UIAccessibilityIsVoiceOverRunning();
	#else
		NSWindow* win = g_window ? (NSWindow*)g_window->get_native_window() : nullptr;
		return [NSApp keyWindow] == win;
	#endif
}

void voice_over_speech_shutdown() {
	speech_shutdown = true;
	speech_new_event.set();
}

std::string apple_get_identifier_for_vendor() {
#if TARGET_OS_IOS
	NSUUID* uuid = [UIDevice currentDevice].identifierForVendor;
	if (uuid) return [uuid.UUIDString UTF8String];
#endif
	return "";
}

bool screen_reader_load() { return true; }
void screen_reader_unload() { voice_over_speech_shutdown(); }
std::string screen_reader_detect() { return voice_over_is_running() ? "VoiceOver" : ""; }
bool screen_reader_has_speech() { return voice_over_is_running(); }
bool screen_reader_has_braille() { return false; }
bool screen_reader_is_speaking() { return false; }
bool screen_reader_output(const std::string& text, bool interrupt) { return voice_over_speak(text, interrupt); }
bool screen_reader_speak(const std::string& text, bool interrupt) { return voice_over_speak(text, interrupt); }
bool screen_reader_braille(const std::string& text) { return false; }
bool screen_reader_silence() { return voice_over_speak("", true); }
// The following code was originally taken from https://github.com/hammerspoon/hammerspoon under an MIT license, but has been heavily trimmed/modified for our simpler needs and basically consists of system API calls. It was then run through Claude to create the IOS version.
#if !TARGET_OS_IOS
std::string apple_input_box(const std::string& title, const std::string& message, const std::string& default_value, bool secure, bool readonly) {
	NSAlert* alert = [[NSAlert alloc] init];
	[alert setMessageText:[NSString stringWithUTF8String:title.c_str()]];
	[alert setInformativeText:[NSString stringWithUTF8String:message.c_str()]];
	[alert addButtonWithTitle:@"OK"];
	[alert addButtonWithTitle:@"Cancel"];
	[[alert.buttons objectAtIndex:0] setKeyEquivalent:@"\r"]; // Return
	[[alert.buttons objectAtIndex:1] setKeyEquivalent:@"\033"]; // Escape
	NSTextField* input;
	if (secure) input = [[NSSecureTextField alloc] initWithFrame:NSMakeRect(0, 0, 200, 24)];
	else input = [[NSTextField alloc] initWithFrame:NSMakeRect(0, 0, 200, 24)];
	[input setStringValue:[NSString stringWithUTF8String:default_value.c_str()]];
	input.editable = !readonly;
	[alert setAccessoryView:input];
	[[alert window] setInitialFirstResponder:input]; // Focus on text input.
	NSInteger result = [alert runModal];
	if (result == NSAlertFirstButtonReturn) return [[input stringValue] UTF8String];
	else if (result == NSAlertSecondButtonReturn) return "\xff"; // nvgt value for cancel for the moment.
	return "\xff"; // Either an error or we can't determine what was pressed.
}
#else
std::string apple_input_box(const std::string& title, const std::string& message, const std::string& default_value, bool secure, bool readonly) {
	__block std::string result = "\xff";
	__block bool done = false;
	__block UIWindow* alertWindow = nil;
	dispatch_async(dispatch_get_main_queue(), ^{
		UIWindow* sdlWindow = g_window ? (UIWindow*)g_window->get_native_window() : nil;
		UIAlertController* alert = [UIAlertController alertControllerWithTitle:[NSString stringWithUTF8String:title.c_str()] message:[NSString stringWithUTF8String:message.c_str()] preferredStyle:UIAlertControllerStyleAlert];
		[alert addTextFieldWithConfigurationHandler:^(UITextField* field) {
			field.text = [NSString stringWithUTF8String:default_value.c_str()];
			field.secureTextEntry = secure;
			field.enabled = !readonly;
			field.accessibilityLabel = [NSString stringWithUTF8String:message.c_str()]; // Attach caption so VoiceOver announces label+field as one element.
		}];
		void (^dismiss)(void) = ^{
			if (alertWindow) alertWindow.hidden = YES;
			alertWindow = nil;
			if (sdlWindow) sdlWindow.hidden = NO;
			done = true;
		};
		[alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:^(UIAlertAction* action) {
			NSString* text = alert.textFields.firstObject.text;
			result = text ? [text UTF8String] : "";
			dismiss();
		}]];
		[alert addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:^(UIAlertAction* action) {
			dismiss();
		}]];
		// Create a dedicated window isolated from SDL's view hierarchy. Hidden (not key) so SDL retains key status,
		// preventing orientation changes and touch disruption. SDL's window is hidden to stop VoiceOver forwarding touches to it.
		if (@available(iOS 13.0, *)) {
			for (UIScene* scene in [UIApplication sharedApplication].connectedScenes) {
				if (scene.activationState == UISceneActivationStateForegroundActive && [scene isKindOfClass:[UIWindowScene class]]) {
					alertWindow = [[UIWindow alloc] initWithWindowScene:(UIWindowScene*)scene];
					break;
				}
			}
		}
		if (!alertWindow) alertWindow = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
		alertWindow.rootViewController = [[UIViewController alloc] init];
		alertWindow.windowLevel = UIWindowLevelAlert;
		if (sdlWindow) sdlWindow.hidden = YES;
		alertWindow.hidden = NO;
		[alertWindow.rootViewController presentViewController:alert animated:YES completion:nil];
	});
	while (!done) [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.05]];
	return result;
}
#endif

unsigned long long system_running_milliseconds() {
	struct timeval boottime, now;
	int mib[2] = {CTL_KERN, KERN_BOOTTIME};
	size_t size = sizeof(boottime);
	if (sysctl(mib, 2, &boottime, &size, NULL, 0) != 0) return 0;
	gettimeofday(&now, NULL);
	long long ms = ((long long)(now.tv_sec - boottime.tv_sec)) * 1000LL + (now.tv_usec - boottime.tv_usec) / 1000;
	return ms > 0 ? (unsigned long long)ms : 0;
}
