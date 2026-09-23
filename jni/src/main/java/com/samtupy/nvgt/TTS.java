package com.samtupy.nvgt;

import android.accessibilityservice.AccessibilityServiceInfo;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.ResolveInfo;
import android.media.AudioAttributes;
import android.os.Bundle;
import android.provider.Settings;
import android.speech.tts.TextToSpeech;
import android.speech.tts.TextToSpeech.OnInitListener;
import android.speech.tts.UtteranceProgressListener;
import android.speech.tts.Voice;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityManager;
import java.io.File;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.ArrayList;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.libsdl.app.SDL;

public class TTS {
	// First the static screen reader methods.
	static String AvoidDuplicateSpeechHack = ""; // Talkback unfortunately sets a flag that causes speech messages to not always be spoken over again in announcement events when the same message is repeated, we work around it by appending a changing number of spaces to the message and this variable stores those.
	public static boolean isScreenReaderActive() {
		Context context = SDL.getContext();
		AccessibilityManager am = (AccessibilityManager) context.getSystemService(Context.ACCESSIBILITY_SERVICE);
		if (am != null && am.isEnabled()) {
			List<AccessibilityServiceInfo> serviceInfoList = am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_SPOKEN);
			if (serviceInfoList.isEmpty()) return false;
			// Check for TouchExploration to avoid false positives from password managers/antivirus
			if (am.isTouchExplorationEnabled()) return true;
			for (AccessibilityServiceInfo info : serviceInfoList) {
				if (info.getId().contains("com.nirenr.talkman")) return true;
			}
		}
		return false;
	}

	public static String screenReaderDetect() {
		Context context = SDL.getContext();
		AccessibilityManager am = (AccessibilityManager) context.getSystemService(Context.ACCESSIBILITY_SERVICE);
		if (am != null && am.isEnabled()) {
			List<AccessibilityServiceInfo> serviceInfoList = am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_SPOKEN);
			if (serviceInfoList.isEmpty()) return "";
			if (am.isTouchExplorationEnabled()) return serviceInfoList.get(0).getId();
			for (AccessibilityServiceInfo info : serviceInfoList) {
				if (info.getId().contains("com.nirenr.talkman")) return info.getId();
			}
		}
		return "";
	}

	public static boolean screenReaderSpeak(String text, boolean interrupt) {
		Context context = SDL.getContext();
		AccessibilityManager accessibilityManager = (AccessibilityManager) context.getSystemService(Context.ACCESSIBILITY_SERVICE);
		if (accessibilityManager == null) return false;
		if (interrupt) accessibilityManager.interrupt();

		AccessibilityEvent e;
		if (android.os.Build.VERSION.SDK_INT >= 30) {
			e = new AccessibilityEvent();
		} else {
			e = AccessibilityEvent.obtain();
		}
		e.setEventType(AccessibilityEvent.TYPE_ANNOUNCEMENT);

		e.setPackageName(context.getPackageName());
		e.getText().add(text + AvoidDuplicateSpeechHack);
		AvoidDuplicateSpeechHack += " ";
		if (AvoidDuplicateSpeechHack.length() > 20) AvoidDuplicateSpeechHack = "";
		accessibilityManager.sendAccessibilityEvent(e);
		return true;
	}

	public static boolean screenReaderSilence() {
		Context context = SDL.getContext();
		AccessibilityManager accessibilityManager = (AccessibilityManager) context.getSystemService(Context.ACCESSIBILITY_SERVICE);
		if (accessibilityManager == null) return false;
		accessibilityManager.interrupt();
		return true;
	}

	public static List<String> getEnginePackages() {
		Context context = SDL.getContext();
		List<String> packages = new ArrayList<>();
		try {
			// Enumerate installed TTS engines WITHOUT instantiating a TextToSpeech. Creating a TextToSpeech (even just to call getEngines()) eagerly binds to the default engine; doing it here AND in getDefaultEnginePackage() is exactly why the default engine was being bound twice at startup. queryIntentServices is a lightweight PackageManager query, gated by the <queries> TTS_SERVICE declaration in our manifest, so it returns the same engine list with no binding.
			Intent intent = new Intent(TextToSpeech.Engine.INTENT_ACTION_TTS_SERVICE);
			List<ResolveInfo> services = context.getPackageManager().queryIntentServices(intent, 0);
			if (services != null) {
				for (ResolveInfo info : services) {
					if (info.serviceInfo != null && info.serviceInfo.packageName != null) packages.add(info.serviceInfo.packageName);
				}
			}
		} catch (Exception e) {}
		return packages;
	}

	public static String getDefaultEnginePackage() {
		Context context = SDL.getContext();
		try {
			// Read the user's default TTS engine straight from settings instead of constructing a TextToSpeech (which would bind to it). This is the same value TextToSpeech.getDefaultEngine() reports, minus the bind.
			String defaultEngine = Settings.Secure.getString(context.getContentResolver(), "tts_default_synth");
			return defaultEngine != null ? defaultEngine : "";
		} catch (Exception e) {
			return "";
		}
	}

	// Then, the instantiable object that interfaces directly with the Android TextToSpeech system.
	private volatile TextToSpeech tts; // volatile: written on the constructor (game) thread, read from JNI/finalizer threads.
	private float ttsPan = 0.0f;
	private float ttsVolume = 1.0f;
	private float ttsRate = 1.0f;
	private float ttsPitch = 1.0f;
	// Nothing reaches the engine unless a script explicitly sets it. Until then an utterance carries no rate, pitch, volume or pan, so the TTS service fills them in from the user's own settings on every request, and the voice stays the one TextToSpeech took from the user's language setting while connecting (see defaultVoice).
	private boolean rateExplicit = false, pitchExplicit = false, volumeExplicit = false, panExplicit = false;
	// TextToSpeech cannot clear a rate or pitch once one has been set. After such a value is reset we therefore re-apply the current system value before each utterance instead (see followSystemSettings()).
	private boolean ratePinned = false, pitchPinned = false;
	private Voice defaultVoice; // The voice TextToSpeech selected from the user's settings when it connected, which resetVoice() restores.
	private volatile boolean isTTSInitialized = false;
	private volatile int ttsInitStatus = TextToSpeech.ERROR; // status handed off from onInit (main thread) to the constructor via the latch.
	private CountDownLatch isTTSInitializedLatch;
	private String enginePackage;

	// PCM synthesis fields
	private ByteArrayOutputStream pcmAudioBuffer;
	private CountDownLatch pcmSynthesisLatch;
	private int pcmSampleRate;
	private int pcmAudioFormat;
	private int pcmChannelCount;
	private boolean pcmSynthesisSuccessful;
	private String currentPcmUtteranceId;

	// Voice management fields
	private List<Voice> availableVoices;
	public TTS(String enginePkg) {
		Context context = SDL.getContext();
		enginePackage = enginePkg;
		isTTSInitializedLatch = new CountDownLatch(1);
		// IMPORTANT: onInit is dispatched on the *main* thread, while this constructor
		// runs on the game/JNI thread. On fast devices (or when the TTS service is
		// already bound) onInit can fire *before* the `tts = new TextToSpeech(...)`
		// assignment below completes, so the listener must NEVER dereference `tts`
		// (that caused the `setSpeechRate on null` NPE). The listener now only records
		// the status and releases the latch; all engine setup that needs `tts` happens
		// after await() on THIS thread, where `tts` is guaranteed assigned. As a bonus
		// this moves the blocking getVoices() binder calls off the main thread,
		// eliminating the TTS-init ANRs.
		OnInitListener listener = new OnInitListener() {
			@Override
			public void onInit(int status) {
				ttsInitStatus = status;
				isTTSInitializedLatch.countDown();
			}
		};
		try {
			tts = enginePackage != null ? new TextToSpeech(context, listener, enginePackage) : new TextToSpeech(context, listener);
		} catch (Exception e) {
			// Some restricted engines (e.g. Sao Mai Myanmar TTS, org.saomaicenter.myanmartts) refuse to let third-party apps bind to their service and throw a SecurityException straight from the constructor. If we let that propagate it leaves a pending Java exception that aborts the process on the next JNI call. Swallow it here and mark this engine as unavailable instead.
			tts = null;
			isTTSInitialized = false;
			isTTSInitializedLatch.countDown();
			return;
		}
		try {
			// Wait for the async onInit callback (10s for slower devices / cold starts).
			isTTSInitializedLatch.await(10, TimeUnit.SECONDS);
		} catch (InterruptedException e) {}
		// Finish setting up here, on the constructor thread, where `tts` is non-null.
		// No speech setting is applied (no language, voice, rate or pitch): while
		// connecting, TextToSpeech has already selected the language and default voice
		// from the user's TTS settings, and the service applies the user's rate and
		// pitch to every request that doesn't carry its own. Setting any of them here
		// would override those settings. The audio attributes are different: they only
		// route speech through the accessibility stream, like a screen reader's.
		if (ttsInitStatus == TextToSpeech.SUCCESS && tts != null) {
			try {
				AudioAttributes audioAttributes = new AudioAttributes.Builder().setUsage(AudioAttributes.USAGE_ASSISTANCE_ACCESSIBILITY).setContentType(AudioAttributes.CONTENT_TYPE_SPEECH).build();
				tts.setAudioAttributes(audioAttributes);
			} catch (Exception e) {}
			// Must be true before initializeVoices(), which early-returns when !isActive().
			isTTSInitialized = true;
			try {
				defaultVoice = tts.getVoice();
			} catch (Exception e) {}
			initializeVoices();
			setupPcmListener();
		} else {
			isTTSInitialized = false;
		}
	}
	public TTS() { this(null); }

	public boolean isActive() { return this.isTTSInitialized; }
	public boolean isSpeaking() { return isActive()? tts.isSpeaking() : false; }

	public boolean speak(String text, boolean interrupt) {
		if (!isActive()) return false;
		if (text.length() > tts.getMaxSpeechInputLength()) return false;
		followSystemSettings();
		return tts.speak(text, interrupt? TextToSpeech.QUEUE_FLUSH : TextToSpeech.QUEUE_ADD, utteranceParams(), null) == TextToSpeech.SUCCESS;
	}
	// Per-utterance parameters: only the ones a script set, so the service uses its own defaults for the rest.
	private Bundle utteranceParams() {
		Bundle params = new Bundle();
		if (volumeExplicit) params.putFloat(TextToSpeech.Engine.KEY_PARAM_VOLUME, ttsVolume);
		if (panExplicit) params.putFloat(TextToSpeech.Engine.KEY_PARAM_PAN, ttsPan);
		return params;
	}
	private static float systemRate() {
		try {
			return Settings.Secure.getInt(SDL.getContext().getContentResolver(), Settings.Secure.TTS_DEFAULT_RATE, 100) / 100.0f;
		} catch (Exception e) {
			return 1.0f;
		}
	}
	private static float systemPitch() {
		try {
			return Settings.Secure.getInt(SDL.getContext().getContentResolver(), Settings.Secure.TTS_DEFAULT_PITCH, 100) / 100.0f;
		} catch (Exception e) {
			return 1.0f;
		}
	}
	// A rate or pitch that was set and then reset stays stored in TextToSpeech, so bring it in line with the user's current setting before speaking, which is what the service would have used had it never been set.
	private void followSystemSettings() {
		if (!rateExplicit && ratePinned) {
			float rate = systemRate();
			if (rate != ttsRate && tts.setSpeechRate(rate) == TextToSpeech.SUCCESS) ttsRate = rate;
		}
		if (!pitchExplicit && pitchPinned) {
			float pitch = systemPitch();
			if (pitch != ttsPitch && tts.setPitch(pitch) == TextToSpeech.SUCCESS) ttsPitch = pitch;
		}
	}
	public boolean silence() { return isActive()? tts.stop() == TextToSpeech.SUCCESS : false; }
	public String getVoice() { 
		if (!isActive() || tts.getVoice() == null) return null;
		return tts.getVoice().getName(); 
	}

	public boolean setRate(float rate) {
		if (!isActive()) return false;
		if (tts.setSpeechRate(rate) == TextToSpeech.SUCCESS) {
			ttsRate = rate;
			rateExplicit = true;
			ratePinned = true;
			return true;
		}
		return false;
	}
	public boolean setPitch(float pitch) {
		if (!isActive()) return false;
		if (tts.setPitch(pitch) == TextToSpeech.SUCCESS) {
			ttsPitch = pitch;
			pitchExplicit = true;
			pitchPinned = true;
			return true;
		}
		return false;
	}
	public void setPan(float pan) { ttsPan = pan; panExplicit = true; }
	public void setVolume(float volume) { ttsVolume = volume; volumeExplicit = true; }
	// The reset methods go back to following the user's settings. They return false only when the engine is unusable.
	public boolean resetRate() {
		if (!isActive()) return false;
		rateExplicit = false;
		return true;
	}
	public boolean resetPitch() {
		if (!isActive()) return false;
		pitchExplicit = false;
		return true;
	}
	public boolean resetVolume() {
		if (!isActive()) return false;
		ttsVolume = 1.0f;
		volumeExplicit = false;
		return true;
	}
	public boolean resetVoice() {
		if (!isActive() || defaultVoice == null) return false;
		return tts.setVoice(defaultVoice) == TextToSpeech.SUCCESS;
	}

	@Override
	protected void finalize() throws Throwable {
		if (isActive())
			tts.shutdown();
		super.finalize();
	}

	public List<String> getVoices() {
		List<String> names = new ArrayList<>();
		if (!isActive() || tts.getVoices() == null) return names;
		for (Voice voice : tts.getVoices())
			names.add(voice.getName());
		return names;
	}
	public boolean setVoice(String name) {
		if (!isActive()) return false;
		Set<Voice> voices = tts.getVoices();
		if (voices == null) return false;
		for (Voice voice : voices) {
			if (voice.getName().equals(name))
				return tts.setVoice(voice) == TextToSpeech.SUCCESS;
		}
		return false;
	}
	public int getMaxSpeechInputLength() { return isActive()? tts.getMaxSpeechInputLength() : 0; }
	public String getEngineLabel() {
		if (!isActive()) return enginePackage != null ? enginePackage : "";
		try {
			List<TextToSpeech.EngineInfo> engines = tts.getEngines();
			if (engines != null) {
				for (TextToSpeech.EngineInfo engine : engines) {
					if (engine.name.equals(enginePackage)) return engine.label;
				}
			}
		} catch (Exception e) {}
		return enginePackage != null ? enginePackage : "";
	}
	// Unless a script set them, rate and pitch are the user's current system values, read on every call.
	public float getRate() { return rateExplicit? ttsRate : systemRate(); }
	public float getPitch() { return pitchExplicit? ttsPitch : systemPitch(); }
	public float getVolume() { return ttsVolume; }
	public float getPan() { return ttsPan; }

	// Initialize voice management
	private void initializeVoices() {
		if (!isActive()) return;
		availableVoices = new ArrayList<>();
		try {
			Set<Voice> voices = tts.getVoices();
			if (voices != null) {
				for (Voice voice : voices) {
					if (!voice.isNetworkConnectionRequired() && !voice.getFeatures().contains("notInstalled"))
						availableVoices.add(voice);
				}
			}
			// The voice the user's settings selected is listed even when the filter above would drop it (a network voice, for instance), so that the current voice can always be reported.
			if (defaultVoice != null) {
				boolean listed = false;
				for (Voice voice : availableVoices) {
					if (voice.getName().equals(defaultVoice.getName())) {
						listed = true;
						break;
					}
				}
				if (!listed) availableVoices.add(defaultVoice);
			}
		} catch (Exception e) {}
	}

	// Set up permanent UtteranceProgressListener for PCM synthesis
	private void setupPcmListener() {
		tts.setOnUtteranceProgressListener(new UtteranceProgressListener() {
			@Override
			public void onStart(String utteranceId) {}
			@Override
			public void onBeginSynthesis(String utteranceId, int sampleRateInHz, int audioFormat, int channelCount) {
				if (currentPcmUtteranceId != null && currentPcmUtteranceId.equals(utteranceId)) {
					pcmSampleRate = sampleRateInHz;
					pcmAudioFormat = audioFormat;
					pcmChannelCount = channelCount;
				}
			}

			@Override
			public void onAudioAvailable(String utteranceId, byte[] audio) {
				if (currentPcmUtteranceId != null && currentPcmUtteranceId.equals(utteranceId) && pcmAudioBuffer != null) {
					try {
						pcmAudioBuffer.write(audio);
					} catch (IOException e) {
						pcmSynthesisSuccessful = false;
					}
				}
			}

			@Override
			public void onDone(String utteranceId) {
				if (currentPcmUtteranceId != null && currentPcmUtteranceId.equals(utteranceId)) {
					pcmSynthesisSuccessful = true;
					new File(SDL.getContext().getCacheDir(), "nvgt_speech.wav").delete();
					if (pcmSynthesisLatch != null) {
						pcmSynthesisLatch.countDown();
					}
				}
			}

			@Override
			public void onError(String utteranceId) {
				if (currentPcmUtteranceId != null && currentPcmUtteranceId.equals(utteranceId)) {
					pcmSynthesisSuccessful = false;
					new File(SDL.getContext().getCacheDir(), "nvgt_speech.wav").delete();
					if (pcmSynthesisLatch != null) {
						pcmSynthesisLatch.countDown();
					}
				}
			}
		});
	}

	public int getVoiceCount() { return isActive() && availableVoices != null? availableVoices.size() : 0; }
	public String getVoiceName(int index) {
		if (!isActive() || availableVoices == null || index < 0 || index >= availableVoices.size()) return "";
		return availableVoices.get(index).getName();
	}
	public String getVoiceLanguage(int index) {
		if (!isActive() || availableVoices == null || index < 0 || index >= availableVoices.size()) return "";
		Locale locale = availableVoices.get(index).getLocale();
		if (locale == null) return "";
		String lang = locale.getLanguage();
		String country = locale.getCountry();
		return country.isEmpty()? lang.toLowerCase(Locale.ROOT) : (lang + "-" + country).toLowerCase(Locale.ROOT);
	}
	public boolean setVoiceByIndex(int index) {
		if (!isActive() || availableVoices == null || index < 0 || index >= availableVoices.size()) return false;
		return tts.setVoice(availableVoices.get(index)) == TextToSpeech.SUCCESS;
	}
	// The voice TextToSpeech is actually speaking with: the one a script set, otherwise the one it took from the user's settings. -1 if it has none, which happens when the engine doesn't support the language the settings name.
	public int getCurrentVoiceIndex() {
		if (!isActive() || availableVoices == null) return -1;
		Voice current;
		try {
			current = tts.getVoice();
		} catch (Exception e) {
			return -1;
		}
		if (current == null) return -1;
		for (int i = 0; i < availableVoices.size(); i++) {
			if (availableVoices.get(i).getName().equals(current.getName())) return i;
		}
		return -1;
	}

	// Synthesize text to PCM audio buffer
	public byte[] speakPcm(String text) {
		if (!isActive() || text.isEmpty()) return null;
		if (text.length() > tts.getMaxSpeechInputLength()) return null;

		// Prepare for PCM synthesis
		pcmAudioBuffer = new ByteArrayOutputStream();
		pcmSynthesisLatch = new CountDownLatch(1);
		pcmSynthesisSuccessful = false;
		pcmSampleRate = 0;
		pcmAudioFormat = 0;
		pcmChannelCount = 0;

		// Create utterance ID and set it as current
		currentPcmUtteranceId = "nvgtts_" + System.currentTimeMillis();

		// Start synthesis - using speak with synthesis callbacks
		followSystemSettings();
		int result = tts.synthesizeToFile(text, utteranceParams(), new File(SDL.getContext().getCacheDir(), "nvgt_speech.wav"), currentPcmUtteranceId);
		if (result != TextToSpeech.SUCCESS) {
			currentPcmUtteranceId = null;
			return null;
		}

		// Wait for synthesis to complete
		try {
			pcmSynthesisLatch.await(10000, TimeUnit.MILLISECONDS); // 10 second timeout
		} catch (InterruptedException e) {
			currentPcmUtteranceId = null;
			return null;
		}

		// Clean up and return the audio data if successful
		currentPcmUtteranceId = null;
		if (pcmSynthesisSuccessful) {
			return pcmAudioBuffer.toByteArray();
		}
		return null;
	}

	public int getPcmSampleRate() { return pcmSampleRate; }
	public int getPcmAudioFormat() { return pcmAudioFormat; }
	public int getPcmChannelCount() { return pcmChannelCount; }
}
