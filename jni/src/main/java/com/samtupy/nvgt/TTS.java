package com.samtupy.nvgt;

import android.accessibilityservice.AccessibilityServiceInfo;
import android.app.Activity;
import android.app.Application;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.ApplicationInfo;
import android.content.pm.ResolveInfo;
import android.media.AudioAttributes;
import android.media.AudioFormat;
import android.os.Build;
import android.os.Bundle;
import android.os.SystemClock;
import android.os.Looper;
import android.provider.Settings;
import android.speech.tts.TextToSpeech;
import android.speech.tts.TextToSpeech.OnInitListener;
import android.speech.tts.UtteranceProgressListener;
import android.speech.tts.Voice;
import android.util.Log;
import android.view.ViewTreeObserver;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityManager;
import java.io.File;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Collections;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.HashSet;
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
		if (accessibilityManager == null || !accessibilityManager.isEnabled()) return false; // See the comment on screenReaderSilence().
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
		return isScreenReaderActive(); // See screenReaderSilence().
	}

	// With accessibility off nothing would receive an announcement or interruption: Android 5.0 throws when asked for one,
	// and later versions throw on the main thread but only log on others, such as the script's, which then looked like
	// success. So nothing is sent, and the call reports failure on every version. Any accessibility service turns
	// accessibility on, a password manager for instance, so with it on the calls succeed when a screen reader is active by
	// the same test as screen_reader_has_speech().
	public static boolean screenReaderSilence() {
		Context context = SDL.getContext();
		AccessibilityManager accessibilityManager = (AccessibilityManager) context.getSystemService(Context.ACCESSIBILITY_SERVICE);
		if (accessibilityManager == null || !accessibilityManager.isEnabled()) return false;
		accessibilityManager.interrupt();
		return isScreenReaderActive();
	}

	public static List<String> getEnginePackages() {
		List<String> packages = queryEnginePackages();
		return packages != null? packages : new ArrayList<>();
	}
	// The installed engines, or null when the package manager couldn't be asked.
	private static List<String> queryEnginePackages() {
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
		} catch (Exception e) {
			return null;
		}
		return packages;
	}
	// The same engines in the order Android itself falls back through them (TtsEngines.getEngines): those that are part of
	// the system image first, then by the priority their intent filter declares. getEnginePackages() keeps the package
	// manager's order, which voice indices depend on.
	public static List<String> getRankedEnginePackages() {
		List<String> packages = queryRankedEnginePackages();
		return packages != null? packages : new ArrayList<>();
	}
	private static List<String> queryRankedEnginePackages() {
		Context context = SDL.getContext();
		List<String> packages = new ArrayList<>();
		try {
			Intent intent = new Intent(TextToSpeech.Engine.INTENT_ACTION_TTS_SERVICE);
			List<ResolveInfo> services = context.getPackageManager().queryIntentServices(intent, 0);
			if (services == null) return packages;
			List<ResolveInfo> ranked = new ArrayList<>(services);
			Collections.sort(ranked, (a, b) -> {
				boolean aSystem = isSystemEngine(a), bSystem = isSystemEngine(b);
				if (aSystem != bSystem) return aSystem? -1 : 1;
				return b.priority - a.priority;
			});
			for (ResolveInfo info : ranked) {
				if (info.serviceInfo != null && info.serviceInfo.packageName != null) packages.add(info.serviceInfo.packageName);
			}
		} catch (Exception e) {
			return null;
		}
		return packages;
	}
	private static boolean isSystemEngine(ResolveInfo info) {
		ApplicationInfo app = info.serviceInfo != null? info.serviceInfo.applicationInfo : null;
		return app != null && (app.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
	}

	// The engine to use when none is asked for, read without the bind that constructing a TextToSpeech would make: the
	// user's default engine from the settings while it is installed, otherwise the highest ranked one, as the setting goes
	// on naming an engine whose app was removed. TextToSpeech.getDefaultEngine() falls back only to an engine of the
	// system image; any installed engine does here, which is still better than none.
	public static String getDefaultEnginePackage() {
		Context context = SDL.getContext();
		String defaultEngine = null;
		try {
			defaultEngine = Settings.Secure.getString(context.getContentResolver(), "tts_default_synth");
		} catch (Exception e) {}
		if (defaultEngine != null && !defaultEngine.isEmpty() && isEngineInstalled(defaultEngine)) return defaultEngine;
		List<String> ranked = installedEngines(true);
		return ranked.isEmpty()? "" : ranked.get(0);
	}

	// Engines the user installs, removes, disables or updates while the app runs. The package manager is asked again only
	// after a package changed, so whether an engine is still installed costs nothing to check otherwise. An app being
	// updated is removed and added again, and counts as installed meanwhile.
	private static volatile int packageGeneration = 0; // Raised on the main thread only.
	private static final Object packageListsLock = new Object(); // Guards the three below, and is never held while the package manager is asked.
	private static int listedGeneration = -1; // packageGeneration when the lists below were made.
	private static List<String> installedPackages = new ArrayList<>(), rankedPackages = new ArrayList<>();
	private static final Set<String> updatingPackages = Collections.newSetFromMap(new java.util.concurrent.ConcurrentHashMap<>()); // Used without a lock, so the main thread never waits for one.
	private static volatile boolean packageWatchInstalled = false; // Set under the class lock.
	private static void installPackageWatch() {
		if (packageWatchInstalled) return;
		synchronized (TTS.class) { installPackageWatchLocked(); }
	}
	private static void installPackageWatchLocked() {
		if (packageWatchInstalled) return;
		Context context = SDL.getContext();
		if (context == null || context.getApplicationContext() == null) return;
		packageWatchInstalled = true;
		BroadcastReceiver receiver = new BroadcastReceiver() {
			@Override
			public void onReceive(Context c, Intent intent) {
				String pkg = intent.getData() != null? intent.getData().getSchemeSpecificPart() : null;
				boolean updating = Intent.ACTION_PACKAGE_REMOVED.equals(intent.getAction()) && intent.getBooleanExtra(Intent.EXTRA_REPLACING, false);
				if (pkg != null && updating) updatingPackages.add(pkg);
				else if (pkg != null) updatingPackages.remove(pkg);
				packageGeneration++;
			}
		};
		IntentFilter filter = new IntentFilter();
		filter.addAction(Intent.ACTION_PACKAGE_ADDED);
		filter.addAction(Intent.ACTION_PACKAGE_REMOVED);
		filter.addAction(Intent.ACTION_PACKAGE_CHANGED);
		filter.addAction(Intent.ACTION_PACKAGE_REPLACED);
		filter.addDataScheme("package");
		try {
			// Only the system sends these, but on Android 13 and later a receiver must say it takes broadcasts from outside the app to get all of them.
			if (Build.VERSION.SDK_INT >= 33) context.getApplicationContext().registerReceiver(receiver, filter, Context.RECEIVER_EXPORTED);
			else context.getApplicationContext().registerReceiver(receiver, filter);
		} catch (Exception e) {}
	}
	// The installed engines in the package manager's order, or ranked as Android falls back through them. Lists the
	// package manager couldn't give leave the ones there were, to be asked for again on the next call.
	private static List<String> installedEngines(boolean ranked) {
		installPackageWatch();
		int generation = packageGeneration;
		synchronized (packageListsLock) {
			if (generation == listedGeneration) return ranked? rankedPackages : installedPackages;
		}
		List<String> installed = queryEnginePackages(), rankedList = queryRankedEnginePackages();
		synchronized (packageListsLock) {
			if (installed != null && rankedList != null && generation != listedGeneration) {
				installedPackages = installed;
				rankedPackages = rankedList;
				listedGeneration = generation;
			}
			return ranked? rankedPackages : installedPackages;
		}
	}
	private static boolean isEngineInstalled(String pkg) {
		return installedEngines(false).contains(pkg) || updatingPackages.contains(pkg);
	}
	// Changes when the voices of an engine may have changed: when a package was installed, removed or updated, or when a
	// window of the app gained focus again, as voices are installed and removed in the engine's own settings.
	public int getVoicesGeneration() { return packageGeneration + focusGeneration + connectionChanges; }
	// Raised when the voices are worth listing again for this engine alone: when recoverConnection() made a new connection,
	// and when an engine answers again after a listing found its connection down, as one does while its app is updated.
	private volatile int connectionChanges = 0;
	private volatile boolean listingMissed = false;
	private int listedAt = Integer.MIN_VALUE; // getVoicesGeneration() when the voices were last listed. Guarded by the object.
	// Lists the voices again when they may have changed since they were listed (see getVoicesGeneration()), so that an
	// engine, also one that waited in NVGT's pool meanwhile, never lists voices that were removed or leaves out new ones.
	private synchronized void listVoicesIfChanged() {
		if (listedAt != getVoicesGeneration()) initializeVoices();
	}

	// Then, the instantiable object that interfaces directly with the Android TextToSpeech system.
	private volatile TextToSpeech tts; // volatile: written on the constructor (game) thread, read from JNI/finalizer threads.
	private float ttsPan = 0.0f;
	private float ttsVolume = 1.0f;
	private float ttsRate = 1.0f;
	private float ttsPitch = 1.0f;
	// Nothing reaches the engine unless a script explicitly sets it. Until then an utterance carries no rate, pitch, volume or pan, so the TTS service fills them in from the user's own settings on every request, and the voice is the one the user's settings select (see followedSettings).
	private boolean rateExplicit = false, pitchExplicit = false, volumeExplicit = false, panExplicit = false;
	// TextToSpeech cannot clear a rate or pitch once one has been set. After such a value is reset we therefore re-apply the current system value before each utterance instead (see followSystemSettings()).
	private boolean ratePinned = false, pitchPinned = false;
	private Voice defaultVoice; // The voice the user's settings select, as TextToSpeech took it while connecting and followDefaultVoice() since, which resetVoice() restores.
	private volatile Voice chosenVoice; // The voice a script set, if any, which a replacement TextToSpeech is given too.
	private Locale defaultLanguage; // The language of the user's settings, as TextToSpeech took it while connecting and takeDefaultVoice() since.
	// While no voice was chosen, the voice follows the user's settings as they are now: the language set for the engine, or
	// the phone's, and the voice the engine itself names as its default for it. TextToSpeech looks both up only as it
	// connects and then names that voice in every request, so a change made while the app runs went unheard, and unreported,
	// until it started again. The language settings are read before every utterance, which costs nothing while they are
	// unchanged. The engine's own default voice changes only in the engine's settings, which take the user out of the app's
	// window, so it is looked up again once the window has had focus back (see followDefaultVoice()).
	private final Object followLock = new Object(); // Guards chosenVoice changes, defaultVoice, defaultLanguage and the two below.
	private String followedSettings; // The language settings the voice was last brought in line with, null to look again.
	private int followedFocus = -1; // focusGeneration when it was.
	private static volatile int focusGeneration = 0; // Raised, on the main thread only, each time an app window gains focus.
	private volatile boolean isTTSInitialized = false;
	private volatile int ttsInitStatus = TextToSpeech.ERROR; // status handed off from onInit (main thread) to the constructor via the latch.
	private CountDownLatch isTTSInitializedLatch;
	private final Object setupLock = new Object();
	private boolean gaveUp = false; // The constructor stopped waiting without a working connection. Guarded by setupLock.
	private String enginePackage;

	// PCM synthesis fields
	private int pcmSampleRate; // The format of the last synthesized audio, read back by the native side.
	private int pcmAudioFormat;
	private int pcmChannelCount;
	// One PCM request. The listener looks the current one up once and works on that object, so callbacks of a request that
	// timed out, which the engine can still deliver while the next one runs, only ever touch their own.
	private static final class PcmRequest {
		final String id;
		final ByteArrayOutputStream audio = new ByteArrayOutputStream();
		final CountDownLatch done = new CountDownLatch(1);
		volatile boolean started, successful;
		volatile int sampleRate, audioFormat, channelCount;
		PcmRequest(String id) { this.id = id; }
	}
	private volatile PcmRequest pcmRequest;
	private PcmRequest pcmRequestFor(String utteranceId) {
		PcmRequest request = pcmRequest;
		return request != null && request.id.equals(utteranceId)? request : null;
	}

	// Voice management fields
	private volatile List<Voice> availableVoices; // Replaced whole when the voices are listed again.

	// TextToSpeech finishes connecting to an engine on an AsyncTask that catches only RemoteException. When the engine's
	// own setCallback or default language code throws, the exception comes back through binder (a NullPointerException,
	// for example) and escapes that background thread, which ends the app. Only that failure is absorbed: TextToSpeech
	// then never calls onInit, and the constructor waiting for it is released at once when the failure can only be its
	// own (see connectionFailed()), or else gives up after its wait as it does for an engine that never answers.
	private static final String CONNECTION_SETUP_TASK = "android.speech.tts.TextToSpeech$Connection$SetupConnectionAsyncTask";
	private static boolean connectionGuardInstalled = false;
	private static synchronized void installConnectionGuard() {
		if (connectionGuardInstalled) return;
		connectionGuardInstalled = true;
		final Thread.UncaughtExceptionHandler previous = Thread.getDefaultUncaughtExceptionHandler();
		Thread.setDefaultUncaughtExceptionHandler((thread, error) -> {
			if (thread != Looper.getMainLooper().getThread() && isConnectionSetupFailure(error)) {
				Log.w("NVGT", "The text to speech engine failed while connecting", error);
				connectionFailed();
				return;
			}
			if (previous != null) previous.uncaughtException(thread, error);
		});
	}
	// A chain of causes can loop (initCause only refuses a throwable as its own cause), so at most 32 links are looked at.
	private static boolean isConnectionSetupFailure(Throwable error) {
		int links = 0;
		for (Throwable t = error; t != null && links < 32; t = t.getCause(), links++) {
			for (StackTraceElement frame : t.getStackTrace()) {
				if (CONNECTION_SETUP_TASK.equals(frame.getClassName()) && "doInBackground".equals(frame.getMethodName())) return true;
			}
		}
		return false;
	}
	// Every TTS object that created a TextToSpeech, added just before it does. A failure doesn't say which TextToSpeech it
	// came from, and any TextToSpeech, even one that was shut down or had connected, can set its connection up again when
	// its engine restarts, which public API gives no sign of. So a failure is only known to be an object's own while that
	// object's TextToSpeech is the only one the app has ever created; with more, a waiting constructor waits out its
	// timeout as it does for an engine that never answers.
	private static final Set<TTS> textToSpeechOwners = new HashSet<>();
	// Set once an object replaced its TextToSpeech (see recoverConnection()), after which no failure can be shown to come
	// from only one TextToSpeech.
	private static volatile boolean textToSpeechReplaced = false;
	private static void connectionFailed() {
		if (textToSpeechReplaced) return;
		TTS failed;
		synchronized (textToSpeechOwners) {
			if (textToSpeechOwners.size() != 1) return;
			failed = textToSpeechOwners.iterator().next();
		}
		boolean late;
		synchronized (failed.setupLock) { late = failed.gaveUp; }
		failed.isTTSInitializedLatch.countDown(); // ttsInitStatus is still ERROR, since onInit never came.
		if (late) failed.release();
	}
	// Shuts down a TextToSpeech this object gave up on, on a thread of its own: an engine that never answered can hold
	// TextToSpeech's lock indefinitely, and one that failed can throw again before the connection is released, which then
	// stays open.
	private void release() { shutDown(tts); }
	private static void shutDown(final TextToSpeech unusable) {
		if (unusable == null) return;
		Thread thread = new Thread(() -> {
			try {
				unusable.shutdown();
			} catch (RuntimeException e) {}
		}, "NVGT TTS shutdown");
		thread.setDaemon(true);
		thread.start();
	}
	// Before Android 12, TextToSpeech binds to the default or highest ranked engine instead of one it can't find, which
	// would then pose as the engine asked for, so an engine whose service can't be found is treated as unusable.
	private boolean engineFound(Context context) {
		if (enginePackage == null) return true;
		try {
			return context.getPackageManager().resolveService(new Intent(TextToSpeech.Engine.INTENT_ACTION_TTS_SERVICE).setPackage(enginePackage), 0) != null;
		} catch (Exception e) {
			return true; // Unknown, so left to TextToSpeech as before.
		}
	}
	// Routes speech through the accessibility stream, like a screen reader's. This sets no speech parameter.
	private static void useAccessibilityStream(TextToSpeech target) {
		try {
			AudioAttributes audioAttributes = new AudioAttributes.Builder().setUsage(AudioAttributes.USAGE_ASSISTANCE_ACCESSIBILITY).setContentType(AudioAttributes.CONTENT_TYPE_SPEECH).build();
			target.setAudioAttributes(audioAttributes);
		} catch (Exception e) {}
	}

	// Counts the times a window of the app gains focus, as it does when the user comes back from settings, also from a
	// window beside it. Activities are watched as they resume, so one that replaces another is watched too.
	private static boolean focusWatchInstalled = false;
	private static synchronized void installFocusWatch() {
		if (focusWatchInstalled) return;
		Context context = SDL.getContext();
		if (context == null) return;
		final Application application = (Application) context.getApplicationContext();
		if (application == null) return;
		focusWatchInstalled = true;
		final ViewTreeObserver.OnWindowFocusChangeListener focusListener = hasFocus -> {
			if (hasFocus) focusGeneration++;
		};
		final Set<Activity> watched = Collections.newSetFromMap(new java.util.WeakHashMap<>()); // Used on the main thread only.
		final Runnable watchActivity = () -> {
			if (!(context instanceof Activity)) return;
			Activity activity = (Activity) context;
			if (!watched.add(activity)) return;
			try {
				activity.getWindow().getDecorView().getViewTreeObserver().addOnWindowFocusChangeListener(focusListener);
			} catch (Exception e) {}
		};
		new android.os.Handler(Looper.getMainLooper()).post(() -> {
			watchActivity.run();
			application.registerActivityLifecycleCallbacks(new Application.ActivityLifecycleCallbacks() {
				@Override public void onActivityResumed(Activity activity) {
					focusGeneration++;
					if (!watched.add(activity)) return;
					try {
						activity.getWindow().getDecorView().getViewTreeObserver().addOnWindowFocusChangeListener(focusListener);
					} catch (Exception e) {}
				}
				@Override public void onActivityCreated(Activity activity, Bundle savedInstanceState) {}
				@Override public void onActivityStarted(Activity activity) {}
				@Override public void onActivityPaused(Activity activity) {}
				@Override public void onActivityStopped(Activity activity) {}
				@Override public void onActivitySaveInstanceState(Activity activity, Bundle outState) {}
				@Override public void onActivityDestroyed(Activity activity) {}
			});
		});
	}

	public TTS(String enginePkg) {
		installConnectionGuard();
		installFocusWatch();
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
				boolean late;
				synchronized (setupLock) {
					ttsInitStatus = status;
					late = gaveUp;
				}
				isTTSInitializedLatch.countDown();
				if (late) release(); // The connection came up, or failed, after the constructor stopped waiting for it.
			}
		};
		if (!engineFound(context)) {
			isTTSInitialized = false;
			isTTSInitializedLatch.countDown();
			return;
		}
		// Registered before TextToSpeech exists, since its connection can fail or call onInit before the constructor returns.
		synchronized (textToSpeechOwners) { textToSpeechOwners.add(this); }
		synchronized (followLock) { // The settings the connection takes its voice from, read before it does.
			followedSettings = languageSettings();
			followedFocus = focusGeneration;
		}
		try {
			tts = enginePackage != null ? new TextToSpeech(context, listener, enginePackage) : new TextToSpeech(context, listener);
		} catch (Exception e) {
			// Some restricted engines (e.g. Sao Mai Myanmar TTS, org.saomaicenter.myanmartts) refuse to let third-party apps bind to their service and throw a SecurityException straight from the constructor. If we let that propagate it leaves a pending Java exception that aborts the process on the next JNI call. Swallow it here and mark this engine as unavailable instead.
			synchronized (textToSpeechOwners) { textToSpeechOwners.remove(this); }
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
		boolean ready;
		synchronized (setupLock) {
			ready = ttsInitStatus == TextToSpeech.SUCCESS && tts != null;
			gaveUp = !ready;
		}
		if (ready) {
			useAccessibilityStream(tts);
			// Must be true before initializeVoices(), which early-returns when !isActive().
			isTTSInitialized = true;
			try {
				defaultVoice = tts.getVoice();
				defaultLanguage = tts.getLanguage();
			} catch (Exception e) {}
			initializeVoices();
			setupPcmListener(tts);
		} else {
			isTTSInitialized = false;
			release();
		}
	}
	public TTS() { this(null); }

	// An engine whose app was removed while this object used it is not active any more.
	public boolean isActive() { return isTTSInitialized && (enginePackage == null || isEngineInstalled(enginePackage)); }
	public boolean isSpeaking() { return isActive()? tts.isSpeaking() : false; }
	// Whether this object's own speech is still to be heard: speech it queued that hasn't ended, while the service speaks,
	// or for ten seconds after it was queued until the service picks it up, since an engine that dies reports no end. The
	// service's isSpeaking() alone answers for everyone using the engine, every app and every other TextToSpeech.
	public boolean hasPendingSpeech() {
		if (!isActive() || endedSerial >= trackedSerial) return false;
		return SystemClock.elapsedRealtime() - lastQueuedAt < 10000 || tts.isSpeaking();
	}

	public boolean speak(String text, boolean interrupt) { return speakTracked(text, interrupt) >= 0; }
	// The service refuses a text longer than getMaxSpeechInputLength() characters, and before Android 10 one of exactly
	// that length too, so longer text is queued, or synthesized, in parts.
	private static int maxRequestLength() { return TextToSpeech.getMaxSpeechInputLength() - (Build.VERSION.SDK_INT < 29? 1 : 0); }
	// Parts of at most max characters, each ending after the last sentence end or line break within the limit, else after
	// the last whitespace, else at the limit, but never between the halves of a surrogate pair. Text that fits stays whole.
	private static List<String> splitForSpeech(String text, int max) {
		List<String> parts = new ArrayList<>();
		int start = 0;
		while (text.length() - start > max) {
			int limit = start + max, cut = -1;
			for (int i = limit - 1; i > start && cut < 0; i--) {
				char c = text.charAt(i);
				if (c == '\n' || ((c == '.' || c == '!' || c == '?') && Character.isWhitespace(text.charAt(i + 1)))) cut = i + 1;
			}
			for (int i = limit - 1; i > start && cut < 0; i--) {
				if (Character.isWhitespace(text.charAt(i))) cut = i + 1;
			}
			if (cut < 0) cut = Character.isHighSurrogate(text.charAt(limit - 1))? limit - 1 : limit;
			parts.add(text.substring(start, cut));
			start = cut;
		}
		parts.add(text.substring(start));
		return parts;
	}
	// Queues text, the first part as interrupt asks and any others after it; only the last part carries lastUtteranceId.
	// Called with queueLock held, so the parts of one text can't be interleaved with another text being queued.
	// Returns QUEUED when all of it was queued and NOTHING_QUEUED when none was. When the service refuses a later part, a
	// moment of silence carrying lastUtteranceId follows the parts already queued, so the id still reports when they have
	// been spoken, and PARTLY_QUEUED is returned.
	private static final int NOTHING_QUEUED = 0, PARTLY_QUEUED = 1, QUEUED = 2;
	private int queueText(String text, boolean interrupt, String lastUtteranceId) {
		List<String> parts = splitForSpeech(text, maxRequestLength());
		Bundle params = utteranceParams(true);
		for (int i = 0; i < parts.size(); i++) {
			int mode = interrupt && i == 0? TextToSpeech.QUEUE_FLUSH : TextToSpeech.QUEUE_ADD;
			if (tts.speak(parts.get(i), mode, params, i == parts.size() - 1? lastUtteranceId : null) == TextToSpeech.SUCCESS) continue;
			if (i == 0 || lastUtteranceId == null) return NOTHING_QUEUED;
			return tts.playSilentUtterance(1, TextToSpeech.QUEUE_ADD, lastUtteranceId) == TextToSpeech.SUCCESS? PARTLY_QUEUED : NOTHING_QUEUED;
		}
		return QUEUED;
	}
	// isSpeaking() only turns true once the service has picked a request up, which can be after speak() returns, so speech
	// is spoken with an utterance id holding a serial number, and the listener records the highest serial that ended. This
	// object's utterances end in the order they were queued, or are dropped by a flush, so every lower serial has ended too.
	private static final String TRACKED_UTTERANCE = "nvgt_tracked_";
	private final Object queueLock = new Object();
	private volatile long trackedSerial = 0; // Written under queueLock, which is held while queueing, so serials follow queue order.
	private volatile long lastQueuedAt = 0; // When trackedSerial was last queued, in elapsedRealtime milliseconds.
	private volatile long endedSerial = 0; // Written under endedLock.
	private final Object endedLock = new Object();
	public long speakTracked(String text, boolean interrupt) {
		if (!isActive()) return -1;
		synchronized (queueLock) {
			followSystemSettings();
			followDefaultVoice();
			long serial = trackedSerial + 1;
			TextToSpeech speaking = tts;
			int queued = queueText(text, interrupt, TRACKED_UTTERANCE + serial);
			if (queued == NOTHING_QUEUED) {
				if (!recoverConnection(speaking)) return -1;
				followSystemSettings();
				followDefaultVoice();
				queued = queueText(text, interrupt, TRACKED_UTTERANCE + serial);
			}
			if (queued == NOTHING_QUEUED) return -1;
			trackedSerial = serial;
			lastQueuedAt = SystemClock.elapsedRealtime();
			return queued == QUEUED? serial : -2; // With part of the text refused the call fails, -2 telling it from -1, nothing queued, while what was queued is tracked till it has been spoken.
		}
	}
	public boolean isTrackedDone(long serial) { return endedSerial >= serial; }
	// Stopped speech, and speech a replaced TextToSpeech had queued, reports no end of its own.
	private void allTrackedEnded() {
		synchronized (endedLock) {
			endedSerial = Math.max(endedSerial, trackedSerial);
		}
	}
	private void trackedEnded(String utteranceId) {
		if (utteranceId == null || !utteranceId.startsWith(TRACKED_UTTERANCE)) return;
		long serial;
		try {
			serial = Long.parseLong(utteranceId.substring(TRACKED_UTTERANCE.length()));
		} catch (NumberFormatException e) {
			return;
		}
		synchronized (endedLock) {
			if (serial > endedSerial) endedSerial = serial;
		}
	}
	// On Android 12 and later, once its engine's process dies a TextToSpeech has no engine for good: the system ends its
	// session with the engine and TextToSpeech never asks for another, so everything it is asked to do fails. When a request
	// fails on a TextToSpeech that has no working connection any more (getVoices() is null only then), a new one is made for
	// the same engine and given what the script set, and the old one is shut down. The voices are listed again at the next
	// use, as the new connection can have other voices, so voice indices can change. One attempt is made at most every 30
	// seconds, because a failed one waits out the connection timeout.
	private long lastRecovery = 0; // Guarded by queueLock.
	private long connectionLostAt = 0; // When a request first found the connection gone, 0 while it works. Guarded by queueLock.
	private boolean recoverConnection(TextToSpeech failed) {
		synchronized (queueLock) {
			if (tts != failed) return true; // Another request already replaced it.
			Set<Voice> voices;
			try {
				voices = failed.getVoices();
			} catch (Exception e) {
				voices = null;
			}
			if (voices != null) { // The connection works, so the request failed for another reason.
				connectionLostAt = 0;
				return false;
			}
			long now = SystemClock.elapsedRealtime();
			// Before Android 12 TextToSpeech binds the engine itself and binds it again when the engine restarts, and while it
			// waits for that, shutdown() can't unbind it, so a replacement would leave it bound for good. It gets five seconds
			// to come back first.
			if (connectionLostAt == 0) connectionLostAt = now;
			if (Build.VERSION.SDK_INT < 31 && now - connectionLostAt < 5000) return false;
			if (lastRecovery != 0 && now - lastRecovery < 30000) return false;
			lastRecovery = now;
			Context context = SDL.getContext();
			if (!engineFound(context)) return false;
			textToSpeechReplaced = true;
			final CountDownLatch connected = new CountDownLatch(1);
			final int[] status = { TextToSpeech.ERROR };
			OnInitListener listener = result -> {
				status[0] = result;
				connected.countDown();
			};
			TextToSpeech replacement;
			try {
				replacement = enginePackage != null ? new TextToSpeech(context, listener, enginePackage) : new TextToSpeech(context, listener);
			} catch (Exception e) {
				return false;
			}
			try {
				connected.await(10, TimeUnit.SECONDS);
			} catch (InterruptedException e) {}
			if (status[0] != TextToSpeech.SUCCESS) {
				shutDown(replacement);
				return false;
			}
			useAccessibilityStream(replacement);
			setupPcmListener(replacement);
			synchronized (followLock) {
				try {
					Voice settingsVoice = replacement.getVoice();
					if (settingsVoice != null) defaultVoice = settingsVoice;
					Locale settingsLanguage = replacement.getLanguage();
					if (settingsLanguage != null) defaultLanguage = settingsLanguage;
					Voice voice = chosenVoice;
					if (voice != null) replacement.setVoice(voice);
				} catch (Exception e) {}
				followedSettings = null;
			}
			// A fresh TextToSpeech holds no rate or pitch, so only those a script set are given to it.
			if (rateExplicit) replacement.setSpeechRate(ttsRate);
			else ratePinned = false;
			if (pitchExplicit) replacement.setPitch(ttsPitch);
			else pitchPinned = false;
			tts = replacement;
			connectionChanges++;
			connectionLostAt = 0;
			allTrackedEnded();
			shutDown(failed);
			return true;
		}
	}
	// Per-utterance parameters: only the ones a script set, so the service uses its own defaults for the rest. Synthesis to a
	// file leaves the volume out, as withVolume() applies it to the samples, and an engine that honoured it too would apply it twice.
	private Bundle utteranceParams(boolean withVolume) {
		Bundle params = new Bundle();
		if (volumeExplicit && withVolume) params.putFloat(TextToSpeech.Engine.KEY_PARAM_VOLUME, ttsVolume);
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
	// The language setting of every engine (Settings.Secure.TTS_DEFAULT_LOCALE, hidden from the SDK but readable by apps), and
	// the phone's language, which an engine without one of its own speaks.
	private static String languageSettings() {
		String setting = null;
		try {
			setting = Settings.Secure.getString(SDL.getContext().getContentResolver(), "tts_default_locale");
		} catch (Exception e) {}
		return setting + "|" + Locale.getDefault().toLanguageTag();
	}
	// Brings the voice in line with the user's settings while no voice was chosen (see followedSettings): the engine's
	// default voice for its language as the settings name it now, as TextToSpeech would have taken it while connecting. An
	// engine that names no voice for that language keeps the one it has.
	private void followDefaultVoice() {
		if (chosenVoice != null || !isActive()) return;
		String settings = languageSettings();
		int focus = focusGeneration;
		synchronized (followLock) {
			if (chosenVoice != null || (!followAgain && focus == followedFocus && settings.equals(followedSettings))) return;
			followedSettings = settings;
			followedFocus = focus;
			followAgain = false;
			takeDefaultVoice(tts);
		}
	}
	// A lookup of the settings' voice that found the engine not answering, made again once it answers (see onStart).
	private volatile boolean followMissed = false, followAgain = false;
	// Gives the engine the default voice the user's settings select now. True when the engine has it; false when the settings
	// select none or the engine refused it, in which case it keeps the voice it has, which isn't taken as the default to put
	// back either. TextToSpeech answers the same while it isn't connected, so then the lookup is made again later. Called with
	// followLock held.
	private boolean takeDefaultVoice(TextToSpeech target) {
		try {
			Voice voice = target.getDefaultVoice();
			Voice current = voice != null? target.getVoice() : null;
			if (voice != null && ((current != null && current.getName().equals(voice.getName())) || target.setVoice(voice) == TextToSpeech.SUCCESS)) {
				defaultVoice = voice;
				if (voice.getLocale() != null) defaultLanguage = voice.getLocale();
				listVoice(voice);
				return true;
			}
			if (target.getVoices() == null) followMissed = true; // The engine isn't answering, so the settings weren't looked up at all.
		} catch (Exception e) {
			followMissed = true;
		}
		return false;
	}
	public boolean silence() {
		if (!isActive()) return false;
		allTrackedEnded();
		return tts.stop() == TextToSpeech.SUCCESS;
	}
	public String getVoice() { 
		if (!isActive()) return null;
		followDefaultVoice();
		Voice voice = tts.getVoice();
		return voice != null? voice.getName() : null;
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
		if (!isActive()) return false;
		synchronized (followLock) {
			// The settings' voice as it is now, as the one kept from before can have been replaced or removed while a voice was
			// chosen; failing that, the one kept, or the settings' language, as an engine can name no voice for it and still
			// speak it, and asking for that language again then brings its default back.
			String settings = languageSettings();
			int focus = focusGeneration;
			boolean reset = takeDefaultVoice(tts);
			if (!reset && defaultVoice != null) reset = tts.setVoice(defaultVoice) == TextToSpeech.SUCCESS;
			if (!reset && defaultLanguage != null) reset = tts.setLanguage(defaultLanguage) >= TextToSpeech.LANG_AVAILABLE;
			if (!reset) return false;
			chosenVoice = null;
			followedSettings = settings;
			followedFocus = focus;
		}
		return true;
	}

	// Called by the native engine as it is destroyed: the static set of TextToSpeech owners and the connection's listeners
	// keep this object reachable, so finalize() never comes. The object stays in that set, which counts every TextToSpeech
	// the app has created.
	public void shutdown() {
		isTTSInitialized = false;
		allTrackedEnded();
		shutDown(tts);
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
			if (!voice.getName().equals(name)) continue;
			synchronized (followLock) {
				if (tts.setVoice(voice) != TextToSpeech.SUCCESS) return false;
				chosenVoice = voice;
			}
			return true;
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

	// Lists the engine's installed voices. A list that can't be read now, while the connection is down for instance, leaves the one there was.
	private synchronized void initializeVoices() {
		if (!isActive()) return;
		int generation = getVoicesGeneration();
		List<Voice> listed = new ArrayList<>();
		java.util.Map<String, Voice> engineVoices = null; // Every voice the engine has, by name; null when it couldn't say.
		try {
			Set<Voice> voices = tts.getVoices();
			if (voices == null) listingMissed = true; // Listed again once the engine answers.
			else listedAt = generation;
			if (voices == null && availableVoices != null) return;
			if (voices != null) {
				engineVoices = new java.util.HashMap<>();
				for (Voice voice : voices) {
					engineVoices.put(voice.getName(), voice);
					if (!voice.isNetworkConnectionRequired() && !voice.getFeatures().contains("notInstalled"))
						listed.add(voice);
				}
			}
		} catch (Exception e) {
			listingMissed = true;
			if (availableVoices != null) return;
		}
		availableVoices = listed;
		// The voice the user's settings selected, and one the script chose, are listed even when the filter above would drop them (a network voice, for instance), so that the current voice can always be reported and a chosen one isn't taken as removed. Only while the engine still has them, though: a voice deleted in the engine's settings has left it, and a chosen one that isn't installed any more can't be spoken with, so both count as removed.
		Voice settingsVoice = defaultVoice, chosen = chosenVoice;
		if (settingsVoice != null && (engineVoices == null || engineVoices.containsKey(settingsVoice.getName()))) listVoice(settingsVoice);
		if (chosen != null && engineVoices != null) {
			Voice current = engineVoices.get(chosen.getName());
			if (current != null && !current.getFeatures().contains("notInstalled")) listVoice(chosen);
		}
	}
	// Lists the voices again, as voices can be installed or removed while the app runs; their indices can change.
	public void refreshVoices() { initializeVoices(); }
	// Adds a voice the user's settings selected, or the script chose, to the list when it isn't there, at its end, so that indices stay as they were.
	private synchronized void listVoice(Voice voice) {
		List<Voice> voices = availableVoices;
		if (voices == null) return;
		for (Voice listed : voices) {
			if (listed.getName().equals(voice.getName())) return;
		}
		// A new list rather than an addition, as the list is read without a lock on other threads.
		List<Voice> extended = new ArrayList<>(voices);
		extended.add(voice);
		availableVoices = extended;
	}

	// Set up permanent UtteranceProgressListener for PCM synthesis
	private void setupPcmListener(TextToSpeech target) {
		target.setOnUtteranceProgressListener(new UtteranceProgressListener() {
			@Override
			public void onStart(String utteranceId) {
				PcmRequest request = pcmRequestFor(utteranceId);
				if (request != null) request.started = true;
				if (listingMissed) {
					listingMissed = false;
					connectionChanges++;
				}
				if (followMissed) {
					followMissed = false;
					followAgain = true;
				}
			}
			@Override
			public void onBeginSynthesis(String utteranceId, int sampleRateInHz, int audioFormat, int channelCount) {
				PcmRequest request = pcmRequestFor(utteranceId);
				if (request == null) return;
				request.sampleRate = sampleRateInHz;
				request.audioFormat = audioFormat;
				request.channelCount = channelCount;
				request.started = true;
			}

			@Override
			public void onAudioAvailable(String utteranceId, byte[] audio) {
				PcmRequest request = pcmRequestFor(utteranceId);
				if (request != null) request.audio.write(audio, 0, audio.length);
			}

			// Before Android 6.0 a stopped utterance also ends here.
			@Override
			public void onDone(String utteranceId) {
				trackedEnded(utteranceId);
				PcmRequest request = pcmRequestFor(utteranceId);
				if (request == null) return;
				request.successful = true;
				request.done.countDown();
			}

			@Override
			public void onError(String utteranceId) {
				trackedEnded(utteranceId);
				PcmRequest request = pcmRequestFor(utteranceId);
				if (request != null) request.done.countDown();
			}

			@Override
			public void onStop(String utteranceId, boolean interrupted) {
				trackedEnded(utteranceId);
				PcmRequest request = pcmRequestFor(utteranceId);
				if (request != null) request.done.countDown();
			}
		});
	}

	public int getVoiceCount() {
		if (!isActive()) return 0;
		listVoicesIfChanged();
		List<Voice> voices = availableVoices;
		return voices != null? voices.size() : 0;
	}
	public String getVoiceName(int index) {
		List<Voice> voices = availableVoices;
		if (!isActive() || voices == null || index < 0 || index >= voices.size()) return "";
		return voices.get(index).getName();
	}
	public String getVoiceLanguage(int index) {
		List<Voice> voices = availableVoices;
		if (!isActive() || voices == null || index < 0 || index >= voices.size()) return "";
		Locale locale = voices.get(index).getLocale();
		if (locale == null) return "";
		String lang = locale.getLanguage();
		// Before Android 15, or for an app targeting an earlier version, Locale keeps the codes ISO 639 replaced for Hebrew, Indonesian
		// and Yiddish, which other platforms don't report.
		if (lang.equals("iw")) lang = "he";
		else if (lang.equals("in")) lang = "id";
		else if (lang.equals("ji")) lang = "yi";
		String country = locale.getCountry();
		return country.isEmpty()? lang.toLowerCase(Locale.ROOT) : (lang + "-" + country).toLowerCase(Locale.ROOT);
	}
	public boolean setVoiceByIndex(int index) {
		List<Voice> voices = availableVoices;
		if (!isActive() || voices == null || index < 0 || index >= voices.size()) return false;
		Voice voice = voices.get(index);
		synchronized (followLock) {
			if (tts.setVoice(voice) != TextToSpeech.SUCCESS) return false;
			chosenVoice = voice;
		}
		return true;
	}
	// The voice TextToSpeech is actually speaking with: the one a script set, otherwise the one it took from the user's settings. -1 if it has none, which happens when the engine doesn't support the language the settings name.
	public int getCurrentVoiceIndex() {
		if (!isActive()) return -1;
		listVoicesIfChanged();
		if (availableVoices == null) return -1;
		followDefaultVoice();
		Voice current;
		try {
			current = tts.getVoice();
		} catch (Exception e) {
			return -1;
		}
		List<Voice> voices = availableVoices;
		if (current == null || voices == null) return -1;
		for (int i = 0; i < voices.size(); i++) {
			if (voices.get(i).getName().equals(current.getName())) return i;
		}
		return -1;
	}

	// Synthesize text to PCM audio buffer. Text too long for one request is synthesized in parts whose samples are joined;
	// a part that produced no samples is skipped, and parts in different formats fail the whole text.
	public byte[] speakPcm(String text) {
		if (!isActive() || text.isEmpty()) return null;
		List<String> parts = splitForSpeech(text, maxRequestLength());
		if (parts.size() == 1) return withVolume(synthesizePart(text));
		ByteArrayOutputStream joined = new ByteArrayOutputStream();
		int sampleRate = 0, audioFormat = 0, channelCount = 0;
		for (String part : parts) {
			byte[] audio = synthesizePart(part);
			if (audio == null) return null;
			if (audio.length == 0) continue;
			if (joined.size() == 0) {
				sampleRate = pcmSampleRate;
				audioFormat = pcmAudioFormat;
				channelCount = pcmChannelCount;
			} else if (pcmSampleRate != sampleRate || pcmAudioFormat != audioFormat || pcmChannelCount != channelCount) return null;
			joined.write(audio, 0, audio.length);
		}
		pcmSampleRate = sampleRate;
		pcmAudioFormat = audioFormat;
		pcmChannelCount = channelCount;
		return withVolume(joined.toByteArray());
	}
	// The service applies a request's volume only while it plays the speech, through the AudioTrack, and not to audio
	// synthesized to a file, so the volume a script set is applied to the samples here, the same linear gain.
	private byte[] withVolume(byte[] audio) {
		if (audio == null || !volumeExplicit || ttsVolume >= 1.0f) return audio;
		float volume = Math.max(0.0f, ttsVolume);
		ByteBuffer samples = ByteBuffer.wrap(audio).order(ByteOrder.LITTLE_ENDIAN);
		if (pcmAudioFormat == AudioFormat.ENCODING_PCM_16BIT) {
			for (int i = 0; i + 1 < audio.length; i += 2) samples.putShort(i, (short) Math.round(samples.getShort(i) * volume));
		} else if (pcmAudioFormat == AudioFormat.ENCODING_PCM_8BIT) {
			for (int i = 0; i < audio.length; i++) audio[i] = (byte) Math.round(((audio[i] & 0xFF) - 128) * volume + 128);
		} else if (pcmAudioFormat == AudioFormat.ENCODING_PCM_FLOAT) {
			for (int i = 0; i + 3 < audio.length; i += 4) samples.putFloat(i, samples.getFloat(i) * volume);
		}
		return audio;
	}
	private long pcmSerial = 0; // Numbers PCM requests, which the caller makes one at a time.
	private static final java.util.concurrent.atomic.AtomicLong instanceSerials = new java.util.concurrent.atomic.AtomicLong();
	private final long instanceSerial = instanceSerials.incrementAndGet(); // Tells this object's synthesis file apart from other objects'.
	private byte[] synthesizePart(String text) {
		pcmSampleRate = 0;
		pcmAudioFormat = 0;
		pcmChannelCount = 0;
		PcmRequest request = new PcmRequest("nvgtts_" + (++pcmSerial));
		pcmRequest = request;

		// Start synthesis - using speak with synthesis callbacks. Each TTS object has its own file, since several can use one
		// engine at once: synthesis on one object is serialized by the caller, and a file that a timed out request writes
		// late is replaced by the next request.
		File file = new File(SDL.getContext().getCacheDir(), "nvgt_speech_" + (enginePackage != null ? enginePackage : "default") + "_" + instanceSerial + ".wav");
		followSystemSettings();
		followDefaultVoice();
		TextToSpeech synthesizing = tts;
		int result = synthesizing.synthesizeToFile(text, utteranceParams(false), file, request.id);
		if (result != TextToSpeech.SUCCESS && recoverConnection(synthesizing)) {
			followSystemSettings();
			followDefaultVoice();
			result = tts.synthesizeToFile(text, utteranceParams(false), file, request.id);
		}
		if (result != TextToSpeech.SUCCESS) {
			pcmRequest = null;
			return null;
		}

		// Wait for synthesis to complete. The engine takes requests one at a time, from every app using it, and one that
		// speaks holds the next until its speech has nearly been played, so the ten seconds count from when the engine was
		// last seen speaking before synthesis started, pushed back like that for at most a minute. Long text can take
		// longer than ten seconds to synthesize, so they also count from the last audio written to the file, which the
		// engine writes as it goes.
		try {
			long now = SystemClock.elapsedRealtime(), limit = now + 10000, stopExtending = now + 60000, written = 0;
			while (!request.done.await(100, TimeUnit.MILLISECONDS)) {
				now = SystemClock.elapsedRealtime();
				if (!request.started && now < stopExtending && tts.isSpeaking()) limit = now + 10000;
				long size = file.length();
				if (size != written) {
					written = size;
					limit = now + 10000;
				}
				if (now >= limit) break;
			}
		} catch (InterruptedException e) {
			pcmRequest = null;
			file.delete();
			return null;
		}

		// Clean up and return the audio data if successful
		pcmRequest = null;
		byte[] audio = null;
		if (request.successful) {
			pcmSampleRate = request.sampleRate;
			pcmAudioFormat = request.audioFormat;
			pcmChannelCount = request.channelCount;
			audio = request.audio.toByteArray();
			// Before Android 7.0 TextToSpeech gives the listener no audio, only the finished file.
			if (audio.length == 0) audio = readWavFile(file);
		}
		file.delete();
		return audio;
	}
	// The samples in a WAV file TextToSpeech wrote, with the format fields set from its header as onBeginSynthesis would
	// set them. TextToSpeech writes 8 and 16-bit samples, and floats as 32-bit ones, all under the PCM format tag.
	private byte[] readWavFile(File file) {
		byte[] data;
		try (RandomAccessFile in = new RandomAccessFile(file, "r")) {
			data = new byte[(int) in.length()];
			in.readFully(data);
		} catch (IOException e) {
			return null;
		}
		ByteBuffer wav = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
		if (data.length < 12 || wav.getInt(0) != 0x46464952 || wav.getInt(8) != 0x45564157) return null; // "RIFF", "WAVE"
		int channels = 0, sampleRate = 0, bits = 0;
		for (int chunk = 12; chunk <= data.length - 8;) {
			int id = wav.getInt(chunk), size = wav.getInt(chunk + 4), body = chunk + 8;
			if (size < 0 || size > data.length - body) size = data.length - body;
			if (id == 0x20746d66 && size >= 16) { // "fmt "
				channels = wav.getShort(body + 2);
				sampleRate = wav.getInt(body + 4);
				bits = wav.getShort(body + 14);
			} else if (id == 0x61746164) { // "data"
				int encoding = bits == 8? AudioFormat.ENCODING_PCM_8BIT : bits == 16? AudioFormat.ENCODING_PCM_16BIT : bits == 32? AudioFormat.ENCODING_PCM_FLOAT : 0;
				if (channels <= 0 || sampleRate <= 0 || encoding == 0) return null;
				pcmSampleRate = sampleRate;
				pcmChannelCount = channels;
				pcmAudioFormat = encoding;
				return Arrays.copyOfRange(data, body, body + size);
			}
			chunk = body + size + (size & 1);
		}
		return null;
	}

	public int getPcmSampleRate() { return pcmSampleRate; }
	public int getPcmAudioFormat() { return pcmAudioFormat; }
	public int getPcmChannelCount() { return pcmChannelCount; }
}
