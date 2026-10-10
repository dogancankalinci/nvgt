package com.samtupy.nvgt;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.graphics.Typeface;
import android.text.method.ScrollingMovementMethod;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputMethodManager;
import android.widget.*;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.io.StringWriter;
import java.io.PrintWriter;
import android.os.Build;
import android.os.PowerManager;
import android.provider.Settings;
import android.text.Editable;
import android.text.Spannable;
import android.text.method.PasswordTransformationMethod;
import android.text.style.SuggestionSpan;
import android.view.accessibility.AccessibilityNodeInfo;
import android.content.Context;
import android.content.ContextWrapper;
import org.libsdl.app.SDLActivity;

public final class DialogUtils {
	public static String getExceptionInfo(Throwable t) {
		if (t == null) return "Unknown Error";
		StringWriter sw = new StringWriter();
		PrintWriter pw = new PrintWriter(sw);
		t.printStackTrace(pw);
		return sw.toString();
	}

	/**
	 * Adds what a focused TextView puts in its accessibility node, except for the clipboard query. TalkBack asks for the
	 * node whenever it moves through the views, and a focused TextView answers by calling
	 * ClipboardManager.hasPrimaryClip() over binder on the UI thread to decide whether to offer Paste; a clipboard
	 * service that is slow to reply then freezes the UI thread long enough to be reported as not responding. A view
	 * that builds its node as if unfocused skips that query and calls this to restore the rest, with the conditions
	 * TextView uses on every version from Android 5 to 16. Paste is offered without the clipboard check: performing it
	 * checks the clipboard itself and does nothing when it is empty. Process text and smart actions are left out, as
	 * TextView only offers them for a view that has an id.
	 */
	public static void addFocusedAccessibilityActions(TextView view, AccessibilityNodeInfo info) {
		info.setFocused(true);
		info.removeAction(AccessibilityNodeInfo.AccessibilityAction.ACTION_FOCUS);
		info.addAction(AccessibilityNodeInfo.AccessibilityAction.ACTION_CLEAR_FOCUS);
		CharSequence text = view.getText();
		boolean editable = text instanceof Editable, keys = editable && view.getKeyListener() != null;
		if (Build.VERSION.SDK_INT >= 30 && editable && view.onCheckIsTextEditor() && view.isEnabled()) {
			CharSequence label = view.getImeActionLabel();
			if (label == null) label = systemString(view, "keyboardview_keycode_enter");
			info.addAction(new AccessibilityNodeInfo.AccessibilityAction(android.R.id.accessibilityActionImeEnter, label));
		}
		boolean canCopy = !(view.getTransformationMethod() instanceof PasswordTransformationMethod) && text.length() > 0 && view.hasSelection();
		if (canCopy) info.addAction(AccessibilityNodeInfo.AccessibilityAction.ACTION_COPY);
		if (keys && view.getSelectionStart() >= 0 && view.getSelectionEnd() >= 0) info.addAction(AccessibilityNodeInfo.AccessibilityAction.ACTION_PASTE);
		if (canCopy && keys) info.addAction(AccessibilityNodeInfo.AccessibilityAction.ACTION_CUT);
		if (Build.VERSION.SDK_INT >= 33 && canShowSuggestions(view)) {
			info.addAction(AccessibilityNodeInfo.AccessibilityAction.ACTION_SHOW_TEXT_SUGGESTIONS);
		}
		if (Build.VERSION.SDK_INT >= 23 && canCopy && canShare(view)) {
			CharSequence label = systemString(view, "share");
			if (label != null) info.addAction(new AccessibilityNodeInfo.AccessibilityAction(ACCESSIBILITY_ACTION_SHARE, label));
		}
	}

	// TextView's own id for its Share action (TextView.ACCESSIBILITY_ACTION_SHARE, unchanged since Android 6). TextView
	// performs it itself, after checking again that the view is focused and that sharing is allowed.
	private static final int ACCESSIBILITY_ACTION_SHARE = 0x10000000;
	private static volatile boolean deviceProvisioned = false;

	// TextView.canShare without its canCopy part. canStartActivityForResult is hidden, but only an Activity answers true.
	static boolean canShare(TextView view) {
		Context context = view.getContext();
		if (Build.VERSION.SDK_INT >= 24) {
			boolean activity = false;
			for (Context c = context; c != null && !activity; c = c instanceof ContextWrapper ? ((ContextWrapper) c).getBaseContext() : null) activity = c instanceof Activity;
			if (!activity) return false;
			// Like TextView, remember a provisioned device instead of asking settings again; provisioning is not undone.
			if (!deviceProvisioned) deviceProvisioned = Settings.Global.getInt(context.getContentResolver(), Settings.Global.DEVICE_PROVISIONED, 0) != 0;
			if (!deviceProvisioned) return false;
		}
		if (Build.VERSION.SDK_INT >= 35) {
			int id = view.getResources().getIdentifier("config_textShareSupported", "bool", "android");
			if (id != 0 && !view.getResources().getBoolean(id)) return false;
		}
		return true;
	}

	// A string from Android's own resources, which TextView uses for these action labels, or null if there is none.
	private static CharSequence systemString(TextView view, String name) {
		int id = view.getResources().getIdentifier(name, "string", "android");
		return id != 0 ? view.getResources().getText(id) : null;
	}

	// Android's own test for offering text suggestions to accessibility services, TextView.canReplace together with
	// Editor.shouldOfferToShowSuggestions; both are written against public API, so it can be reproduced exactly.
	static boolean canShowSuggestions(TextView view) {
		if (view.getTransformationMethod() instanceof PasswordTransformationMethod) return false;
		CharSequence text = view.getText();
		if (text.length() == 0 || !(text instanceof Spannable) || !view.isSuggestionsEnabled()) return false;
		Spannable spannable = (Spannable) text;
		int selectionStart = view.getSelectionStart(), selectionEnd = view.getSelectionEnd();
		SuggestionSpan[] spans = spannable.getSpans(selectionStart, selectionEnd, SuggestionSpan.class);
		if (spans.length == 0) return false;
		if (selectionStart == selectionEnd) {
			for (SuggestionSpan span : spans) {
				if (span.getSuggestions().length > 0) return true;
			}
			return false;
		}
		int minSpanStart = text.length(), maxSpanEnd = 0;
		int coverStart = text.length(), coverEnd = 0;
		boolean hasValidSuggestions = false;
		for (SuggestionSpan span : spans) {
			int spanStart = spannable.getSpanStart(span), spanEnd = spannable.getSpanEnd(span);
			minSpanStart = Math.min(minSpanStart, spanStart);
			maxSpanEnd = Math.max(maxSpanEnd, spanEnd);
			if (selectionStart < spanStart || selectionStart > spanEnd) continue;
			hasValidSuggestions = hasValidSuggestions || span.getSuggestions().length > 0;
			coverStart = Math.min(coverStart, spanStart);
			coverEnd = Math.max(coverEnd, spanEnd);
		}
		if (!hasValidSuggestions || coverStart >= coverEnd) return false;
		return minSpanStart >= coverStart && maxSpanEnd <= coverEnd;
	}

	public static CompletableFuture<String> inputBox(Activity activity, String caption, String prompt, String defaultText) {
		Objects.requireNonNull(activity, "activity");
		Objects.requireNonNull(caption, "caption");
		Objects.requireNonNull(prompt, "prompt");
		final String initial = defaultText != null ? defaultText : "";
		final CompletableFuture<String> result = new CompletableFuture<>();
		activity.runOnUiThread(() -> {
			// Building the dialog runs framework code that can throw, for example when a widget cannot load one of the
			// system's own resources or the activity's window is already gone. Uncaught on the UI thread that ends the
			// process, and inputBoxSync would otherwise wait on this future forever, so report it as a cancelled input.
			try {
			EditText edit = new EditText(activity) {
				// Builds its accessibility node as if unfocused; see addFocusedAccessibilityActions.
				private boolean buildingNode;

				@Override
				public boolean isFocused() {
					return !buildingNode && super.isFocused();
				}

				@Override
				public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo info) {
					boolean focused = super.isFocused();
					buildingNode = true;
					try {
						super.onInitializeAccessibilityNodeInfo(info);
					} finally {
						buildingNode = false;
					}
					if (focused) addFocusedAccessibilityActions(this, info);
				}
			};
			edit.setSingleLine(true);
			edit.setText(initial);
			edit.setSelection(initial.length());
			edit.setImeOptions(EditorInfo.IME_ACTION_DONE);
			AlertDialog dialog = new AlertDialog.Builder(activity)
				.setTitle(caption)
				.setMessage(prompt)
				.setView(edit)
				.setCancelable(true)
				.setPositiveButton("OK", (dlg, which) ->
					result.complete(edit.getText().toString())
				)
				.setNegativeButton("Cancel", (dlg, which) ->
					result.complete("\u00FF")
				)
				.setOnCancelListener(dlg ->
					result.complete("\u00FF")
				)
				.create();
			dialog.getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_VISIBLE);
			dialog.setCanceledOnTouchOutside(false);
			dialog.show();
			edit.setOnEditorActionListener((v, actionId, event) -> {
				if (actionId == EditorInfo.IME_ACTION_DONE) {
					dialog.getButton(DialogInterface.BUTTON_POSITIVE).performClick();
					return true;
				}
				return false;
			});
			} catch (RuntimeException e) {
				result.complete("\u00FF");
			}
		});
		return result;
	}


/**
	 * Displays a modal information dialog with title, prompt, and multi-line text.
	 * Resolves when the user taps "Close".
	 */

	public static CompletableFuture<Void> infoBox(Activity activity, String caption, String prompt, String text) {
		Objects.requireNonNull(activity, "activity");
		Objects.requireNonNull(caption, "caption");
		Objects.requireNonNull(prompt, "prompt");
		Objects.requireNonNull(text, "text");
		final CompletableFuture<Void> done = new CompletableFuture<>();
		activity.runOnUiThread(() -> {
			// Same reasoning as inputBox: a framework failure while building the dialog must resolve the future.
			try {
			LinearLayout container = new LinearLayout(activity);
			container.setOrientation(LinearLayout.VERTICAL);
			int padding = (int)(16 * activity.getResources().getDisplayMetrics().density);
			container.setPadding(padding, padding, padding, padding);
			TextView lbl = new TextView(activity);
			lbl.setText(prompt);
			lbl.setTypeface(Typeface.DEFAULT_BOLD);
			container.addView(lbl, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
			ScrollView scroller = new ScrollView(activity);
			TextView tv = new TextView(activity);
			tv.setText(text);
			tv.setMovementMethod(new ScrollingMovementMethod());
			scroller.addView(tv, new ScrollView.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
			container.addView(scroller, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1.0f));
			new AlertDialog.Builder(activity)
				.setTitle(caption)
				.setView(container)
				.setCancelable(true)
				.setPositiveButton("Close", (dlg, which) -> {
					done.complete(null);
				})
				.setOnCancelListener(dlg -> done.complete(null))
				.show();
			} catch (RuntimeException e) {
				done.complete(null);
			}
		});
		return done;
	}

	public static String inputBoxSync(Activity activity, String caption, String prompt, String defaultText) {
		try {
			return inputBox(activity, caption, prompt, defaultText).get();
		} catch (Exception e) {
			return "\u00FF";
		}
	}

	public static void infoBoxSync(Activity activity, String caption, String prompt, String text) {
		try {
			infoBox(activity, caption, prompt, text).get();
		} catch (Exception ignored) { }
	}

	public static boolean isWindowActive(Activity activity) {
		if (activity == null) return false;
		PowerManager pm = (PowerManager)activity.getSystemService(Context.POWER_SERVICE);
		boolean screenOn = pm == null || pm.isInteractive();
		return activity.hasWindowFocus() && SDLActivity.mIsResumedCalled && screenOn;
	}
}
