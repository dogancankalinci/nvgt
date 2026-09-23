package com.samtupy.nvgt;
import android.content.Context;
import org.libsdl.app.SDLActivity;
import org.libsdl.app.SDLSurface;
public class NVGTGame extends SDLActivity {
	protected String getMainSharedObject() {
		return getContext().getApplicationInfo().nativeLibraryDir + "/libgame.so";
	}
	protected String[] getLibraries() {
		return new String[] {"SDL3", "game"};
	}
	protected SDLSurface createSDLSurface(Context context) {
		return new NVGTSurface(context);
	}
}
