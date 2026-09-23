package com.samtupy.nvgt;
import android.content.Context;
import org.libsdl.app.SDLActivity;
import org.libsdl.app.SDLSurface;
public class NVGTGame extends SDLActivity {
	protected SDLSurface createSDLSurface(Context context) {
		return new NVGTSurface(context);
	}
}
