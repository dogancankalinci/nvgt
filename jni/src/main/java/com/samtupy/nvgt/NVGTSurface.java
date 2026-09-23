package com.samtupy.nvgt;

import android.content.Context;
import android.hardware.Sensor;
import org.libsdl.app.SDLSurface;

// SDL registers an accelerometer listener whenever the activity is in the foreground. On every
// sensor event (SENSOR_DELAY_GAME, roughly 50 per second) its onSensorChanged runs on the UI thread
// and calls Display.getRotation(), which some vendor builds turn into a binder call into the system
// server; when that call stalls, input queued behind it times out and the app is reported as not
// responding. The listener only feeds SDL's virtual "Android Accelerometer" joystick and the display
// orientation, and NVGT uses neither: its joystick object opens gamepads only, and scripts have no
// access to the display orientation. So the accelerometer is never registered. Window size changes
// still arrive through surfaceChanged as before.
public class NVGTSurface extends SDLSurface {
	public NVGTSurface(Context context) {
		super(context);
	}

	@Override
	protected void enableSensor(int sensortype, boolean enabled) {
		if (sensortype == Sensor.TYPE_ACCELEROMETER) return;
		super.enableSensor(sensortype, enabled);
	}
}
