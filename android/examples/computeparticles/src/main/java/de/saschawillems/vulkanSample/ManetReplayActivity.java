package de.saschawillems.vulkanSample;

import android.app.Activity;
import android.os.Bundle;
import android.view.Surface;
import android.view.SurfaceHolder;
import android.view.SurfaceView;
import android.view.Window;
import android.view.WindowManager;

public class ManetReplayActivity extends Activity implements SurfaceHolder.Callback {
    static {
        System.loadLibrary("manet_replay_bridge");
    }

    private SurfaceView surfaceView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        requestWindowFeature(Window.FEATURE_NO_TITLE);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_FULLSCREEN,
                WindowManager.LayoutParams.FLAG_FULLSCREEN);

        surfaceView = new SurfaceView(this);
        surfaceView.getHolder().addCallback(this);
        setContentView(surfaceView);
    }

    @Override
    public void surfaceCreated(SurfaceHolder holder) {
        Surface surface = holder.getSurface();
        String tracePath = getIntent().getStringExtra("tracePath");
        if (tracePath == null || tracePath.isEmpty()) {
            tracePath = getFilesDir().getAbsolutePath() + "/mali_hook_computeparticles.jsonl";
        }
        boolean runReplay = getIntent().getBooleanExtra("runReplay", false);
        boolean allowKick = getIntent().getBooleanExtra("allowKick", false);
        boolean submitKick = getIntent().getBooleanExtra("submitKick", false);
        int importLimit = getIntent().getIntExtra("importLimit", allowKick ? 1 : 0);
        int replayWidth = getIntent().getIntExtra("replayWidth", allowKick ? 1280 : 0);
        int replayHeight = getIntent().getIntExtra("replayHeight", allowKick ? 720 : 0);
        nativeSurfaceReady(surface, tracePath, runReplay, allowKick, submitKick, importLimit, replayWidth, replayHeight);
    }

    @Override
    public void surfaceChanged(SurfaceHolder holder, int format, int width, int height) {
        nativeSurfaceResized(holder.getSurface(), width, height);
    }

    @Override
    public void surfaceDestroyed(SurfaceHolder holder) {
        nativeSurfaceDestroyed();
    }

    private static native void nativeSurfaceReady(Surface surface, String tracePath, boolean runReplay, boolean allowKick, boolean submitKick, int importLimit, int replayWidth, int replayHeight);
    private static native void nativeSurfaceResized(Surface surface, int width, int height);
    private static native void nativeSurfaceDestroyed();
}
