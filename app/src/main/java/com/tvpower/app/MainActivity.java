package com.tvpower.app;

import android.app.Activity;
import android.graphics.Color;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * 电视电源 — 打开即关机 (reboot -p)。
 *
 * 首次使用需导入电脑上的 adbkey 私钥 (一次性):
 *   电脑 PowerShell 运行:
 *   adb push %USERPROFILE%\.android\adbkey /sdcard/Android/data/com.tvpower.app/files/adbkey
 * 导入后 App 以该私钥连接本机 adbd — 对应公钥已在电视授权列表内,
 * adbd 验签通过即直接授权, 无需任何弹窗。
 */
public class MainActivity extends Activity {

    private static final String EXTERNAL_KEY_NAME = "adbkey";     // 电脑推送目标 (/sdcard/Android/data/<pkg>/files/adbkey)
    private static final String INTERNAL_KEY_NAME = "adbkey.pem"; // App 内部私有存储

    private TextView statusText;
    private View importPanel;
    private PrivateKey adbKey;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(Color.BLACK);
        root.setPadding(48, 48, 48, 48);
        root.setGravity(Gravity.CENTER);

        statusText = new TextView(this);
        statusText.setTextColor(Color.WHITE);
        statusText.setTextSize(20);
        statusText.setGravity(Gravity.CENTER);
        root.addView(statusText, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f));

        importPanel = buildImportPanel();
        importPanel.setVisibility(View.GONE);
        root.addView(importPanel, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));

        setContentView(root);

        new Thread(this::startFlow).start();
    }

    private View buildImportPanel() {
        LinearLayout panel = new LinearLayout(this);
        panel.setOrientation(LinearLayout.VERTICAL);
        panel.setBackgroundColor(Color.parseColor("#101418"));
        panel.setPadding(32, 24, 32, 24);

        TextView info = new TextView(this);
        info.setTextColor(Color.parseColor("#c8d0d8"));
        info.setTextSize(14);
        info.setText("首次使用：导入电脑上的 adbkey 私钥（一次性）。\n\n"
                + "在电脑 PowerShell 中运行：\n"
                + "& \"D:\\Files\\ai_workSpace\\workBuddy_CN\\2026-10-25-11-57-07"
                + "\\platform-tools\\platform-tools\\adb.exe\" push "
                + "\"$env:USERPROFILE\\.android\\adbkey\" "
                + "/sdcard/Android/data/com.tvpower.app/files/adbkey\n\n"
                + "完成后回到本页点「重新检测」。\n\n"
                + "私钥仅保存在本机 App 私有空间，卸载本 App 即彻底清除。");
        panel.addView(info);

        Button retry = new Button(this);
        retry.setText("重新检测");
        retry.setFocusable(true);
        retry.setOnClickListener(v -> {
            importPanel.setVisibility(View.GONE);
            new Thread(this::startFlow).start();
        });
        panel.addView(retry);

        Button legacy = new Button(this);
        legacy.setText("直接尝试连接（走系统弹窗授权）");
        legacy.setFocusable(true);
        legacy.setOnClickListener(v -> new Thread(() -> shutdown(null)).start());
        panel.addView(legacy);

        return panel;
    }

    private void startFlow() {
        try {
            adbKey = loadKeyWithImport();
        } catch (Exception e) {
            final String msg = e.getMessage();
            runOnUiThread(() -> {
                statusText.setText("密钥导入失败：" + msg);
                importPanel.setVisibility(View.VISIBLE);
            });
            return;
        }
        if (adbKey == null) {
            runOnUiThread(() -> {
                statusText.setText("等待导入 adbkey…");
                importPanel.setVisibility(View.VISIBLE);
            });
            return;
        }
        shutdown(adbKey);
    }

    /** key 非空 = 注入私钥直连; key = null = AndroidKeyStore + 弹窗路线 */
    private void shutdown(final PrivateKey key) {
        runOnUiThread(() -> statusText.setText("正在关机…"));
        final List<String> hosts = new ArrayList<>();
        hosts.addAll(localIpCandidates());
        hosts.add("127.0.0.1");
        String lastErr = "未知错误";
        for (String host : hosts) {
            AdbClient client = null;
            try {
                client = new AdbClient(key);
                client.connect(host, 5555, 5000, 8000);
                client.shell("reboot -p", 3000);
                return; // 已断电, 不会回来
            } catch (Exception e) {
                lastErr = host + " — " + e.getMessage();
            } finally {
                if (client != null) client.close();
            }
        }
        final String err = lastErr;
        runOnUiThread(() -> {
            statusText.setText("关机失败：" + err);
            importPanel.setVisibility(View.VISIBLE);
        });
    }

    // ---------------- 密钥导入 ----------------

    /** 内部存储优先; 否则从 App 外部私有目录导入并转存内部 */
    private PrivateKey loadKeyWithImport() throws Exception {
        PrivateKey k = loadInternalKey();
        if (k != null) return k;

        File ext = new File(getExternalFilesDir(null), EXTERNAL_KEY_NAME);
        if (ext.exists()) {
            byte[] pem = readAll(ext);
            PrivateKey parsed = AdbClient.parsePrivateKeyPem(pem); // 失败抛异常, 不删文件
            File internal = new File(getFilesDir(), INTERNAL_KEY_NAME);
            writeAll(internal, pem);
            ext.delete(); // 清除外部副本
            return parsed;
        }
        return null;
    }

    private PrivateKey loadInternalKey() throws Exception {
        File f = new File(getFilesDir(), INTERNAL_KEY_NAME);
        if (!f.exists()) return null;
        return AdbClient.parsePrivateKeyPem(readAll(f));
    }

    private static byte[] readAll(File f) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (InputStream in = new FileInputStream(f)) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
        }
        return bos.toByteArray();
    }

    private static void writeAll(File f, byte[] data) throws Exception {
        try (FileOutputStream out = new FileOutputStream(f)) {
            out.write(data);
        }
    }

    /** 本机 wlan/eth 地址列表 */
    private List<String> localIpCandidates() {
        List<String> result = new ArrayList<>();
        try {
            for (NetworkInterface nif : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                if (nif.getName().startsWith("wlan") || nif.getName().startsWith("eth")) {
                    for (java.util.Enumeration<InetAddress> addrs = nif.getInetAddresses(); addrs.hasMoreElements(); ) {
                        InetAddress a = addrs.nextElement();
                        if (a instanceof Inet4Address && a.getHostAddress() != null) {
                            result.add(a.getHostAddress());
                        }
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return result;
    }
}
