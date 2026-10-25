package com.tvpower.app;

import android.app.Activity;
import android.os.Bundle;
import android.view.Gravity;
import android.widget.TextView;

import java.net.Inet4Address;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.List;

/**
 * 电视电源: 启动即直接关机 (reboot -p), 无按钮、无确认界面。
 * 指令通过本机 ADB 以 shell 身份执行:
 *   - 索尼 adbd 对 127.0.0.1 来源的连接会跳过授权弹框(静默等待),
 *     故优先连本机 WLAN/eth IP (来源形式与 PC 连接一致, 弹框正常),
 *     loopback 仅作兜底。
 *   - 首次使用会在电视上弹出 "允许 USB 调试?" 对话框, 点允许即可 (仅一次)。
 */
public class MainActivity extends Activity {

    private TextView statusText;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        statusText = new TextView(this);
        statusText.setText("正在关机…");
        statusText.setTextSize(24);
        statusText.setGravity(Gravity.CENTER);
        statusText.setBackgroundColor(0xFF101418);
        statusText.setTextColor(0xFFF5F7FA);
        setContentView(statusText);

        shutdown();
    }

    private void shutdown() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                List<String> hosts = new ArrayList<>();
                hosts.addAll(localIpCandidates());
                hosts.add("127.0.0.1");
                Exception lastError = null;
                for (String h : hosts) {
                    AdbClient client = new AdbClient();
                    try {
                        client.connect(h, 5555, 10000, 120000);
                        client.shell("reboot -p", 8000);
                        return;
                    } catch (Exception e) {
                        lastError = e;
                        client.close();
                    }
                }
                final Exception le = lastError;
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        statusText.setText("关机失败：" + (le != null ? le.getMessage() : "无法连接本机 ADB"));
                    }
                });
            }
        }).start();
    }

    /** 本机 wlan/eth 地址列表 */
    private List<String> localIpCandidates() {
        List<String> result = new ArrayList<>();
        try {
            for (NetworkInterface nif : java.util.Collections.list(NetworkInterface.getNetworkInterfaces())) {
                if (nif.getName().startsWith("wlan") || nif.getName().startsWith("eth")) {
                    for (java.util.Enumeration<Inet4Address> addrs = nif.getInetAddresses(); addrs.hasMoreElements(); ) {
                        Inet4Address a = addrs.nextElement();
                        if (a.getHostAddress() != null) result.add(a.getHostAddress());
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return result;
    }
}
