# tvpower — 电视电源按钮

给 Android TV 加一个真正的「关机 / 重启」按钮。

系统原生关机对话框 (`ShutdownActivity`) 需要 signature 级
`android.permission.SHUTDOWN`，shell 与第三方 App 均被拒绝；
本 App 通过**本机回环 ADB**（`127.0.0.1:5555`）以 shell 身份执行
`reboot -p`（彻底关机）/ `reboot`（重启）——该链路已在
索尼 KD-55X8500G（Android 10, BRAVIA UR2）实测有效。

- 首次使用：电视上弹「允许 USB 调试？」→ 点允许（仅一次）
- 密钥对存放于 AndroidKeyStore，不落盘明文
- 无任何系统修改、无 root，卸载即还原

## 构建

推送即自动构建（GitHub Actions），APK 在 Actions artifact
`tvpower-apk` 中下载。本地构建：

```bash
gradle assembleDebug
# 产物: app/build/outputs/apk/debug/app-debug.apk
```

## 安装

```bash
adb install app-debug.apk
```

装后图标出现在电视应用列表中（LAUNCHER + LEANBACK_LAUNCHER）。
