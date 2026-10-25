package com.tvpower.app

import android.app.Activity
import android.app.AlertDialog
import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.view.Gravity
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import java.net.Inet4Address
import java.net.NetworkInterface

/**
 * 电视电源: 两个大按钮 (关机 / 重启), 均带确认弹窗。
 * 指令通过本机回环 ADB (127.0.0.1:5555) 以 shell 身份执行
 * reboot -p (彻底关机) / reboot (重启)。
 */
class MainActivity : Activity() {

    private lateinit var statusText: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val bg = Color.parseColor("#101418")
        val offColor = Color.parseColor("#E5484D")
        val rebootColor = Color.parseColor("#3E63DD")
        val textPrimary = Color.parseColor("#F5F7FA")
        val textMuted = Color.parseColor("#8B98A9")

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setBackgroundColor(bg)
            setPadding(56, 48, 56, 48)
        }

        val title = TextView(this).apply {
            text = "电视电源"
            textSize = 30f
            setTextColor(textPrimary)
            typeface = Typeface.DEFAULT_BOLD
            gravity = Gravity.CENTER
        }

        statusText = TextView(this).apply {
            text = "选择要执行的操作"
            textSize = 18f
            setTextColor(textMuted)
            gravity = Gravity.CENTER
            setPadding(0, 16, 0, 48)
        }

        val offBtn = makeButton("关  机", offColor)
        offBtn.setOnClickListener { confirm("关机", "reboot -p") }

        val rebootBtn = makeButton("重  启", rebootColor)
        rebootBtn.setOnClickListener { confirm("重启", "reboot") }

        val hint = TextView(this).apply {
            text = "首次使用会在电视上弹出“允许 USB 调试？”对话框，点“允许”即可（仅一次）"
            textSize = 14f
            setTextColor(textMuted)
            gravity = Gravity.CENTER
            setPadding(0, 48, 0, 0)
        }

        root.addView(title)
        root.addView(statusText)
        root.addView(offBtn)
        root.addView(
            rebootBtn,
            LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { topMargin = 28 }
        )
        root.addView(hint)
        setContentView(root)
    }

    private fun makeButton(text: String, color: Int): Button =
        Button(this).apply {
            this.text = text
            textSize = 26f
            setTextColor(Color.WHITE)
            typeface = Typeface.DEFAULT_BOLD
            setBackgroundColor(color)
            isAllCaps = false
            setPadding(32, 36, 32, 36)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }

    private fun confirm(label: String, cmd: String) {
        AlertDialog.Builder(this)
            .setTitle("确认$label")
            .setMessage("确定要$label 吗？")
            .setPositiveButton("确定") { _, _ -> runCommand(label, cmd) }
            .setNegativeButton("取消", null)
            .show()
    }

    private fun runCommand(label: String, cmd: String) {
        statusText.text = "连接中…"
        Thread {
            val hosts = ArrayList<String>()
            hosts.add("127.0.0.1")
            hosts.addAll(localIpCandidates())
            var lastError: Exception? = null
            for (h in hosts) {
                val client = AdbClient()
                try {
                    client.connect(h, 5555)
                    runOnUiThread { statusText.text = "已连接，正在$label…" }
                    client.shell(cmd)
                    runOnUiThread { statusText.text = "$label 指令已发送" }
                    return@Thread
                } catch (e: Exception) {
                    lastError = e
                    client.close()
                }
            }
            runOnUiThread {
                statusText.text = "失败：${lastError?.message ?: "无法连接本机 ADB"}"
            }
        }.start()
    }

    /** 回环不通时, 依次尝试本机 wlan/eth 地址 */
    private fun localIpCandidates(): List<String> = try {
        NetworkInterface.getNetworkInterfaces().toList()
            .filter { it.name.startsWith("wlan") || it.name.startsWith("eth") }
            .flatMap { it.inetAddresses.toList() }
            .filterIsInstance<Inet4Address>()
            .map { it.hostAddress }
            .filterNotNull()
            .distinct()
    } catch (_: Exception) {
        emptyList()
    }
}
