package com.tvpower.app

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.RSAPublicKey
import java.util.zip.CRC32

/**
 * 最小 ADB 协议客户端 (仅实现连接所需子集):
 *   TCP -> CNXN 握手 -> AUTH (RSA 签名 / 公钥注册) -> OPEN "shell:<cmd>"
 *
 * 密钥对存放于 AndroidKeyStore (别名 tvpower-adb-key), 首次连接时
 * 电视端会弹出 "允许 USB 调试?" 授权框, 用户点允许后进入 CNXN。
 */
class AdbClient {

    companion object {
        private const val A_CNXN = 0x4e584e43 // "CNXN"
        private const val A_AUTH = 0x48545541 // "AUTH"
        private const val A_OPEN = 0x4e504f4f // "OPEN"
        private const val A_OKAY = 0x59414b4f // "OKAY"
        private const val A_CLSE = 0x45534c43 // "CLSE"
        private const val A_WRTE = 0x45545257 // "WRTE"
        private const val AUTH_TOKEN = 1
        private const val AUTH_SIGNATURE = 2
        private const val AUTH_RSAPUBLICKEY = 3
        private const val A_VERSION = 0x01000000
        private const val MAX_PAYLOAD = 4096
        private const val KEY_ALIAS = "tvpower-adb-key"
        private const val BANNER = "host::features=shell_v2"
    }

    private class AdbMessage(val cmd: Int, val arg0: Int, val arg1: Int, val data: ByteArray)

    private var socket: Socket? = null
    private var out: DataOutputStream? = null
    private var input: DataInputStream? = null
    private var privateKey: PrivateKey? = null
    private var publicKeyDer: ByteArray? = null

    /**
     * 连接并完成认证。authTimeoutMs 需足够长 (等待用户在电视上点"允许")。
     */
    @Throws(Exception::class)
    fun connect(host: String, port: Int, connectTimeoutMs: Int = 10000, authTimeoutMs: Int = 120000) {
        close()
        ensureKeys()

        val s = Socket()
        s.connect(InetSocketAddress(host, port), connectTimeoutMs)
        s.tcpNoDelay = true
        s.soTimeout = authTimeoutMs
        socket = s
        out = DataOutputStream(s.getOutputStream())
        input = DataInputStream(s.getInputStream())

        writeMessage(A_CNXN, A_VERSION, MAX_PAYLOAD, BANNER.toByteArray(Charsets.UTF_8))

        while (true) {
            val msg = readMessage() ?: throw Exception("连接中断 (认证阶段)")
            when (msg.cmd) {
                A_CNXN -> return // 认证通过
                A_AUTH -> {
                    if (msg.arg0 == AUTH_TOKEN) {
                        val sig = signToken(msg.data)
                        if (sig != null) {
                            writeMessage(A_AUTH, AUTH_SIGNATURE, 0, sig)
                        } else {
                            val pk = publicKeyDer!!
                            val buf = ByteArray(pk.size + 1) // DER + '\0'
                            System.arraycopy(pk, 0, buf, 0, pk.size)
                            writeMessage(A_AUTH, AUTH_RSAPUBLICKEY, 0, buf)
                        }
                    }
                }
                else -> throw Exception("意外协议响应: 0x${Integer.toHexString(msg.cmd)}")
            }
        }
    }

    /**
     * 打开一个 shell 流执行命令。命令发出即返回 (不等输出),
     * 对 reboot / reboot -p 足够: 指令送达后设备就会重启或断电。
     */
    @Throws(Exception::class)
    fun shell(command: String, waitMs: Long = 8000) {
        writeMessage(A_OPEN, 1, 0, "shell:$command".toByteArray(Charsets.UTF_8))
        val start = System.currentTimeMillis()
        while (System.currentTimeMillis() - start < waitMs) {
            val msg = readMessage() ?: return // 设备已重启/断电, 流断开
            if (msg.cmd == A_OKAY || msg.cmd == A_CLSE) return
        }
    }

    fun close() {
        try { socket?.close() } catch (_: Exception) {}
        socket = null
        out = null
        input = null
    }

    // ---------------- 内部实现 ----------------

    private fun ensureKeys() {
        val ks = KeyStore.getInstance("AndroidKeyStore")
        ks.load(null)
        if (!ks.containsAlias(KEY_ALIAS)) {
            val spec = KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setKeySize(2048)
                .setDigests(KeyProperties.DIGEST_SHA1) // adbd 校验用 SHA1withRSA
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                .build()
            val kpg = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore")
            kpg.initialize(spec)
            kpg.generateKeyPair()
        }
        val ks2 = KeyStore.getInstance("AndroidKeyStore")
        ks2.load(null)
        val entry = ks2.getEntry(KEY_ALIAS, null) as KeyStore.PrivateKeyEntry
        privateKey = entry.privateKey
        publicKeyDer = (entry.certificate.publicKey as RSAPublicKey).encoded // X.509 SPKI DER
    }

    private fun signToken(token: ByteArray): ByteArray? = try {
        val sig = Signature.getInstance("SHA1withRSA")
        sig.initSign(privateKey)
        sig.update(token)
        sig.sign()
    } catch (_: Exception) {
        null
    }

    private fun writeMessage(cmd: Int, arg0: Int, arg1: Int, data: ByteArray) {
        val crc = CRC32().apply { update(data) }.value.toInt()
        val bb = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN)
        bb.putInt(cmd)
        bb.putInt(arg0)
        bb.putInt(arg1)
        bb.putInt(data.size)
        bb.putInt(crc)
        bb.putInt(cmd.inv()) // magic = command 取反
        val o = out!!
        o.write(bb.array())
        if (data.isNotEmpty()) o.write(data)
        o.flush()
    }

    private fun readMessage(): AdbMessage? {
        val inp = input ?: return null
        val header = readFully(inp, 24) ?: return null
        val bb = ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN)
        val cmd = bb.int
        val arg0 = bb.int
        val arg1 = bb.int
        val len = bb.int
        // bb.int  // data_check (crc) — 不校验
        // bb.int  // magic — 不校验
        if (len < 0 || len > 1024 * 1024) throw Exception("非法数据长度: $len")
        val data = if (len > 0) readFully(inp, len) ?: return null else ByteArray(0)
        return AdbMessage(cmd, arg0, arg1, data)
    }

    private fun readFully(inp: DataInputStream, n: Int): ByteArray? {
        val buf = ByteArray(n)
        var read = 0
        while (read < n) {
            val r = inp.read(buf, read, n - read)
            if (r < 0) return null
            read += r
        }
        return buf
    }
}
