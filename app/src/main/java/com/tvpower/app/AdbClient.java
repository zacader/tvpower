package com.tvpower.app;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.util.zip.CRC32;

/**
 * 最小 ADB 协议客户端 (仅实现关机所需子集):
 *   TCP -> CNXN 握手 -> AUTH (RSA 签名 / 公钥注册) -> OPEN "shell:reboot -p"
 *
 * 密钥对存放于 AndroidKeyStore (别名 tvpower-adb-key)。首次连接时电视端
 * 弹出 "允许 USB 调试?" 授权框, 用户点允许后进入 CNXN。
 */
public class AdbClient {

    private static final int A_CNXN = 0x4e584e43; // "CNXN"
    private static final int A_AUTH = 0x48545541; // "AUTH"
    private static final int A_OPEN = 0x4e504f4f; // "OPEN"
    private static final int A_OKAY = 0x59414b4f; // "OKAY"
    private static final int A_CLSE = 0x45534c43; // "CLSE"
    private static final int A_WRTE = 0x45545257; // "WRTE"
    private static final int AUTH_TOKEN = 1;
    private static final int AUTH_SIGNATURE = 2;
    private static final int AUTH_RSAPUBLICKEY = 3;
    private static final int A_VERSION = 0x01000000;
    private static final int MAX_PAYLOAD = 4096;
    private static final String KEY_ALIAS = "tvpower-adb-key";
    private static final String BANNER = "host::features=shell_v2";

    private static class AdbMessage {
        final int cmd, arg0, arg1;
        final byte[] data;

        AdbMessage(int cmd, int arg0, int arg1, byte[] data) {
            this.cmd = cmd;
            this.arg0 = arg0;
            this.arg1 = arg1;
            this.data = data;
        }
    }

    private Socket socket;
    private DataOutputStream out;
    private DataInputStream input;
    private PrivateKey privateKey;
    private byte[] publicKeyDer;

    /**
     * 连接并完成认证。authTimeoutMs 需足够长 (等待用户在电视上点"允许")。
     */
    public void connect(String host, int port, int connectTimeoutMs, int authTimeoutMs) throws Exception {
        close();
        ensureKeys();

        Socket s = new Socket();
        s.connect(new InetSocketAddress(host, port), connectTimeoutMs);
        s.setTcpNoDelay(true);
        s.setSoTimeout(authTimeoutMs);
        socket = s;
        out = new DataOutputStream(s.getOutputStream());
        input = new DataInputStream(s.getInputStream());

        writeMessage(A_CNXN, A_VERSION, MAX_PAYLOAD, BANNER.getBytes("UTF-8"));

        while (true) {
            AdbMessage msg = readMessage();
            if (msg == null) throw new Exception("连接中断(认证阶段)");
            if (msg.cmd == A_CNXN) return; // 认证通过
            if (msg.cmd == A_AUTH && msg.arg0 == AUTH_TOKEN) {
                byte[] sig = signToken(msg.data);
                if (sig != null) {
                    writeMessage(A_AUTH, AUTH_SIGNATURE, 0, sig);
                } else {
                    byte[] buf = new byte[publicKeyDer.length + 1]; // DER + '\0'
                    System.arraycopy(publicKeyDer, 0, buf, 0, publicKeyDer.length);
                    writeMessage(A_AUTH, AUTH_RSAPUBLICKEY, 0, buf);
                }
            } else {
                throw new Exception("意外协议响应");
            }
        }
    }

    /**
     * 打开 shell 流执行命令, 发出即返回 (reboot -p 送达后设备即断电)。
     */
    public void shell(String command, long waitMs) throws Exception {
        writeMessage(A_OPEN, 1, 0, ("shell:" + command).getBytes("UTF-8"));
        long start = System.currentTimeMillis();
        while (System.currentTimeMillis() - start < waitMs) {
            AdbMessage msg = readMessage();
            if (msg == null) return; // 设备已重启/断电, 流断开
            if (msg.cmd == A_OKAY || msg.cmd == A_CLSE) return;
        }
    }

    public void close() {
        try {
            if (socket != null) socket.close();
        } catch (Exception ignored) {
        }
        socket = null;
        out = null;
        input = null;
    }

    // ---------------- 内部实现 ----------------

    private void ensureKeys() throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        if (!ks.containsAlias(KEY_ALIAS)) {
            KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setKeySize(2048)
                    .setDigests(KeyProperties.DIGEST_SHA1) // adbd 校验用 SHA1withRSA
                    .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                    .build();
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
            kpg.initialize(spec);
            kpg.generateKeyPair();
        }
        KeyStore ks2 = KeyStore.getInstance("AndroidKeyStore");
        ks2.load(null);
        KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) ks2.getEntry(KEY_ALIAS, null);
        privateKey = entry.getPrivateKey();
        publicKeyDer = ((RSAPublicKey) entry.getCertificate().getPublicKey()).getEncoded(); // X.509 SPKI DER
    }

    private byte[] signToken(byte[] token) {
        try {
            Signature sig = Signature.getInstance("SHA1withRSA");
            sig.initSign(privateKey);
            sig.update(token);
            return sig.sign();
        } catch (Exception e) {
            return null;
        }
    }

    private void writeMessage(int cmd, int arg0, int arg1, byte[] data) throws Exception {
        CRC32 crc32 = new CRC32();
        crc32.update(data);
        int crc = (int) crc32.getValue();
        ByteBuffer bb = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        bb.putInt(cmd);
        bb.putInt(arg0);
        bb.putInt(arg1);
        bb.putInt(data.length);
        bb.putInt(crc);
        bb.putInt(~cmd); // magic = command 取反
        DataOutputStream o = out;
        o.write(bb.array());
        if (data.length > 0) o.write(data);
        o.flush();
    }

    private AdbMessage readMessage() throws Exception {
        DataInputStream inp = input;
        if (inp == null) return null;
        byte[] header = readFully(inp, 24);
        if (header == null) return null;
        ByteBuffer bb = ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN);
        int cmd = bb.getInt();
        int arg0 = bb.getInt();
        int arg1 = bb.getInt();
        int len = bb.getInt();
        // bb.getInt(); // data_check (crc) — 不校验
        // bb.getInt(); // magic — 不校验
        if (len < 0 || len > 1024 * 1024) throw new Exception("非法数据长度: " + len);
        byte[] data = new byte[0];
        if (len > 0) {
            data = readFully(inp, len);
            if (data == null) return null;
        }
        return new AdbMessage(cmd, arg0, arg1, data);
    }

    private byte[] readFully(DataInputStream in, int n) throws Exception {
        byte[] buf = new byte[n];
        int read = 0;
        while (read < n) {
            int r = in.read(buf, read, n - read);
            if (r < 0) return null;
            read += r;
        }
        return buf;
    }
}
