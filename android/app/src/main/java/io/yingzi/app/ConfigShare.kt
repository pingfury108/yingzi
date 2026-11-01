package io.yingzi.app

import android.content.Context
import android.graphics.Bitmap
import android.graphics.Color
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import org.json.JSONObject
import java.util.Base64

/**
 * 配置分享：yz://<base64(json)> —— 二维码或剪贴板文本
 * 注意：载荷包含网络密钥，等同入网凭证，请只分享给自己信任的设备。
 */
object ConfigShare {

    fun encode(cfg: NodeConfig): String {
        val json = JSONObject().apply {
            put("v", 1)
            put("ns", cfg.networkSecret)
            put("co", cfg.coordinator)
            put("name", cfg.name)
            put("exit", cfg.defaultExit)
            put("rdns", cfg.remoteDns)
            put("ddns", cfg.directDns)
            put("fakeip", cfg.fakeIp)
        }.toString()
        return "yz://" + Base64.getEncoder().encodeToString(json.toByteArray())
    }

    /** 解析并落盘；返回错误信息（成功返回 null） */
    fun import(ctx: Context, text: String): String? {
        val payload = text.trim().removePrefix("yz://")
        val json = try {
            JSONObject(String(Base64.getDecoder().decode(payload)))
        } catch (e: Exception) {
            return "不是有效的 yingzi 配置"
        }
        val ns = json.optString("ns")
        if (ns.length != 64) return "网络密钥无效"
        val cfg = NodeConfig.load(ctx)
        NodeConfig.save(
            ctx,
            secret = ns,
            coordinator = json.optString("co", cfg.coordinator),
            name = json.optString("name", cfg.name),
            exit = json.optString("exit", cfg.defaultExit),
            remoteDns = json.optString("rdns", cfg.remoteDns),
            directDns = json.optString("ddns", cfg.directDns),
            fakeIp = json.optBoolean("fakeip", cfg.fakeIp),
        )
        return null
    }

    /** 生成二维码位图 */
    fun qr(content: String, size: Int = 640): Bitmap? = try {
        val hints = mapOf(
            EncodeHintType.MARGIN to 1,
            EncodeHintType.CHARACTER_SET to "UTF-8",
        )
        val matrix = QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, size, size, hints)
        val bmp = Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888)
        for (x in 0 until size) {
            for (y in 0 until size) {
                bmp.setPixel(x, y, if (matrix[x, y]) Color.BLACK else Color.WHITE)
            }
        }
        bmp
    } catch (e: Exception) {
        null
    }
}
