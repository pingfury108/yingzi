package io.yingzi.app

import android.content.Context
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * 规则数据（geoip.dat / geosite.dat）
 * 优先用下载版（files/geo/），没有则回退到 APK 内置 assets。
 */
object GeoData {
    private const val BASE =
        "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download"

    fun dir(ctx: Context): File = File(ctx.filesDir, "geo").apply { mkdirs() }

    fun geoip(ctx: Context): String = pick(ctx, "geoip.dat")
    fun geosite(ctx: Context): String = pick(ctx, "geosite.dat")

    private fun pick(ctx: Context, name: String): String {
        val downloaded = File(dir(ctx), name)
        if (downloaded.exists() && downloaded.length() > 1024 * 512) return downloaded.absolutePath
        return assetToFile(ctx, name)
    }

    private fun assetToFile(ctx: Context, name: String): String {
        val out = File(ctx.filesDir, name)
        if (out.exists() && out.length() > 0) return out.absolutePath
        return try {
            ctx.assets.open(name).use { input ->
                out.outputStream().use { output -> input.copyTo(output) }
            }
            out.absolutePath
        } catch (e: Exception) {
            ""
        }
    }

    /** 已下载数据的描述（没有则说明用内置/缺失） */
    fun info(ctx: Context): String {
        val ip = File(dir(ctx), "geoip.dat")
        val site = File(dir(ctx), "geosite.dat")
        if (!ip.exists() || !site.exists()) {
            val builtin = File(ctx.filesDir, "geosite.dat")
            return if (builtin.exists()) "内置数据 · 点按可更新" else "未安装 · 点按下载"
        }
        val mb = (ip.length() + site.length()) / 1048576.0
        val date = SimpleDateFormat("MM-dd HH:mm", Locale.getDefault())
            .format(Date(ip.lastModified()))
        return String.format("%.1f MB · %s", mb, date)
    }

    /** 后台下载两份数据；回调在主线程 */
    fun update(ctx: Context, onDone: (String) -> Unit) {
        Thread {
            val result = try {
                val d = dir(ctx)
                for (name in listOf("geoip.dat", "geosite.dat")) {
                    val tmp = File(d, "$name.tmp")
                    download("$BASE/$name", tmp)
                    if (tmp.length() < 1024 * 512) throw IllegalStateException("$name 数据异常")
                    val dst = File(d, name)
                    if (dst.exists()) dst.delete()
                    if (!tmp.renameTo(dst)) throw IllegalStateException("$name 写入失败")
                }
                "更新完成"
            } catch (e: Exception) {
                "更新失败: ${e.message}"
            }
            android.os.Handler(android.os.Looper.getMainLooper()).post { onDone(result) }
        }.start()
    }

    private fun download(url: String, out: File) {
        val conn = (URL(url).openConnection() as HttpURLConnection).apply {
            connectTimeout = 15000
            readTimeout = 60000
            instanceFollowRedirects = true
            setRequestProperty("User-Agent", "yingzi-android")
        }
        try {
            if (conn.responseCode !in 200..299) error("HTTP ${conn.responseCode}")
            conn.inputStream.use { input ->
                out.outputStream().use { output -> input.copyTo(output, 64 * 1024) }
            }
        } finally {
            conn.disconnect()
        }
    }
}
