package io.yingzi.app

import android.content.Context
import android.os.Build
import android.provider.Settings

/**
 * 默认节点名：取系统设备名（用户可改），回退到机型；
 * 末尾带 2 位设备指纹，避免两台同名手机在节点列表里混在一起。
 */
object DeviceName {

    fun suggest(ctx: Context): String {
        val raw = systemName(ctx) ?: Build.MODEL ?: "android"
        val clean = raw.trim()
            .replace(Regex("\\s+"), "-")
            .replace(Regex("[^\\p{L}\\p{N}._-]"), "")
            .take(20)
            .trim('-', '.', '_')
        val base = if (clean.isEmpty()) "android" else clean
        val id = try {
            Settings.Secure.getString(ctx.contentResolver, Settings.Secure.ANDROID_ID)
        } catch (e: Exception) {
            null
        }
        val suffix = if (!id.isNullOrEmpty() && id.length >= 4) id.takeLast(2).lowercase() else ""
        return if (suffix.isEmpty()) base else "$base-$suffix"
    }

    private fun systemName(ctx: Context): String? = try {
        Settings.Global.getString(ctx.contentResolver, Settings.Global.DEVICE_NAME)
            ?.takeIf { it.isNotBlank() }
    } catch (e: Exception) {
        null
    }
}
