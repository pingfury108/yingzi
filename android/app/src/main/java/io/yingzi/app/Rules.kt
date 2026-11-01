package io.yingzi.app

import android.content.Context
import org.json.JSONArray

/** 分流规则（持久化在 SharedPreferences，热更新到核心） */
object Rules {
    private const val KEY = "rules"

    val PRESETS = linkedMapOf(
        "广告拦截" to "geosite:category-ads-all=block",
        "国内直连" to "geosite:cn=direct",
        "国内 IP 直连" to "geoip:cn=direct",
        "内网直连" to "geoip:private=direct",
        "苹果服务直连" to "geosite:apple-cn=direct",
        "Google 走出口" to "geosite:google=exit",
        "Telegram 走出口" to "geosite:telegram=exit",
    )

    fun load(ctx: Context): MutableList<String> {
        val raw = ctx.getSharedPreferences("yz", Context.MODE_PRIVATE).getString(KEY, null)
        if (raw != null) {
            return try {
                val arr = JSONArray(raw)
                MutableList(arr.length()) { arr.getString(it) }
            } catch (_: Exception) {
                default().toMutableList()
            }
        }
        return default().toMutableList()
    }

    fun save(ctx: Context, list: List<String>) {
        ctx.getSharedPreferences("yz", Context.MODE_PRIVATE).edit()
            .putString(KEY, JSONArray(list).toString()).apply()
    }

    fun default(): List<String> = listOf(
        "geosite:category-ads-all=block",
        "geosite:cn=direct",
        "geoip:cn=direct",
        "geoip:private=direct",
    )
}
