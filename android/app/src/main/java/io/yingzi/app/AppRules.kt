package io.yingzi.app

import android.content.Context
import android.content.pm.PackageManager

/**
 * 分应用代理：
 * - GLOBAL  全局代理（默认）
 * - INCLUDE 仅代理选中应用
 * - EXCLUDE 选中应用直连（其余代理）
 */
object AppRules {
    const val GLOBAL = 0
    const val INCLUDE = 1
    const val EXCLUDE = 2

    fun mode(ctx: Context): Int =
        ctx.getSharedPreferences("yz", Context.MODE_PRIVATE).getInt("app_mode", GLOBAL)

    fun setMode(ctx: Context, mode: Int) {
        ctx.getSharedPreferences("yz", Context.MODE_PRIVATE).edit().putInt("app_mode", mode).apply()
    }

    fun selected(ctx: Context): MutableSet<String> {
        val raw = ctx.getSharedPreferences("yz", Context.MODE_PRIVATE)
            .getStringSet("app_list", emptySet()) ?: emptySet()
        return raw.toMutableSet()
    }

    fun setSelected(ctx: Context, pkgs: Set<String>) {
        ctx.getSharedPreferences("yz", Context.MODE_PRIVATE).edit()
            .putStringSet("app_list", pkgs).apply()
    }

    /** 已安装的可启动应用（含自身，便于排除） */
    fun installed(ctx: Context): List<AppEntry> {
        val pm = ctx.packageManager
        val intent = android.content.Intent(android.content.Intent.ACTION_MAIN)
            .addCategory(android.content.Intent.CATEGORY_LAUNCHER)
        return pm.queryIntentActivities(intent, 0)
            .mapNotNull { ri ->
                val pkg = ri.activityInfo?.packageName ?: return@mapNotNull null
                val label = ri.loadLabel(pm).toString()
                AppEntry(pkg, label)
            }
            .distinctBy { it.pkg }
            .sortedBy { it.label.lowercase() }
    }

    fun labelOf(ctx: Context, pkg: String): String = try {
        val pm = ctx.packageManager
        pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString()
    } catch (e: Exception) {
        pkg
    }
}

data class AppEntry(val pkg: String, val label: String)
