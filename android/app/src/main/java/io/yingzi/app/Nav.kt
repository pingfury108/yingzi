package io.yingzi.app

import android.app.Activity
import android.content.Intent
import com.google.android.material.bottomnavigation.BottomNavigationView

/**
 * 底部导航：
 * - 「状态」清栈回主页
 * - 其余页面复用已有实例（不堆叠重复页面）
 * - 左上角「<」= 回退一步（finish）
 */
object Nav {

    fun bind(activity: Activity, nav: BottomNavigationView, current: Int) {
        nav.selectedItemId = current
        nav.setOnItemSelectedListener { item ->
            if (item.itemId == current) return@setOnItemSelectedListener true
            when (item.itemId) {
                R.id.nav_status -> home(activity)
                R.id.nav_nodes -> open(activity, NodesActivity::class.java)
                R.id.nav_rules -> open(activity, RulesActivity::class.java)
                R.id.nav_log -> open(activity, LogActivity::class.java)
            }
            true
        }
    }

    private fun home(activity: Activity) {
        activity.startActivity(
            Intent(activity, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        )
    }

    private fun open(activity: Activity, target: Class<*>) {
        activity.startActivity(
            Intent(activity, target).addFlags(Intent.FLAG_ACTIVITY_REORDER_TO_FRONT)
        )
    }
}
