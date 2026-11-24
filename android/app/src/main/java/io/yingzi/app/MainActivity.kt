package io.yingzi.app

import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.fragment.app.Fragment
import com.google.android.material.bottomnavigation.BottomNavigationView

/**
 * 应用外壳：一个 Activity 承载 5 个 Tab（Fragment），底部导航栏只有这一个实例。
 *
 * 之前是 5 个 Activity 各带一份 BottomNavigationView，导致：
 *  - 切页时导航栏跟着重建（看起来"变来变去"）
 *  - 回来的页面高亮停在旧项（选中状态和内容不一致）
 *  - 再点那个"看起来已选中"的项时 Material 不回调，要多点几次
 *
 * 现在切页只是 show/hide Fragment，导航栏位置、状态、点击都稳定。
 * 只保留一个已选中的高亮，切换用 add/show + hide，不重建 Fragment（保留滚动位置/输入内容）。
 */
class MainActivity : AppCompatActivity() {

    private lateinit var nav: BottomNavigationView
    private var current = 0

    private val tabs = listOf(
        R.id.nav_status to StatusFragment::class.java,
        R.id.nav_nodes to NodesFragment::class.java,
        R.id.nav_stats to StatsFragment::class.java,
        R.id.nav_rules to RulesFragment::class.java,
        R.id.nav_log to LogFragment::class.java,
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        nav = findViewById(R.id.nav)

        // 先设初始选中，再挂监听，避免"程序设置选中"触发导航（旧实现的坑）
        nav.selectedItemId = R.id.nav_status
        current = R.id.nav_status
        showTab(R.id.nav_status)

        nav.setOnItemSelectedListener { item ->
            if (item.itemId != current) {
                current = item.itemId
                showTab(item.itemId)
            }
            true
        }

        // autostart 由 StatusFragment 自己在 onViewCreated 里处理
        // （此处 commit 是异步的，立刻 findFragmentByTag 会拿到 null）
    }

    /** 外部（如通知栏）拉起某个 Tab */
    fun switchTab(itemId: Int) {
        nav.selectedItemId = itemId
        if (itemId != current) {
            current = itemId
            showTab(itemId)
        }
    }

    private fun showTab(itemId: Int) {
        val tag = tagOf(itemId)
        val fm = supportFragmentManager
        val ft = fm.beginTransaction()
        for ((id, _) in tabs) {
            val t = tagOf(id)
            fm.findFragmentByTag(t)?.let { if (it.isAdded) ft.hide(it) }
        }
        val existing = fm.findFragmentByTag(tag)
        if (existing == null) {
            ft.add(R.id.container, newFragment(itemId), tag)
        } else {
            ft.show(existing)
        }
        ft.commit()
    }

    private fun tagOf(itemId: Int) = "tab_$itemId"

    private fun newFragment(itemId: Int): Fragment = when (itemId) {
        R.id.nav_nodes -> NodesFragment()
        R.id.nav_stats -> StatsFragment()
        R.id.nav_rules -> RulesFragment()
        R.id.nav_log -> LogFragment()
        else -> StatusFragment()
    }
}