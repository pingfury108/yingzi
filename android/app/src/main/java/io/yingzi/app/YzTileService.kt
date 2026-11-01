package io.yingzi.app

import android.content.Intent
import android.graphics.drawable.Icon
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService

/** 下拉快捷开关：一键连接/断开 */
class YzTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        refresh()
    }

    private fun refresh() {
        val tile = qsTile ?: return
        val on = YzCore.nativeIsRunning()
        tile.state = if (on) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.label = if (on) "yingzi 已连接" else "yingzi"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle = if (on) NodeConfig.load(this).defaultExit else "未连接"
        }
        tile.icon = Icon.createWithResource(this, R.drawable.ic_notif)
        tile.updateTile()
    }

    override fun onClick() {
        super.onClick()
        if (YzCore.nativeIsRunning()) {
            startService(
                Intent(this, YzVpnService::class.java).setAction(YzVpnService.ACTION_STOP)
            )
        } else {
            val prep = VpnService.prepare(this)
            if (prep != null) {
                startActivityAndCollapse(prep)
            } else {
                startService(
                    Intent(this, YzVpnService::class.java).setAction(YzVpnService.ACTION_START)
                )
            }
        }
        // 状态刷新延迟一点（服务启动/停止需要时间）
        android.os.Handler(mainLooper).postDelayed({ refresh() }, 1500)
    }
}
