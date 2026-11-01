package io.yingzi.app

import android.app.*
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import org.json.JSONObject
import java.io.File

/**
 * VpnService：建立 TUN（全流量 + DNS），把 fd 交给 Rust 核心。
 * 核心负责分流决策与出口选择。
 */
class YzVpnService : VpnService() {

    companion object {
        private const val TAG = "YzVpn"
        private const val CHANNEL = "yz_vpn"
        private const val NOTIF_ID = 1001
        const val ACTION_START = "io.yingzi.app.START"
        const val ACTION_STOP = "io.yingzi.app.STOP"
    }

    private var tun: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopVpn()
                return START_NOT_STICKY
            }
            else -> startVpn()
        }
        return START_STICKY
    }

    private fun startVpn() {
        if (tun != null) return
        createNotificationChannel()
        startForeground(NOTIF_ID, buildNotification("正在连接…"))

        val cfg = NodeConfig.load(this)

        // 全流量 + DNS 进 TUN；核心按规则决定直连/出口
        val builder = Builder()
            .setSession("yingzi")
            .setMtu(1400)
            .addAddress("10.99.0.1", 24)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("223.5.5.5")

        // 排除自身（避免核心的 socket 回环）—— 关键
        try {
            builder.addDisallowedApplication(packageName)
            Log.i(TAG, "addDisallowedApplication ok: $packageName")
        } catch (e: Exception) {
            Log.e(TAG, "addDisallowedApplication 失败: $e")
        }

        val pfd = builder.establish() ?: run {
            Log.e(TAG, "establish() 失败")
            stopSelf()
            return
        }
        tun = pfd

        val idFile = File(filesDir, "node.key").absolutePath
        val config = JSONObject().apply {
            put("network_secret", cfg.networkSecret)
            put("identity_file", idFile)
            put("coordinator", cfg.coordinator)
            put("name", cfg.name)
            put("default_exit", cfg.defaultExit)
            put("remote_dns", cfg.remoteDns)
            put("direct_dns", cfg.directDns)
            put("geoip", NodeConfig.geoipPath(this@YzVpnService))
            put("geosite", NodeConfig.geositePath(this@YzVpnService))
            put("rules", org.json.JSONArray(NodeConfig.rules()))
            put("tun_fd", pfd.fd)
            put("mtu", 1400)
        }

        val err = YzCore.nativeStart(config.toString(), this)
        if (err.isNotEmpty()) {
            Log.e(TAG, "nativeStart 失败: $err")
            stopVpn()
            return
        }
        updateNotification("已连接 · 出口 ${cfg.defaultExit}")
    }

    private fun stopVpn() {
        YzCore.nativeStop()
        try { tun?.close() } catch (_: Exception) {}
        tun = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val ch = NotificationChannel(
                CHANNEL, "yingzi", NotificationManager.IMPORTANCE_LOW
            )
            getSystemService(NotificationManager::class.java).createNotificationChannel(ch)
        }
    }

    private fun buildNotification(text: String): Notification {
        val pi = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        return Notification.Builder(this, CHANNEL)
            .setContentTitle("yingzi")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_menu_compass)
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(text: String) {
        getSystemService(NotificationManager::class.java)
            .notify(NOTIF_ID, buildNotification(text))
    }
}
