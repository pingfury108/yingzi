package io.yingzi.app

import android.app.*
import android.content.Intent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.Network
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
        const val ACTION_RESTART = "io.yingzi.app.RESTART"
        const val ACTION_REBUILD = "io.yingzi.app.REBUILD"
    }

    private var tun: ParcelFileDescriptor? = null
    private var netCallback: ConnectivityManager.NetworkCallback? = null
    private var lastRestart = 0L
    private var firstNetCallback = true
    private var currentNetwork: Network? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopVpn()
                return START_NOT_STICKY
            }
            ACTION_RESTART -> {
                restartCore()
                return START_STICKY
            }
            ACTION_REBUILD -> {
                // 分应用模式变化必须重建 TUN（allowed/disallowed 只能建隧道时设定）
                teardown()
                startVpn()
                return START_STICKY
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

        // 分应用模式：allowed 与 disallowed 互斥，必须二选一
        val mode = AppRules.mode(this)
        val picked = AppRules.selected(this) - packageName
        if (mode == AppRules.INCLUDE && picked.isNotEmpty()) {
            // 仅代理选中应用：自身不在白名单内 → 自动绕过 VPN（不会套娃）
            var applied = 0
            for (pkg in picked) {
                try {
                    builder.addAllowedApplication(pkg)
                    applied++
                } catch (e: Exception) {
                    Log.w(TAG, "分应用设置失败 $pkg: $e")
                }
            }
            Log.i(TAG, "仅代理 $applied/${picked.size} 个应用")
            YzCore.nativePushEvent("INFO", "分应用：仅代理 $applied 个应用")
        } else {
            // 全局 / 排除模式：先排除自身，避免核心 socket 回环
            try {
                builder.addDisallowedApplication(packageName)
                Log.i(TAG, "addDisallowedApplication ok: $packageName")
            } catch (e: Exception) {
                Log.e(TAG, "addDisallowedApplication 失败: $e")
            }
            if (mode == AppRules.EXCLUDE && picked.isNotEmpty()) {
                var applied = 0
                for (pkg in picked) {
                    try {
                        builder.addDisallowedApplication(pkg)
                        applied++
                    } catch (e: Exception) {
                        Log.w(TAG, "分应用设置失败 $pkg: $e")
                    }
                }
                Log.i(TAG, "排除 $applied/${picked.size} 个应用")
                YzCore.nativePushEvent("INFO", "分应用：排除 $applied 个应用")
            }
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
            put("rules", org.json.JSONArray(Rules.load(this@YzVpnService)))
            put("tun_fd", pfd.fd)
            put("fake_ip", cfg.fakeIp)
            put("ipv6", cfg.ipv6)
            put("mtu", 1400)
        }

        registerNetworkCallback()
        val err = YzCore.nativeStart(config.toString(), this)
        if (err.isNotEmpty()) {
            Log.e(TAG, "nativeStart 失败: $err")
            stopVpn()
            return
        }
        updateNotification("已连接 · 出口 ${cfg.defaultExit}")
        YzCore.nativePushEvent("INFO", "隧道已建立 · 出口 ${cfg.defaultExit}")
    }

    /** 网络切换（WiFi↔4G）：重建核心，避免 UDP 端点失效后长时间不可用 */
    private fun registerNetworkCallback() {
        val cm = getSystemService(ConnectivityManager::class.java)
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                // 注册后的首个回调只是"当前网络"，不算切换
                if (firstNetCallback) {
                    firstNetCallback = false
                    currentNetwork = network
                    return
                }
                if (currentNetwork == network) return
                // 自己建立的 VPN 网络也会触发 onAvailable，忽略
                val caps = try {
                    getSystemService(ConnectivityManager::class.java).getNetworkCapabilities(network)
                } catch (e: Exception) {
                    null
                }
                if (caps?.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN) == true) return
                currentNetwork = network
                val now = System.currentTimeMillis()
                // 防抖: 10 秒内只重建一次
                if (now - lastRestart < 10_000) return
                lastRestart = now
                Log.i(TAG, "网络变化，重启核心")
                YzCore.nativePushEvent("WARN", "网络变化，正在重建核心")
                restartCore()
            }

            override fun onLost(network: Network) {
                if (currentNetwork == network) currentNetwork = null
            }
        }
        netCallback = cb
        try {
            cm.registerDefaultNetworkCallback(cb)
        } catch (e: Exception) {
            Log.w(TAG, "注册网络回调失败: $e")
        }
    }

    private fun restartCore() {
        val pfd = tun ?: return
        YzCore.nativeStop()
        val cfg = NodeConfig.load(this)
        val config = JSONObject().apply {
            put("network_secret", cfg.networkSecret)
            put("identity_file", File(filesDir, "node.key").absolutePath)
            put("coordinator", cfg.coordinator)
            put("name", cfg.name)
            put("default_exit", cfg.defaultExit)
            put("remote_dns", cfg.remoteDns)
            put("direct_dns", cfg.directDns)
            put("geoip", NodeConfig.geoipPath(this@YzVpnService))
            put("geosite", NodeConfig.geositePath(this@YzVpnService))
            put("rules", org.json.JSONArray(Rules.load(this@YzVpnService)))
            put("tun_fd", pfd.fd)
            put("fake_ip", cfg.fakeIp)
            put("ipv6", cfg.ipv6)
            put("mtu", 1400)
        }
        val err = YzCore.nativeStart(config.toString(), this)
        if (err.isNotEmpty()) Log.e(TAG, "重启核心失败: $err")
    }

    /** 拆除 TUN + 核心（不结束服务） */
    private fun teardown() {
        if (tun != null) YzCore.nativePushEvent("INFO", "隧道已断开")
        netCallback?.let {
            try { getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(it) } catch (_: Exception) {}
        }
        netCallback = null
        YzCore.nativeStop()
        try { tun?.close() } catch (_: Exception) {}
        tun = null
    }

    private fun stopVpn() {
        teardown()
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
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        val stop = PendingIntent.getService(
            this, 1,
            Intent(this, YzVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE
        )
        return androidx.core.app.NotificationCompat.Builder(this, CHANNEL)
            .setContentTitle("yingzi")
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_notif)
            .setContentIntent(open)
            .setOngoing(true)
            .setPriority(androidx.core.app.NotificationCompat.PRIORITY_LOW)
            .addAction(R.drawable.ic_power, "断开", stop)
            .addAction(R.drawable.ic_globe, "打开", open)
            .build()
    }

    private fun updateNotification(text: String) {
        getSystemService(NotificationManager::class.java)
            .notify(NOTIF_ID, buildNotification(text))
    }
}
