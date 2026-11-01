package io.yingzi.app

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import org.json.JSONObject

class MainActivity : AppCompatActivity() {

    private lateinit var toggle: Button
    private lateinit var subtitle: TextView
    private lateinit var stats: TextView
    private lateinit var nodes: TextView
    private lateinit var logs: TextView
    private val handler = Handler(Looper.getMainLooper())
    private val vpnPerm = 1001

    private val tick = object : Runnable {
        override fun run() {
            refresh()
            handler.postDelayed(this, 1500)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        toggle = findViewById(R.id.toggle)
        subtitle = findViewById(R.id.subtitle)
        stats = findViewById(R.id.stats)
        nodes = findViewById(R.id.nodes)
        logs = findViewById(R.id.logs)

        findViewById<Button>(R.id.settings).setOnClickListener {
            startActivity(Intent(this, SettingsActivity::class.java))
        }

        toggle.setOnClickListener {
            if (YzCore.nativeIsRunning()) stop() else start()
        }

        // 支持 adb / 快捷方式直接启动: --ez autostart true
        if (intent?.getBooleanExtra("autostart", false) == true) start()
    }

    private fun start() {
        val prep = VpnService.prepare(this)
        if (prep != null) {
            startActivityForResult(prep, vpnPerm)
        } else {
            launchVpn()
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == vpnPerm && resultCode == RESULT_OK) launchVpn()
    }

    private fun launchVpn() {
        val i = Intent(this, YzVpnService::class.java).setAction(YzVpnService.ACTION_START)
        startForegroundService(i)
    }

    private fun stop() {
        val i = Intent(this, YzVpnService::class.java).setAction(YzVpnService.ACTION_STOP)
        startService(i)
    }

    private fun refresh() {
        val running = YzCore.nativeIsRunning()
        toggle.text = if (running) "停止" else "启动"
        subtitle.text = if (running) "运行中" else "未连接"
        if (!running) {
            stats.text = ""
            nodes.text = ""
            return
        }
        try {
            val s = JSONObject(YzCore.nativeStatus())
            stats.text = buildString {
                appendLine("peers: ${s.optInt("peers")}")
                appendLine("流量: ↓${fmt(s.optLong("rx_bytes"))} ↑${fmt(s.optLong("tx_bytes"))}")
                appendLine("TCP: direct=${s.optLong("tcp_direct")} exit=${s.optLong("tcp_exit")} block=${s.optLong("tcp_blocked")}")
                appendLine("UDP: direct=${s.optLong("udp_direct")} exit=${s.optLong("udp_exit")} dns=${s.optLong("udp_dns")}")
                appendLine("DNS: remote=${s.optLong("dns_remote")} direct=${s.optLong("dns_direct")} block=${s.optLong("dns_blocked")}")
            }
            logs.text = YzCore.nativeEvents()
        } catch (e: Exception) {
            stats.text = "状态读取失败: $e"
        }
    }

    private fun fmt(b: Long): String = when {
        b > 1 shl 30 -> "%.1fG".format(b / 1073741824.0)
        b > 1 shl 20 -> "%.1fM".format(b / 1048576.0)
        b > 1 shl 10 -> "%.1fK".format(b / 1024.0)
        else -> "${b}B"
    }

    override fun onResume() {
        super.onResume()
        handler.post(tick)
    }

    override fun onPause() {
        super.onPause()
        handler.removeCallbacks(tick)
    }
}
