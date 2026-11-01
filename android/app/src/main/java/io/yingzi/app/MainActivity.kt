package io.yingzi.app

import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.button.MaterialButton
import org.json.JSONObject
import kotlin.math.roundToInt

class MainActivity : AppCompatActivity() {

    private lateinit var ring: RingView
    private lateinit var spark: SparkView
    private lateinit var statePill: TextView
    private lateinit var exitLine: TextView
    private lateinit var upValue: TextView
    private lateinit var peersValue: TextView
    private lateinit var uptimeValue: TextView
    private lateinit var toggle: MaterialButton
    private lateinit var exitChips: LinearLayout
    private lateinit var directCount: TextView
    private lateinit var exitCount: TextView
    private lateinit var blockCount: TextView

    private val handler = Handler(Looper.getMainLooper())
    private val vpnPerm = 1001

    private var lastRx = 0L
    private var lastTx = 0L
    private var lastAt = 0L
    private var chipsBuilt = false

    private val tick = object : Runnable {
        override fun run() {
            refresh()
            handler.postDelayed(this, 1200)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        ring = findViewById(R.id.ring)
        spark = findViewById(R.id.spark)
        statePill = findViewById(R.id.statePill)
        exitLine = findViewById(R.id.exitLine)
        upValue = findViewById(R.id.upValue)
        peersValue = findViewById(R.id.peersValue)
        uptimeValue = findViewById(R.id.uptimeValue)
        toggle = findViewById(R.id.toggle)
        exitChips = findViewById(R.id.exitChips)
        directCount = findViewById(R.id.directCount)
        exitCount = findViewById(R.id.exitCount)
        blockCount = findViewById(R.id.blockCount)

        findViewById<ImageButton>(R.id.settingsBtn).setOnClickListener {
            startActivity(Intent(this, SettingsActivity::class.java))
        }

        toggle.setOnClickListener {
            if (YzCore.nativeIsRunning()) stop() else start()
        }

        findViewById<com.google.android.material.bottomnavigation.BottomNavigationView>(R.id.nav)
            .setOnItemSelectedListener { item ->
                when (item.itemId) {
                    R.id.nav_nodes -> startActivity(Intent(this, NodesActivity::class.java))
                    R.id.nav_rules -> startActivity(Intent(this, RulesActivity::class.java))
                    R.id.nav_log -> startActivity(Intent(this, LogActivity::class.java))
                }
                true
            }
        findViewById<com.google.android.material.bottomnavigation.BottomNavigationView>(R.id.nav)
            .selectedItemId = R.id.nav_status

        if (intent?.getBooleanExtra("autostart", false) == true) start()
    }

    // ---------- 连接控制 ----------
    private fun start() {
        val prep = VpnService.prepare(this)
        if (prep != null) startActivityForResult(prep, vpnPerm) else launchVpn()
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == vpnPerm && resultCode == RESULT_OK) launchVpn()
    }

    private fun launchVpn() {
        startForegroundService(
            Intent(this, YzVpnService::class.java).setAction(YzVpnService.ACTION_START)
        )
    }

    private fun stop() {
        startService(Intent(this, YzVpnService::class.java).setAction(YzVpnService.ACTION_STOP))
    }

    private fun switchExit(name: String) {
        val cfg = NodeConfig.load(this)
        NodeConfig.save(
            this, cfg.networkSecret, cfg.coordinator, cfg.name, name,
            cfg.remoteDns, cfg.directDns,
        )
        if (YzCore.nativeIsRunning()) {
            YzCore.nativePushEvent("INFO", "出口切换到 $name")
            startService(
                Intent(this, YzVpnService::class.java).setAction(YzVpnService.ACTION_RESTART)
            )
        }
        chipsBuilt = false
        refresh()
    }

    // ---------- 状态刷新 ----------
    private fun refresh() {
        val running = YzCore.nativeIsRunning()
        applyState(running)
        if (!running) return

        val s = try {
            JSONObject(YzCore.nativeStatus())
        } catch (e: Exception) {
            return
        }

        // 速率（字节差 → MB/s）
        val now = System.currentTimeMillis()
        val rx = s.optLong("rx_bytes")
        val tx = s.optLong("tx_bytes")
        if (lastAt > 0 && now > lastAt) {
            val dt = (now - lastAt) / 1000.0
            val downMB = (rx - lastRx) / dt / 1048576.0
            val upKB = (tx - lastTx) / dt / 1024.0
            ring.value = String.format("%.2f", downMB)
            ring.progress = (downMB / 4.0).toFloat().coerceIn(0f, 1f)
            spark.push(downMB.toFloat())
            upValue.text = when {
                upKB >= 1024 -> String.format("%.1f MB/s", upKB / 1024)
                upKB >= 10 -> "${upKB.roundToInt()} KB/s"
                else -> String.format("%.1f KB/s", upKB)
            }
        }
        lastRx = rx; lastTx = tx; lastAt = now

        peersValue.text = "${s.optInt("peers")}"
        val up = s.optLong("uptime_s")
        uptimeValue.text = String.format("%02d:%02d:%02d", up / 3600, (up % 3600) / 60, up % 60)

        val exit = s.optString("exit")
        val rtt = s.optInt("rtt_ms")
        exitLine.text = if (rtt > 0) "$exit · ${rtt}ms" else "$exit · —"

        directCount.text = "${s.optLong("tcp_direct")}"
        exitCount.text = "${s.optLong("tcp_exit")}"
        blockCount.text = "${s.optLong("tcp_blocked") + s.optLong("dns_blocked")}"

        if (!chipsBuilt) buildChips(s, exit)
    }

    private fun applyState(running: Boolean) {
        statePill.text = if (running) "已连接" else "未连接"
        statePill.setTextColor(getColor(if (running) R.color.accent else R.color.text_3))
        statePill.setBackgroundResource(if (running) R.drawable.bg_pill_accent else R.drawable.bg_pill)
        ring.accent = getColor(if (running) R.color.accent else R.color.text_3)
        ring.progress = if (running) ring.progress else 0f
        toggle.text = if (running) "断开连接" else "建立连接"
        toggle.setBackgroundColor(getColor(if (running) R.color.accent else R.color.surface_2))
        toggle.setTextColor(getColor(if (running) R.color.bg else R.color.text))
    }

    /** 出口快捷芯片：取 RTT 最低的若干节点 */
    private fun buildChips(s: JSONObject, current: String) {
        val nodes = s.optJSONArray("nodes") ?: return
        exitChips.removeAllViews()
        val list = ArrayList<JSONObject>()
        for (i in 0 until nodes.length()) list.add(nodes.getJSONObject(i))
        // 当前出口置顶，其余按 RTT
        list.sortBy { if (it.optString("name") == current) 0 else 1 + it.optInt("rtt") }

        for (n in list.take(4)) {
            val name = n.optString("name")
            val on = name == current
            val chip = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                setBackgroundResource(if (on) R.drawable.bg_chip_on else R.drawable.bg_chip)
                setPadding(dp(13), dp(10), dp(13), dp(10))
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.WRAP_CONTENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT,
                ).apply { marginEnd = dp(8) }
                setOnClickListener { switchExit(name) }
            }
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
            }
            val dot = View(this).apply {
                setBackgroundResource(if (on) R.drawable.bg_dot_accent else R.drawable.bg_dot_muted)
                layoutParams = LinearLayout.LayoutParams(dp(6), dp(6)).apply { marginEnd = dp(7) }
            }
            val label = TextView(this).apply {
                text = name
                typeface = Typeface.MONOSPACE
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
                setTextColor(getColor(if (on) R.color.accent else R.color.text_2))
            }
            row.addView(dot); row.addView(label)

            val sub = TextView(this).apply {
                text = n.optInt("rtt").let { r -> if (r > 0) "${r}ms" else "—" }
                typeface = Typeface.MONOSPACE
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 10f)
                setTextColor(Color.parseColor("#FF5A6875"))
                setPadding(0, dp(6), 0, 0)
            }
            chip.addView(row); chip.addView(sub)
            exitChips.addView(chip)
        }
        chipsBuilt = list.isNotEmpty()
    }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    override fun onResume() {
        super.onResume()
        lastAt = 0
        handler.post(tick)
    }

    override fun onPause() {
        super.onPause()
        handler.removeCallbacks(tick)
    }
}
