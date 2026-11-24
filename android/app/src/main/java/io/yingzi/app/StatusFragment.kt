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
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.*
import androidx.fragment.app.Fragment
import com.google.android.material.button.MaterialButton
import org.json.JSONObject
import kotlin.math.roundToInt

/** 状态页：环形速率仪表 + 分流计数 + 出口快捷切换 */
class StatusFragment : Fragment() {

    private lateinit var root: View
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
    private var poller: java.util.concurrent.ExecutorService? = null
    @Volatile private var polling = false

    private var lastRx = 0L
    private var lastTx = 0L
    private var lastAt = 0L
    private var chipsBuilt = false

    private val tick = object : Runnable {
        override fun run() {
            pollAsync()
            handler.postDelayed(this, 1500)
        }
    }

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?,
    ): View {
        poller = java.util.concurrent.Executors.newSingleThreadExecutor()
        root = inflater.inflate(R.layout.fragment_status, container, false)
        ring = root.findViewById(R.id.ring)
        spark = root.findViewById(R.id.spark)
        statePill = root.findViewById(R.id.statePill)
        exitLine = root.findViewById(R.id.exitLine)
        upValue = root.findViewById(R.id.upValue)
        peersValue = root.findViewById(R.id.peersValue)
        uptimeValue = root.findViewById(R.id.uptimeValue)
        toggle = root.findViewById(R.id.toggle)
        exitChips = root.findViewById(R.id.exitChips)
        directCount = root.findViewById(R.id.directCount)
        exitCount = root.findViewById(R.id.exitCount)
        blockCount = root.findViewById(R.id.blockCount)

        root.findViewById<ImageButton>(R.id.settingsBtn).setOnClickListener {
            startActivity(Intent(requireContext(), SettingsActivity::class.java))
        }
        toggle.setOnClickListener {
            if (YzCore.nativeIsRunning()) stop() else start()
        }
        applyState(YzCore.nativeIsRunning())
        // 支持 adb / 快捷方式直接启动并自动连接
        if (requireActivity().intent?.getBooleanExtra("autostart", false) == true) {
            requireActivity().intent?.removeExtra("autostart")
            start()
        }
        return root
    }

    /** 由外壳在 autostart 时调用 */
    fun autoStart() = start()

    // ---------- 连接控制 ----------
    private fun start() {
        val prep = VpnService.prepare(requireContext())
        if (prep != null) startActivityForResult(prep, vpnPerm) else launchVpn()
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == vpnPerm && resultCode == android.app.Activity.RESULT_OK) launchVpn()
    }

    private fun launchVpn() {
        requireContext().startForegroundService(
            Intent(requireContext(), YzVpnService::class.java).setAction(YzVpnService.ACTION_START)
        )
    }

    private fun stop() {
        requireContext().startService(
            Intent(requireContext(), YzVpnService::class.java).setAction(YzVpnService.ACTION_STOP)
        )
    }

    private fun switchExit(name: String) {
        val ctx = requireContext()
        val cfg = NodeConfig.load(ctx)
        NodeConfig.save(
            ctx, cfg.networkSecret, cfg.coordinator, cfg.name, name,
            cfg.remoteDns, cfg.directDns,
        )
        if (YzCore.nativeIsRunning()) {
            YzCore.nativePushEvent("INFO", "出口切换到 $name")
            // 热切换，避免重启核心导致 fake-IP 池被清空
            YzCore.nativeSetExit(name)
        }
        chipsBuilt = false
        pollAsync()
    }

    // ---------- 状态刷新 ----------
    private fun pollAsync() {
        if (polling) return
        polling = true
        poller?.execute {
            val running = YzCore.nativeIsRunning()
            val json = if (running) YzCore.nativeStatus() else ""
            handler.post {
                polling = false
                if (!isAdded) return@post
                applyStatus(running, json)
            }
        }
    }

    private fun applyStatus(running: Boolean, json: String) {
        applyState(running)
        if (!running || json.isEmpty()) return
        val s = try { JSONObject(json) } catch (e: Exception) { return }
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
        val ctx = requireContext()
        statePill.text = if (running) "已连接" else "未连接"
        statePill.setTextColor(ctx.getColor(if (running) R.color.accent else R.color.text_3))
        statePill.setBackgroundResource(
            if (running) R.drawable.bg_pill_accent else R.drawable.bg_pill
        )
        ring.accent = ctx.getColor(if (running) R.color.accent else R.color.text_3)
        if (!running) ring.progress = 0f
        toggle.text = if (running) "断开连接" else "建立连接"
        toggle.setBackgroundColor(ctx.getColor(if (running) R.color.accent else R.color.surface_2))
        toggle.setTextColor(ctx.getColor(if (running) R.color.bg else R.color.text))
    }

    /** 出口快捷芯片：当前出口置顶，其余按 RTT */
    private fun buildChips(s: JSONObject, current: String) {
        val ctx = requireContext()
        val nodes = s.optJSONArray("nodes") ?: return
        exitChips.removeAllViews()
        val list = ArrayList<JSONObject>()
        for (i in 0 until nodes.length()) list.add(nodes.getJSONObject(i))
        list.sortBy { if (it.optString("name") == current) 0 else 1 + it.optInt("rtt") }

        for (n in list.take(4)) {
            val name = n.optString("name")
            val on = name == current
            val chip = LinearLayout(ctx).apply {
                orientation = LinearLayout.VERTICAL
                setBackgroundResource(if (on) R.drawable.bg_chip_on else R.drawable.bg_chip)
                setPadding(dp(13), dp(10), dp(13), dp(10))
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.WRAP_CONTENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT,
                ).apply { marginEnd = dp(8) }
                setOnClickListener { switchExit(name) }
            }
            val row = LinearLayout(ctx).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
            }
            row.addView(View(ctx).apply {
                setBackgroundResource(
                    if (on) R.drawable.bg_dot_accent else R.drawable.bg_dot_muted
                )
                layoutParams = LinearLayout.LayoutParams(dp(6), dp(6)).apply { marginEnd = dp(7) }
            })
            row.addView(TextView(ctx).apply {
                text = name
                typeface = Typeface.MONOSPACE
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
                setTextColor(ctx.getColor(if (on) R.color.accent else R.color.text_2))
            })
            chip.addView(row)
            chip.addView(TextView(ctx).apply {
                text = n.optInt("rtt").let { r -> if (r > 0) "${r}ms" else "—" }
                typeface = Typeface.MONOSPACE
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 10f)
                setTextColor(Color.parseColor("#FF5A6875"))
                setPadding(0, dp(6), 0, 0)
            })
            exitChips.addView(chip)
        }
        chipsBuilt = list.isNotEmpty()
    }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    override fun onResume() {
        super.onResume()
        lastAt = 0
        if (::root.isInitialized) handler.post(tick)
    }

    override fun onPause() {
        super.onPause()
        handler.removeCallbacks(tick)
    }

    override fun onDestroyView() {
        poller?.shutdownNow()
        poller = null
        super.onDestroyView()
    }
}