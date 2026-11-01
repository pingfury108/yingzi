package io.yingzi.app

import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import org.json.JSONObject

/** 统计：会话流量 / 分流占比 / 域名 TOP */
class StatsActivity : AppCompatActivity() {

    private lateinit var spark: SparkView
    private lateinit var totalDown: TextView
    private lateinit var totalUp: TextView
    private lateinit var totalTime: TextView
    private lateinit var bars: LinearLayout
    private lateinit var domainList: LinearLayout

    private val handler = Handler(Looper.getMainLooper())
    private val poller = java.util.concurrent.Executors.newSingleThreadExecutor()
    @Volatile private var polling = false
    private var lastRx = 0L
    private var lastAt = 0L

    private val tick = object : Runnable {
        override fun run() {
            poll()
            handler.postDelayed(this, 2000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_stats)
        spark = findViewById(R.id.spark)
        totalDown = findViewById(R.id.totalDown)
        totalUp = findViewById(R.id.totalUp)
        totalTime = findViewById(R.id.totalTime)
        bars = findViewById(R.id.bars)
        domainList = findViewById(R.id.domainList)

        findViewById<ImageButton>(R.id.back).setOnClickListener { finish() }
        Nav.bind(this, findViewById(R.id.nav), R.id.nav_stats)
    }

    private fun poll() {
        if (polling) return
        polling = true
        poller.execute {
            val json = if (YzCore.nativeIsRunning()) YzCore.nativeStatus() else ""
            handler.post {
                polling = false
                if (isFinishing) return@post
                render(json)
            }
        }
    }

    private fun render(json: String) {
        if (json.isEmpty()) {
            totalDown.text = "0 B"; totalUp.text = "0 B"; totalTime.text = "00:00:00"
            return
        }
        val s = try { JSONObject(json) } catch (e: Exception) { return }
        val rx = s.optLong("rx_bytes")
        val tx = s.optLong("tx_bytes")
        totalDown.text = fmt(rx)
        totalUp.text = fmt(tx)
        val up = s.optLong("uptime_s")
        totalTime.text = String.format("%02d:%02d:%02d", up / 3600, (up % 3600) / 60, up % 60)

        // 曲线：速率采样
        val now = System.currentTimeMillis()
        if (lastAt > 0 && now > lastAt) {
            val mb = (rx - lastRx) / ((now - lastAt) / 1000.0) / 1048576.0
            spark.push(mb.toFloat())
        }
        lastRx = rx; lastAt = now

        // 分流占比
        val direct = s.optLong("tcp_direct")
        val exit = s.optLong("tcp_exit")
        val block = s.optLong("tcp_blocked")
        val total = (direct + exit + block).coerceAtLeast(1)
        bars.removeAllViews()
        bars.addView(bar("直连", direct, total, getColor(R.color.direct)))
        bars.addView(bar("代理", exit, total, getColor(R.color.exit)))
        bars.addView(bar("拦截", block, total, getColor(R.color.block)))

        // 域名 TOP
        domainList.removeAllViews()
        val domains = s.optJSONArray("domains")
        if (domains == null || domains.length() == 0) {
            domainList.addView(TextView(this).apply {
                text = "暂无域名记录"
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
                setTextColor(getColor(R.color.text_3))
                gravity = Gravity.CENTER
                setPadding(dp(14), dp(22), dp(14), dp(22))
            })
            return
        }
        val max = (0 until domains.length()).maxOf { domains.getJSONObject(it).optLong("hits") }
            .coerceAtLeast(1)
        for (i in 0 until minOf(domains.length(), 15)) {
            val d = domains.getJSONObject(i)
            if (i > 0) domainList.addView(divider())
            domainList.addView(domainRow(d.optString("name"), d.optLong("hits"), d.optString("action"), max))
        }
    }

    private fun bar(name: String, value: Long, total: Long, color: Int): View {
        val pct = (value * 100.0 / total).toInt()
        val box = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, dp(6), 0, dp(6))
        }
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        row.addView(TextView(this).apply {
            text = name
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f)
            setTextColor(getColor(R.color.text_2))
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        })
        row.addView(TextView(this).apply {
            text = "$value · $pct%"
            typeface = Typeface.MONOSPACE
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f)
            setTextColor(getColor(R.color.text_3))
        })
        box.addView(row)

        val track = FrameLayout(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, dp(4)
            ).apply { topMargin = dp(7) }
            setBackgroundColor(Color.parseColor("#14FFFFFF"))
        }
        track.addView(View(this).apply {
            setBackgroundColor(color)
            layoutParams = FrameLayout.LayoutParams(
                (resources.displayMetrics.widthPixels * (pct / 100.0) * 0.72).toInt().coerceAtLeast(0),
                dp(4),
            )
        })
        box.addView(track)
        return box
    }

    private fun domainRow(name: String, hits: Long, action: String, max: Long): View {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(14), dp(11), dp(14), dp(11))
        }
        val box = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        box.addView(TextView(this).apply {
            text = name
            typeface = Typeface.MONOSPACE
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            setTextColor(getColor(R.color.text))
            maxLines = 1
            ellipsize = android.text.TextUtils.TruncateAt.MIDDLE
        })
        val track = FrameLayout(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, dp(3)
            ).apply { topMargin = dp(6) }
            setBackgroundColor(Color.parseColor("#10FFFFFF"))
        }
        val color = when (action) {
            "direct" -> getColor(R.color.direct)
            "block" -> getColor(R.color.block)
            else -> getColor(R.color.exit)
        }
        track.addView(View(this).apply {
            setBackgroundColor(color)
            layoutParams = FrameLayout.LayoutParams(
                (resources.displayMetrics.widthPixels * 0.6 * (hits.toDouble() / max)).toInt().coerceAtLeast(2),
                dp(3),
            )
        })
        box.addView(track)
        row.addView(box)
        row.addView(TextView(this).apply {
            text = "$hits"
            typeface = Typeface.MONOSPACE
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f)
            setTextColor(getColor(R.color.text_3))
            setPadding(dp(10), 0, 0, 0)
        })
        return row
    }

    private fun divider() = View(this).apply {
        setBackgroundColor(getColor(R.color.line))
        layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, dp(1))
    }

    private fun fmt(b: Long): String = when {
        b >= 1L shl 30 -> String.format("%.2f GB", b / 1073741824.0)
        b >= 1L shl 20 -> String.format("%.1f MB", b / 1048576.0)
        b >= 1L shl 10 -> String.format("%.1f KB", b / 1024.0)
        else -> "$b B"
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

    override fun onDestroy() {
        poller.shutdownNow()
        super.onDestroy()
    }
}
