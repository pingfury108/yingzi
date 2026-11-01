package io.yingzi.app

import android.content.Intent
import android.graphics.Typeface
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.TypedValue
import android.view.Gravity
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import org.json.JSONArray
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** 事件日志：核心事件环 → 等宽流式列表 */
class LogActivity : AppCompatActivity() {

    private lateinit var list: LinearLayout
    private lateinit var scroll: ScrollView
    private lateinit var filters: LinearLayout
    private var filter = "ALL"
    private var paused = false
    private val handler = Handler(Looper.getMainLooper())
    private val fmt = SimpleDateFormat("HH:mm:ss", Locale.getDefault())

    private val tick = object : Runnable {
        override fun run() {
            if (!paused) render()
            handler.postDelayed(this, 2000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_log)
        list = findViewById(R.id.logList)
        scroll = findViewById(R.id.logScroll)
        filters = findViewById(R.id.filters)

        findViewById<ImageButton>(R.id.back).setOnClickListener { finish() }
        findViewById<ImageButton>(R.id.pause).setOnClickListener {
            paused = !paused
            (it as ImageButton).setImageResource(if (paused) R.drawable.ic_play else R.drawable.ic_pause)
        }
        findViewById<com.google.android.material.bottomnavigation.BottomNavigationView>(R.id.nav)
            .apply {
                selectedItemId = R.id.nav_log
                setOnItemSelectedListener { item ->
                    when (item.itemId) {
                        R.id.nav_status -> finish()
                        R.id.nav_nodes -> startActivity(Intent(this@LogActivity, NodesActivity::class.java))
                        R.id.nav_rules -> startActivity(Intent(this@LogActivity, RulesActivity::class.java))
                    }
                    true
                }
            }

        buildFilters()
        render()
    }

    private fun buildFilters() {
        filters.removeAllViews()
        for (f in listOf("ALL", "DNS", "TCP", "WARN", "ERROR")) {
            val on = f == filter
            filters.addView(TextView(this).apply {
                text = f
                typeface = Typeface.MONOSPACE
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f)
                letterSpacing = 0.06f
                setTextColor(getColor(if (on) R.color.accent else R.color.text_3))
                setBackgroundResource(if (on) R.drawable.bg_pill_accent else R.drawable.bg_pill)
                setPadding(dp(10), dp(5), dp(10), dp(5))
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT
                ).apply { marginEnd = dp(6) }
                setOnClickListener { filter = f; buildFilters(); render() }
            })
        }
    }

    private fun render() {
        val arr = try {
            JSONArray(YzCore.nativeEvents())
        } catch (e: Exception) {
            JSONArray()
        }
        list.removeAllViews()
        if (arr.length() == 0) {
            list.addView(TextView(this).apply {
                text = "暂无事件"
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
                setTextColor(getColor(R.color.text_3))
                setPadding(0, dp(24), 0, 0)
                gravity = Gravity.CENTER
            })
            return
        }
        for (i in arr.length() - 1 downTo 0) {
            val e = arr.getJSONObject(i)
            val level = e.optString("level").uppercase()
            if (filter != "ALL" && !level.contains(filter)) continue
            list.addView(line(e.optLong("ts"), level, e.optString("msg")))
        }
    }

    private fun line(ts: Long, level: String, msg: String): LinearLayout {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, dp(9), 0, dp(9))
            setBackgroundColor(getColor(R.color.bg))
        }
        row.addView(TextView(this).apply {
            text = fmt.format(Date(ts * 1000))
            typeface = Typeface.MONOSPACE
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 10f)
            setTextColor(getColor(R.color.text_3))
            layoutParams = LinearLayout.LayoutParams(dp(56), LinearLayout.LayoutParams.WRAP_CONTENT)
        })
        row.addView(TextView(this).apply {
            text = level
            typeface = Typeface.MONOSPACE
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 10f)
            setTextColor(levelColor(level))
            layoutParams = LinearLayout.LayoutParams(dp(46), LinearLayout.LayoutParams.WRAP_CONTENT)
        })
        row.addView(TextView(this).apply {
            text = msg
            typeface = Typeface.MONOSPACE
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f)
            setTextColor(getColor(R.color.text_2))
            setLineSpacing(dp(3).toFloat(), 1f)
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        })
        return row
    }

    private fun levelColor(level: String) = getColor(
        when {
            level.contains("ERROR") -> R.color.block
            level.contains("WARN") -> R.color.warn
            level.contains("DNS") -> R.color.exit
            level.contains("OK") -> R.color.direct
            else -> R.color.text_2
        }
    )

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    override fun onResume() {
        super.onResume()
        handler.post(tick)
    }

    override fun onPause() {
        super.onPause()
        handler.removeCallbacks(tick)
    }
}
