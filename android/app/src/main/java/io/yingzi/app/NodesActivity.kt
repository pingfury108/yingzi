package io.yingzi.app

import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import org.json.JSONObject

/** 出口节点选择：RTT 排序 + 当前出口高亮 */
class NodesActivity : AppCompatActivity() {

    private lateinit var list: LinearLayout

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_nodes)
        list = findViewById(R.id.nodeList)

        findViewById<ImageButton>(R.id.back).setOnClickListener { finish() }
        findViewById<com.google.android.material.bottomnavigation.BottomNavigationView>(R.id.nav)
            .apply {
                selectedItemId = R.id.nav_nodes
                setOnItemSelectedListener { item ->
                    when (item.itemId) {
                        R.id.nav_status -> { finish() }
                        R.id.nav_rules -> startActivity(Intent(this@NodesActivity, RulesActivity::class.java))
                        R.id.nav_log -> startActivity(Intent(this@NodesActivity, LogActivity::class.java))
                    }
                    true
                }
            }
        render()
    }

    private fun render() {
        list.removeAllViews()
        val cfg = NodeConfig.load(this)
        val status = try {
            JSONObject(YzCore.nativeStatus())
        } catch (e: Exception) {
            JSONObject()
        }
        val current = status.optString("exit").ifEmpty { cfg.defaultExit }
        val nodes = status.optJSONArray("nodes")

        // 自动选择
        list.addView(autoCard(current == "auto"))

        list.addView(sectionLabel("可用节点", if (nodes == null) 0 else nodes.length()))

        if (nodes == null || nodes.length() == 0) {
            list.addView(hint("未连接核心时无节点数据，先回到状态页建立连接"))
            return
        }

        val items = ArrayList<JSONObject>()
        for (i in 0 until nodes.length()) items.add(nodes.getJSONObject(i))
        items.sortBy { it.optInt("rtt").let { r -> if (r == 0) 99999 else r } }

        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundResource(R.drawable.bg_card)
        }
        items.forEachIndexed { idx, n ->
            if (idx > 0) card.addView(divider())
            card.addView(nodeRow(n, n.optString("name") == current))
        }
        list.addView(card)

        list.addView(hint("出口决定被代理流量的落地 IP。国内域名与内网地址始终直连，不受此处影响。"))
    }

    private fun autoCard(on: Boolean): View {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(14), dp(14), dp(14), dp(14))
            setBackgroundResource(if (on) R.drawable.bg_chip_on else R.drawable.bg_card)
            setOnClickListener { pick("auto") }
        }
        val icon = ImageView(this).apply {
            setImageResource(R.drawable.ic_bolt)
            setColorFilter(getColor(if (on) R.color.accent else R.color.text_2))
            layoutParams = LinearLayout.LayoutParams(dp(18), dp(18))
        }
        val box = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(12), 0, 0, 0)
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        box.addView(label("自动选择", 13f, R.color.text, false))
        box.addView(sub("按延迟与负载择优", 11f))
        row.addView(icon); row.addView(box)
        if (on) row.addView(checkMark())
        return row
    }

    private fun nodeRow(n: JSONObject, on: Boolean): View {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(14), dp(12), dp(14), dp(12))
            if (on) setBackgroundColor(Color.parseColor("#0B38F0C6"))
            setOnClickListener { pick(n.optString("name")) }
        }
        // 左侧高亮条
        row.addView(View(this).apply {
            setBackgroundColor(if (on) getColor(R.color.accent) else Color.TRANSPARENT)
            layoutParams = LinearLayout.LayoutParams(dp(3), dp(30)).apply { marginEnd = dp(11) }
        })

        val box = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        val title = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
        title.addView(label(n.optString("name"), 13f, R.color.text, true))
        val role = when {
            n.optBoolean("is_exit") -> "出口"
            n.optBoolean("connected") -> "已连"
            else -> "节点"
        }
        title.addView(tag(role))
        box.addView(title)
        box.addView(sub("${n.optString("vip")} · ${n.optString("path").ifEmpty { "—" }}", 11f))
        row.addView(box)

        val rtt = n.optInt("rtt")
        row.addView(TextView(this).apply {
            text = if (rtt > 0) "${rtt}ms" else "—"
            typeface = Typeface.MONOSPACE
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            setTextColor(getColor(if (rtt in 1..20) R.color.direct else R.color.text_2))
            gravity = Gravity.END
        })
        if (on) {
            row.addView(checkMark())
        } else {
            row.addView(View(this).apply { layoutParams = LinearLayout.LayoutParams(dp(18), dp(1)) })
        }
        return row
    }

    private fun pick(name: String) {
        val cfg = NodeConfig.load(this)
        NodeConfig.save(this, cfg.networkSecret, cfg.coordinator, cfg.name, name, cfg.remoteDns, cfg.directDns)
        if (YzCore.nativeIsRunning()) {
            startService(Intent(this, YzVpnService::class.java).setAction(YzVpnService.ACTION_RESTART))
        }
        Toast.makeText(this, "出口已切换到 $name", Toast.LENGTH_SHORT).show()
        list.postDelayed({ render() }, 600)
    }

    // ---------- 小组件 ----------
    private fun sectionLabel(text: String, count: Int): View {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, dp(22), 0, dp(10))
        }
        row.addView(TextView(this).apply { this.text = text.uppercase(); setMicro() })
        row.addView(View(this).apply {
            setBackgroundColor(getColor(R.color.line))
            layoutParams = LinearLayout.LayoutParams(0, dp(1), 1f).apply { marginStart = dp(8); marginEnd = dp(8) }
        })
        row.addView(TextView(this).apply { this.text = "$count"; setMicro() })
        return row
    }

    private fun label(text: String, sp: Float, color: Int, mono: Boolean) = TextView(this).apply {
        this.text = text
        setTextSize(TypedValue.COMPLEX_UNIT_SP, sp)
        setTextColor(getColor(color))
        if (mono) typeface = Typeface.MONOSPACE
    }

    private fun sub(text: String, sp: Float) = TextView(this).apply {
        this.text = text
        setTextSize(TypedValue.COMPLEX_UNIT_SP, sp)
        setTextColor(getColor(R.color.text_3))
        typeface = Typeface.MONOSPACE
        setPadding(0, dp(5), 0, 0)
    }

    private fun tag(text: String) = TextView(this).apply {
        this.text = text
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 9f)
        setTextColor(getColor(R.color.text_3))
        typeface = Typeface.MONOSPACE
        setPadding(dp(5), dp(3), dp(5), dp(3))
        setBackgroundResource(R.drawable.bg_pill)
        layoutParams = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply { marginStart = dp(7) }
    }

    private fun checkMark() = ImageView(this).apply {
        setImageResource(R.drawable.ic_check)
        setColorFilter(getColor(R.color.accent))
        layoutParams = LinearLayout.LayoutParams(dp(16), dp(16)).apply { marginStart = dp(6) }
    }

    private fun divider() = View(this).apply {
        setBackgroundColor(getColor(R.color.line))
        layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, dp(1))
    }

    private fun hint(text: String) = TextView(this).apply {
        this.text = text
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f)
        setTextColor(getColor(R.color.text_3))
        setLineSpacing(dp(4).toFloat(), 1f)
        setPadding(dp(14), dp(14), dp(14), dp(14))
        setBackgroundResource(R.drawable.bg_card_inset)
        layoutParams = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply { topMargin = dp(14) }
    }

    private fun TextView.setMicro() {
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 10f)
        setTextColor(getColor(R.color.text_3))
        typeface = Typeface.MONOSPACE
        letterSpacing = 0.16f
    }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()
}
