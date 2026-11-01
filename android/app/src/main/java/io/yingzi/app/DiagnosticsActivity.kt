package io.yingzi.app

import android.graphics.Typeface
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

/** 网络诊断：节点连通/延迟 + DNS 污染/劫持 */
class DiagnosticsActivity : AppCompatActivity() {

    private lateinit var run: MaterialButton
    private lateinit var hint: TextView
    private lateinit var nodeList: LinearLayout
    private lateinit var dnsBox: LinearLayout
    private val handler = Handler(Looper.getMainLooper())

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_diag)
        run = findViewById(R.id.run)
        hint = findViewById(R.id.hint)
        nodeList = findViewById(R.id.nodeList)
        dnsBox = findViewById(R.id.dnsBox)

        findViewById<ImageButton>(R.id.back).setOnClickListener { finish() }

        run.setOnClickListener {
            if (!YzCore.nativeIsRunning()) {
                Toast.makeText(this, "请先连接", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            start()
        }
        placeholder()
    }

    private fun placeholder() {
        nodeList.removeAllViews()
        nodeList.addView(TextView(this).apply {
            text = "点击「开始检测」"
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            setTextColor(getColor(R.color.text_3))
            gravity = Gravity.CENTER
            setPadding(dp(14), dp(22), dp(14), dp(22))
        })
        dnsBox.removeAllViews()
        dnsBox.addView(TextView(this).apply {
            text = "等待检测"
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            setTextColor(getColor(R.color.text_3))
        })
    }

    private fun start() {
        run.isEnabled = false
        run.text = "检测中…"
        hint.text = "正在连接各节点并比对 DNS（约 3–8 秒）"
        Thread {
            val json = YzCore.nativeDiagnose()
            handler.post {
                run.isEnabled = true
                run.text = "重新检测"
                hint.text = "检测完成"
                render(json)
            }
        }.start()
    }

    private fun render(json: String) {
        val root = try { JSONObject(json) } catch (e: Exception) { return }
        if (root.has("error")) {
            hint.text = root.optString("error")
            return
        }
        // 节点
        nodeList.removeAllViews()
        val nodes = root.optJSONArray("nodes")
        if (nodes == null || nodes.length() == 0) {
            nodeList.addView(row("暂无节点", "", "—", R.color.text_3))
        } else {
            for (i in 0 until nodes.length()) {
                val n = nodes.getJSONObject(i)
                if (i > 0) nodeList.addView(divider())
                val err = if (n.isNull("error")) "" else n.optString("error")
                val rtt = n.optLong("rtt_ms")
                nodeList.addView(
                    row(
                        n.optString("name"),
                        n.optString("addr"),
                        if (err.isNotEmpty()) "失败" else "${rtt}ms",
                        if (err.isNotEmpty()) R.color.block else if (rtt in 1..60) R.color.direct else R.color.warn,
                        err.ifEmpty { null },
                    )
                )
            }
        }

        // DNS
        dnsBox.removeAllViews()
        val dns = root.optJSONObject("dns") ?: return
        val domain = dns.optString("domain")
        dnsBox.addView(label("检测域名 $domain", 11f, R.color.text_3, true))
        dnsBox.addView(dnsLine("直连 DNS", dns.optJSONObject("direct")))
        dnsBox.addView(dnsLine("出口 DNS", dns.optJSONObject("exit")))

        val polluted = dns.optBoolean("polluted")
        val hijacked = dns.optBoolean("hijacked")
        dnsBox.addView(verdict(
            if (polluted) "直连 DNS 结果与出口不一致，疑似被污染" else "直连 DNS 与出口结果一致，未发现污染",
            !polluted,
        ))
        dnsBox.addView(verdict(
            if (hijacked) "不存在的域名被解析出地址，DNS 存在劫持" else "随机域名正确返回 NXDOMAIN，未发现劫持",
            !hijacked,
        ))
    }

    private fun dnsLine(title: String, obj: JSONObject?): View {
        val box = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, dp(10), 0, dp(4))
        }
        val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        row.addView(TextView(this).apply {
            text = title
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            setTextColor(getColor(R.color.text_2))
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        })
        row.addView(TextView(this).apply {
            text = if (obj == null) "失败" else "${obj.optLong("ms")}ms"
            typeface = Typeface.MONOSPACE
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f)
            setTextColor(getColor(R.color.text_3))
        })
        box.addView(row)
        val ips = obj?.optJSONArray("ips")
        val text = when {
            obj == null -> "无结果"
            ips == null || ips.length() == 0 -> "空应答"
            else -> (0 until minOf(ips.length(), 4)).joinToString(", ") { ips.getString(it) }
        }
        box.addView(TextView(this).apply {
            this.text = text
            typeface = Typeface.MONOSPACE
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f)
            setTextColor(getColor(R.color.text))
            setPadding(0, dp(6), 0, 0)
        })
        return box
    }

    private fun verdict(text: String, ok: Boolean): View = TextView(this).apply {
        this.text = (if (ok) "✓ " else "! ") + text
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f)
        setTextColor(getColor(if (ok) R.color.direct else R.color.warn))
        setPadding(0, dp(10), 0, 0)
        setLineSpacing(dp(3).toFloat(), 1f)
    }

    private fun row(name: String, addr: String, value: String, color: Int, detail: String? = null): View {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(14), dp(12), dp(14), dp(12))
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
        })
        box.addView(TextView(this).apply {
            text = detail ?: addr
            typeface = Typeface.MONOSPACE
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 10f)
            setTextColor(getColor(R.color.text_3))
            setPadding(0, dp(5), 0, 0)
        })
        row.addView(box)
        row.addView(TextView(this).apply {
            text = value
            typeface = Typeface.MONOSPACE
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            setTextColor(getColor(color))
        })
        return row
    }

    private fun label(text: String, sp: Float, color: Int, mono: Boolean) = TextView(this).apply {
        this.text = text
        setTextSize(TypedValue.COMPLEX_UNIT_SP, sp)
        setTextColor(getColor(color))
        if (mono) typeface = Typeface.MONOSPACE
    }

    private fun divider() = View(this).apply {
        setBackgroundColor(getColor(R.color.line))
        layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, dp(1))
    }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()
}
