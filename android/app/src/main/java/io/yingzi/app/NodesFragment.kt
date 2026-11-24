package io.yingzi.app

import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.util.TypedValue
import android.view.Gravity
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.*
import androidx.fragment.app.Fragment
import org.json.JSONObject

/** 出口节点选择：RTT 排序 + 当前出口高亮 */
class NodesFragment : Fragment() {

    private lateinit var root: View
    private lateinit var list: LinearLayout

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?,
    ): View {
        root = inflater.inflate(R.layout.fragment_nodes, container, false)
        list = root.findViewById(R.id.nodeList)
        return root
    }

    override fun onResume() {
        super.onResume()
        render()
    }

    private fun render() {
        if (!isAdded) return
        list.removeAllViews()
        val cfg = NodeConfig.load(requireContext())
        val status = try {
            JSONObject(YzCore.nativeStatus())
        } catch (e: Exception) {
            JSONObject()
        }
        val current = status.optString("exit").ifEmpty { cfg.defaultExit }
        val nodes = status.optJSONArray("nodes")

        list.addView(autoCard(current == "auto"))
        list.addView(sectionLabel("可用节点", nodes?.length() ?: 0))

        if (nodes == null || nodes.length() == 0) {
            list.addView(hint("未连接核心时无节点数据，先回到状态页建立连接"))
            return
        }

        val items = ArrayList<JSONObject>()
        for (i in 0 until nodes.length()) items.add(nodes.getJSONObject(i))
        items.sortBy { it.optInt("rtt").let { r -> if (r == 0) 99999 else r } }

        val card = LinearLayout(requireContext()).apply {
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
        val ctx = requireContext()
        val row = LinearLayout(ctx).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(14), dp(14), dp(14), dp(14))
            setBackgroundResource(if (on) R.drawable.bg_chip_on else R.drawable.bg_card)
            setOnClickListener { pick("auto") }
        }
        val icon = ImageView(ctx).apply {
            setImageResource(R.drawable.ic_bolt)
            setColorFilter(ctx.getColor(if (on) R.color.accent else R.color.text_2))
            layoutParams = LinearLayout.LayoutParams(dp(18), dp(18))
        }
        val box = LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(12), 0, 0, 0)
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        box.addView(label("自动选择", 13f, R.color.text, false))
        box.addView(sub("按延迟与负载择优", 11f))
        row.addView(icon)
        row.addView(box)
        if (on) row.addView(checkMark())
        return row
    }

    private fun nodeRow(n: JSONObject, on: Boolean): View {
        val ctx = requireContext()
        val row = LinearLayout(ctx).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(14), dp(12), dp(14), dp(12))
            if (on) setBackgroundColor(Color.parseColor("#0B38F0C6"))
            setOnClickListener { pick(n.optString("name")) }
        }
        row.addView(View(ctx).apply {
            setBackgroundColor(if (on) ctx.getColor(R.color.accent) else Color.TRANSPARENT)
            layoutParams = LinearLayout.LayoutParams(dp(3), dp(30)).apply { marginEnd = dp(11) }
        })

        val connected = n.optBoolean("connected")
        val exitCap = n.optBoolean("is_exit")

        row.addView(View(ctx).apply {
            setBackgroundResource(
                when {
                    connected -> R.drawable.bg_dot_direct
                    exitCap -> R.drawable.bg_dot_warn
                    else -> R.drawable.bg_dot_muted
                }
            )
            layoutParams = LinearLayout.LayoutParams(dp(7), dp(7)).apply { marginEnd = dp(9) }
        })

        val box = LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        val title = LinearLayout(ctx).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        title.addView(label(n.optString("name"), 13f, R.color.text, true))
        if (exitCap) title.addView(tag("出口"))
        box.addView(title)

        val path = n.optString("path")
        val state = when {
            connected && path.isNotEmpty() -> "已连接 · $path"
            connected -> "已连接"
            else -> "${n.optString("vip")} · 未连接"
        }
        box.addView(sub(state, 11f))
        row.addView(box)

        val rtt = n.optInt("rtt")
        row.addView(TextView(ctx).apply {
            text = if (rtt > 0) "${rtt}ms" else "—"
            typeface = Typeface.MONOSPACE
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            setTextColor(
                ctx.getColor(
                    when {
                        !connected -> R.color.text_3
                        rtt in 1..20 -> R.color.direct
                        else -> R.color.text_2
                    }
                )
            )
            gravity = Gravity.END
        })
        if (on) {
            row.addView(checkMark())
        } else {
            row.addView(View(ctx).apply { layoutParams = LinearLayout.LayoutParams(dp(18), dp(1)) })
        }
        return row
    }

    private fun pick(name: String) {
        val ctx = requireContext()
        val cfg = NodeConfig.load(ctx)
        NodeConfig.save(ctx, cfg.networkSecret, cfg.coordinator, cfg.name, name, cfg.remoteDns, cfg.directDns)
        if (YzCore.nativeIsRunning()) {
            ctx.startService(
                Intent(ctx, YzVpnService::class.java).setAction(YzVpnService.ACTION_RESTART)
            )
        }
        Toast.makeText(ctx, "出口已切换到 $name", Toast.LENGTH_SHORT).show()
        list.postDelayed({ render() }, 600)
    }

    private fun sectionLabel(text: String, count: Int): View {
        val ctx = requireContext()
        val row = LinearLayout(ctx).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, dp(22), 0, dp(10))
        }
        row.addView(TextView(ctx).apply { this.text = text.uppercase(); setMicro() })
        row.addView(View(ctx).apply {
            setBackgroundColor(ctx.getColor(R.color.line))
            layoutParams = LinearLayout.LayoutParams(0, dp(1), 1f)
                .apply { marginStart = dp(8); marginEnd = dp(8) }
        })
        row.addView(TextView(ctx).apply { this.text = "$count"; setMicro() })
        return row
    }

    private fun label(text: String, sp: Float, color: Int, mono: Boolean) =
        TextView(requireContext()).apply {
            this.text = text
            setTextSize(TypedValue.COMPLEX_UNIT_SP, sp)
            setTextColor(requireContext().getColor(color))
            if (mono) typeface = Typeface.MONOSPACE
        }

    private fun sub(text: String, sp: Float) = TextView(requireContext()).apply {
        this.text = text
        setTextSize(TypedValue.COMPLEX_UNIT_SP, sp)
        setTextColor(requireContext().getColor(R.color.text_3))
        typeface = Typeface.MONOSPACE
        setPadding(0, dp(5), 0, 0)
    }

    private fun tag(text: String) = TextView(requireContext()).apply {
        this.text = text
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 9f)
        setTextColor(requireContext().getColor(R.color.text_3))
        typeface = Typeface.MONOSPACE
        setPadding(dp(5), dp(3), dp(5), dp(3))
        setBackgroundResource(R.drawable.bg_pill)
        layoutParams = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply { marginStart = dp(7) }
    }

    private fun checkMark() = ImageView(requireContext()).apply {
        setImageResource(R.drawable.ic_check)
        setColorFilter(requireContext().getColor(R.color.accent))
        layoutParams = LinearLayout.LayoutParams(dp(16), dp(16)).apply { marginStart = dp(6) }
    }

    private fun divider() = View(requireContext()).apply {
        setBackgroundColor(requireContext().getColor(R.color.line))
        layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, dp(1))
    }

    private fun hint(msg: String) = TextView(requireContext()).apply {
        text = msg
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f)
        setTextColor(requireContext().getColor(R.color.text_3))
        setLineSpacing(dp(4).toFloat(), 1f)
        setPadding(dp(14), dp(14), dp(14), dp(14))
        setBackgroundResource(R.drawable.bg_card_inset)
        layoutParams = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply { topMargin = dp(14) }
    }

    private fun TextView.setMicro() {
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 10f)
        setTextColor(requireContext().getColor(R.color.text_3))
        typeface = Typeface.MONOSPACE
        letterSpacing = 0.16f
    }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()
}