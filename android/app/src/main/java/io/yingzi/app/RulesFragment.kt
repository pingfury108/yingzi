package io.yingzi.app

import android.graphics.Typeface
import android.os.Bundle
import android.util.TypedValue
import android.view.Gravity
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.*
import androidx.fragment.app.Fragment
import org.json.JSONArray

/** 分流规则：分组列表 + 模板 + 热更新 */
class RulesFragment : Fragment() {

    private lateinit var root: View
    private lateinit var list: LinearLayout
    private lateinit var presets: LinearLayout
    private lateinit var seg: LinearLayout
    private lateinit var input: EditText
    private val rules = mutableListOf<String>()
    private var filter = "全部"

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?,
    ): View {
        root = inflater.inflate(R.layout.fragment_rules, container, false)
        list = root.findViewById(R.id.ruleList)
        presets = root.findViewById(R.id.presets)
        seg = root.findViewById(R.id.seg)
        input = root.findViewById(R.id.ruleInput)
        rules.clear()
        rules += Rules.load(requireContext())

        root.findViewById<Button>(R.id.addRule).setOnClickListener {
            val r = input.text.toString().trim()
            if (r.isEmpty()) return@setOnClickListener
            if (r.contains('=')) {
                rules += r
                input.setText("")
                commit()
            } else {
                Toast.makeText(
                    requireContext(), "格式：匹配器=动作，如 geosite:google=exit",
                    Toast.LENGTH_SHORT
                ).show()
            }
        }

        buildSeg()
        buildPresets()
        render()
        return root
    }

    private fun buildSeg() {
        val ctx = requireContext()
        seg.removeAllViews()
        for (f in listOf("全部", "直连", "代理", "拦截")) {
            val on = f == filter
            seg.addView(TextView(ctx).apply {
                text = f
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f)
                setTextColor(ctx.getColor(if (on) R.color.accent else R.color.text_3))
                setBackgroundResource(if (on) R.drawable.bg_pill_accent else R.drawable.bg_pill)
                setPadding(dp(14), dp(7), dp(14), dp(7))
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT
                ).apply { marginEnd = dp(6) }
                setOnClickListener { filter = f; buildSeg(); render() }
            })
        }
    }

    private fun buildPresets() {
        val ctx = requireContext()
        presets.removeAllViews()
        Rules.PRESETS.forEach { (label, rule) ->
            val on = rules.contains(rule)
            presets.addView(TextView(ctx).apply {
                text = if (on) "✓ $label" else "+ $label"
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f)
                setTextColor(ctx.getColor(if (on) R.color.text_3 else R.color.accent))
                setBackgroundResource(if (on) R.drawable.bg_pill else R.drawable.bg_pill_accent)
                setPadding(dp(12), dp(7), dp(12), dp(7))
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT
                ).apply { marginEnd = dp(6) }
                setOnClickListener {
                    if (rules.contains(rule)) rules.remove(rule) else rules += rule
                    buildPresets(); render(); commit()
                }
            })
        }
    }

    private fun action(rule: String) = when {
        rule.endsWith("=block") -> "block"
        rule.endsWith("=direct") -> "direct"
        else -> "exit"
    }

    private fun render() {
        val ctx = requireContext()
        list.removeAllViews()
        val groups = linkedMapOf("拦截" to "block", "直连" to "direct", "代理" to "exit")
        var shown = 0
        for ((groupName, act) in groups) {
            if (filter != "全部" && filter != groupName) continue
            val items = rules.filter { action(it) == act }
            if (items.isEmpty()) continue
            list.addView(sectionLabel(groupName, items.size))
            val card = LinearLayout(ctx).apply {
                orientation = LinearLayout.VERTICAL
                setBackgroundResource(R.drawable.bg_card)
            }
            items.forEachIndexed { i, r ->
                if (i > 0) card.addView(divider())
                card.addView(ruleRow(r, act))
                shown++
            }
            list.addView(card)
        }
        if (shown == 0) {
            list.addView(TextView(ctx).apply {
                text = "暂无规则（全部走默认出口）"
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
                setTextColor(ctx.getColor(R.color.text_3))
                setPadding(dp(14), dp(20), dp(14), dp(20))
                setBackgroundResource(R.drawable.bg_card_inset)
                gravity = Gravity.CENTER
            })
        }
    }

    private fun ruleRow(rule: String, act: String): View {
        val ctx = requireContext()
        val row = LinearLayout(ctx).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(14), dp(12), dp(14), dp(12))
        }
        row.addView(ImageView(ctx).apply {
            setImageResource(R.drawable.ic_rules)
            setColorFilter(ctx.getColor(R.color.text_3))
            layoutParams = LinearLayout.LayoutParams(dp(14), dp(14)).apply { marginEnd = dp(10) }
        })

        val box = LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        box.addView(TextView(ctx).apply {
            text = rule
            typeface = Typeface.MONOSPACE
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            setTextColor(ctx.getColor(R.color.text))
        })
        row.addView(box)

        row.addView(TextView(ctx).apply {
            text = act.uppercase()
            typeface = Typeface.MONOSPACE
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 9f)
            letterSpacing = 0.12f
            setTextColor(ctx.getColor(when (act) {
                "direct" -> R.color.direct
                "block" -> R.color.block
                else -> R.color.exit
            }))
            setBackgroundResource(R.drawable.bg_pill)
            setPadding(dp(8), dp(5), dp(8), dp(5))
        })

        row.addView(TextView(ctx).apply {
            text = "✕"
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
            setTextColor(ctx.getColor(R.color.block))
            setPadding(dp(12), dp(4), dp(4), dp(4))
            setOnClickListener {
                rules.remove(rule)
                buildPresets(); render(); commit()
            }
        })
        return row
    }

    private fun commit() {
        val ctx = requireContext()
        Rules.save(ctx, rules)
        val ok = YzCore.nativeSetRules(JSONArray(rules).toString())
        if (ok) YzCore.nativePushEvent("INFO", "规则热更新 ${rules.size} 条")
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

    private fun divider() = View(requireContext()).apply {
        setBackgroundColor(requireContext().getColor(R.color.line))
        layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, dp(1))
    }

    private fun TextView.setMicro() {
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 10f)
        setTextColor(requireContext().getColor(R.color.text_3))
        typeface = Typeface.MONOSPACE
        letterSpacing = 0.16f
    }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()
}