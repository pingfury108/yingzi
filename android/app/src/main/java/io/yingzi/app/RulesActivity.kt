package io.yingzi.app

import android.graphics.Color
import android.os.Bundle
import android.view.Gravity
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import org.json.JSONArray

class RulesActivity : AppCompatActivity() {

    private lateinit var list: LinearLayout
    private lateinit var input: EditText
    private val rules = mutableListOf<String>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_rules)
        list = findViewById(R.id.ruleList)
        input = findViewById(R.id.ruleInput)
        rules += Rules.load(this)

        findViewById<Button>(R.id.addRule).setOnClickListener {
            val r = input.text.toString().trim()
            if (r.isEmpty()) return@setOnClickListener
            rules += r
            input.setText("")
            render()
        }

        findViewById<Button>(R.id.saveRules).setOnClickListener {
            Rules.save(this, rules)
            val ok = YzCore.nativeSetRules(JSONArray(rules).toString())
            Toast.makeText(
                this,
                if (ok) "已保存并热更新 (${rules.size} 条)" else "已保存，核心未运行，下次启动生效",
                Toast.LENGTH_SHORT
            ).show()
            finish()
        }

        presets = findViewById(R.id.presets)
        recreatePresets()
        render()
    }

    private lateinit var presets: LinearLayout

    private fun recreatePresets() {
        presets.removeAllViews()
        Rules.PRESETS.forEach { (label, rule) ->
            val b = Button(this).apply {
                text = if (rules.contains(rule)) "✓ $label" else "+ $label"
                textSize = 13f
                gravity = Gravity.START or Gravity.CENTER_VERTICAL
                setTextColor(if (rules.contains(rule)) Color.GRAY else Color.parseColor("#1A73E8"))
                setBackgroundColor(Color.TRANSPARENT)
                setOnClickListener {
                    if (rules.contains(rule)) rules.remove(rule) else rules += rule
                    render()
                    recreatePresets()
                }
            }
            presets.addView(b)
        }
    }

    private fun render() {
        list.removeAllViews()
        if (rules.isEmpty()) {
            list.addView(TextView(this).apply {
                text = "暂无规则（全部走默认出口）"
                setTextColor(Color.GRAY)
                textSize = 13f
            })
            return
        }
        rules.forEachIndexed { idx, rule ->
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                setPadding(0, 6, 0, 6)
            }
            row.addView(TextView(this).apply {
                text = "${idx + 1}. $rule"
                textSize = 13f
                setTextColor(Color.parseColor(actionColor(rule)))
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            })
            row.addView(Button(this).apply {
                text = "✕"
                textSize = 14f
                setTextColor(Color.parseColor("#D93025"))
                setBackgroundColor(Color.TRANSPARENT)
                setOnClickListener {
                    rules.removeAt(idx)
                    render()
                }
            })
            list.addView(row)
        }
    }

    private fun actionColor(rule: String): String = when {
        rule.endsWith("=block") -> "#D93025"
        rule.endsWith("=direct") -> "#188038"
        else -> "#1A73E8"
    }
}
