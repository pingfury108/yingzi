package io.yingzi.app

import android.content.Intent
import android.graphics.Typeface
import android.os.Bundle
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.SwitchCompat

/** 应用分流：选择仅代理 / 排除的应用 */
class AppsActivity : AppCompatActivity() {

    private lateinit var list: LinearLayout
    private lateinit var modes: LinearLayout
    private lateinit var search: EditText
    private var mode = AppRules.GLOBAL
    private val picked = mutableSetOf<String>()
    private var apps: List<AppEntry> = emptyList()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_apps)
        list = findViewById(R.id.appList)
        modes = findViewById(R.id.modes)
        search = findViewById(R.id.search)

        mode = AppRules.mode(this)
        picked += AppRules.selected(this)
        apps = AppRules.installed(this)

        findViewById<ImageButton>(R.id.back).setOnClickListener { finish() }
        findViewById<com.google.android.material.button.MaterialButton>(R.id.saveApps)
            .setOnClickListener {
                AppRules.setMode(this, mode)
                AppRules.setSelected(this, picked)
                if (YzCore.nativeIsRunning()) {
                    startService(
                        Intent(this, YzVpnService::class.java).setAction(YzVpnService.ACTION_REBUILD)
                    )
                }
                Toast.makeText(this, "已保存，核心已重启", Toast.LENGTH_SHORT).show()
                finish()
            }

        search.addTextChangedListener(object : android.text.TextWatcher {
            override fun afterTextChanged(s: android.text.Editable?) = render()
            override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
            override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
        })

        buildModes()
        render()
    }

    private fun buildModes() {
        modes.removeAllViews()
        val items = listOf(
            AppRules.GLOBAL to "全局代理",
            AppRules.INCLUDE to "仅代理选中",
            AppRules.EXCLUDE to "排除选中",
        )
        for ((m, label) in items) {
            val on = m == mode
            modes.addView(TextView(this).apply {
                text = label
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f)
                setTextColor(getColor(if (on) R.color.accent else R.color.text_3))
                setBackgroundResource(if (on) R.drawable.bg_pill_accent else R.drawable.bg_pill)
                setPadding(dp(14), dp(7), dp(14), dp(7))
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT
                ).apply { marginEnd = dp(6) }
                setOnClickListener { mode = m; buildModes(); render() }
            })
        }
    }

    private fun render() {
        list.removeAllViews()
        val q = search.text.toString().trim().lowercase()
        val shown = apps.filter { q.isEmpty() || it.label.lowercase().contains(q) || it.pkg.contains(q) }
        if (mode == AppRules.GLOBAL) {
            list.addView(hint("全局代理下所有应用都走 VPN。切到「仅代理选中」或「排除选中」后可逐个选择应用。"))
        }
        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundResource(R.drawable.bg_card)
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { topMargin = dp(12) }
        }
        shown.forEachIndexed { i, app ->
            if (i > 0) card.addView(View(this).apply {
                setBackgroundColor(getColor(R.color.line))
                layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, dp(1))
            })
            card.addView(row(app))
        }
        list.addView(card)
        list.addView(TextView(this).apply {
            text = "已选 ${picked.size} 个 · 共 ${apps.size} 个可启动应用"
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 10f)
            setTextColor(getColor(R.color.text_3))
            typeface = Typeface.MONOSPACE
            gravity = Gravity.CENTER
            setPadding(0, dp(16), 0, 0)
        })
    }

    private fun row(app: AppEntry): View {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(14), dp(11), dp(14), dp(11))
        }
        val icon = try {
            packageManager.getApplicationIcon(app.pkg)
        } catch (e: Exception) {
            null
        }
        row.addView(ImageView(this).apply {
            setImageDrawable(icon)
            layoutParams = LinearLayout.LayoutParams(dp(30), dp(30)).apply { marginEnd = dp(12) }
        })
        val box = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        box.addView(TextView(this).apply {
            text = app.label
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
            setTextColor(getColor(R.color.text))
            maxLines = 1
            ellipsize = android.text.TextUtils.TruncateAt.END
        })
        box.addView(TextView(this).apply {
            text = app.pkg
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 10f)
            setTextColor(getColor(R.color.text_3))
            typeface = Typeface.MONOSPACE
            setPadding(0, dp(4), 0, 0)
            maxLines = 1
            ellipsize = android.text.TextUtils.TruncateAt.END
        })
        row.addView(box)

        val sw = SwitchCompat(this).apply {
            isChecked = picked.contains(app.pkg)
            isEnabled = mode != AppRules.GLOBAL
            setOnCheckedChangeListener { _, checked ->
                if (checked) picked += app.pkg else picked -= app.pkg
            }
        }
        row.addView(sw)
        if (mode != AppRules.GLOBAL) {
            val toggle = android.view.View.OnClickListener { sw.isChecked = !sw.isChecked }
            row.setOnClickListener(toggle)
            box.setOnClickListener(toggle)
        }
        return row
    }

    private fun hint(msg: String) = TextView(this).apply {
        text = msg
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f)
        setTextColor(getColor(R.color.text_3))
        setLineSpacing(dp(4).toFloat(), 1f)
        setPadding(dp(14), dp(14), dp(14), dp(14))
        setBackgroundResource(R.drawable.bg_card_inset)
    }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()
}
