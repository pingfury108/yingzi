package io.yingzi.app

import android.content.Context
import android.graphics.*
import android.util.AttributeSet
import android.view.View
import kotlin.math.cos
import kotlin.math.min
import kotlin.math.sin

/**
 * 270° 环形仪表：外圈刻度 + 轨道 + 进度弧（带发光）+ 中心标签/数值。
 * 用于主界面显示下行速率。
 */
class RingView @JvmOverloads constructor(
    ctx: Context, attrs: AttributeSet? = null,
) : View(ctx, attrs) {

    var progress = 0f          // 0..1
        set(v) { field = v.coerceIn(0f, 1f); invalidate() }
    var label = "下行速率"
        set(v) { field = v; invalidate() }
    var value = "0.00"
        set(v) { field = v; invalidate() }
    var unit = "MB/s"
        set(v) { field = v; invalidate() }
    var accent = Color.parseColor("#38F0C6")
        set(v) { field = v; invalidate() }

    private val track = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = dp(9f)
        strokeCap = Paint.Cap.ROUND
        color = Color.parseColor("#14FFFFFF")
    }
    private val arc = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = dp(9f)
        strokeCap = Paint.Cap.ROUND
    }
    private val tick = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        strokeWidth = dp(1f)
        color = Color.parseColor("#2EFFFFFF")
    }
    private val labelPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        textAlign = Paint.Align.CENTER
        typeface = Typeface.MONOSPACE
        textSize = dp(10f)
        letterSpacing = 0.16f
        color = Color.parseColor("#FF5A6875")
    }
    private val valuePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        textAlign = Paint.Align.CENTER
        typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)
        textSize = dp(34f)
        color = Color.parseColor("#FFE8EEF4")
    }

    private val rect = RectF()
    private val startAngle = 135f
    private val sweep = 270f

    private fun dp(v: Float) = v * resources.displayMetrics.density

    override fun onDraw(canvas: Canvas) {
        val size = min(width, height).toFloat()
        val cx = width / 2f
        val cy = height / 2f
        val pad = dp(16f)
        val r = (size - pad * 2 - dp(9f)) / 2f
        rect.set(cx - r, cy - r, cx + r, cy + r)

        // 刻度（每 270°/32，4 格一长）
        for (i in 0..32) {
            val a = Math.toRadians((startAngle + sweep / 32f * i).toDouble())
            val inner = r - dp(13f)
            val len = if (i % 4 == 0) dp(7f) else dp(3f)
            canvas.drawLine(
                cx + cos(a).toFloat() * inner, cy + sin(a).toFloat() * inner,
                cx + cos(a).toFloat() * (inner - len), cy + sin(a).toFloat() * (inner - len),
                tick,
            )
        }

        canvas.drawArc(rect, startAngle, sweep, false, track)

        arc.color = accent
        arc.setShadowLayer(dp(9f), 0f, 0f, accent)
        setLayerType(LAYER_TYPE_SOFTWARE, null)
        canvas.drawArc(rect, startAngle, sweep * progress, false, arc)
        arc.clearShadowLayer()

        // 中心文字
        val cyText = cy - dp(6f)
        canvas.drawText(label.uppercase(), cx, cyText - dp(6f), labelPaint)
        canvas.drawText(value, cx, cyText + dp(26f), valuePaint)

        val u = Paint(labelPaint).apply { textSize = dp(10f); color = Color.parseColor("#FF5A6875") }
        canvas.drawText(unit, cx, cyText + dp(44f), u)
    }
}
