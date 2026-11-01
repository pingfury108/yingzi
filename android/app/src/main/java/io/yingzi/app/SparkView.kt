package io.yingzi.app

import android.content.Context
import android.graphics.*
import android.util.AttributeSet
import android.view.View

/**
 * 实时速率面积图：平滑曲线 + 渐变填充 + 末端光点。
 * 数据由外部 push(值) 追加，保留固定窗口。
 */
class SparkView @JvmOverloads constructor(
    ctx: Context, attrs: AttributeSet? = null,
) : View(ctx, attrs) {

    private val window = 45
    private val data = ArrayDeque<Float>()
    var accent = Color.parseColor("#38F0C6")
        set(v) { field = v; linePaint.color = v; dotPaint.color = v; buildShader(); invalidate() }

    private val linePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = dp(1.6f)
        strokeCap = Paint.Cap.ROUND
        strokeJoin = Paint.Join.ROUND
        color = accent
    }
    private val fillPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.FILL }
    private val dotPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = accent }
    private val path = Path()
    private val fillPath = Path()

    private fun dp(v: Float) = v * resources.displayMetrics.density

    private fun buildShader() {
        fillPaint.shader = LinearGradient(
            0f, 0f, 0f, height.toFloat().coerceAtLeast(1f),
            intArrayOf(withAlpha(accent, 72), withAlpha(accent, 0)),
            floatArrayOf(0f, 1f), Shader.TileMode.CLAMP,
        )
    }

    private fun withAlpha(c: Int, a: Int) = Color.argb(a, Color.red(c), Color.green(c), Color.blue(c))

    fun push(v: Float) {
        data.addLast(v)
        while (data.size > window) data.removeFirst()
        invalidate()
    }

    fun reset() {
        data.clear()
        invalidate()
    }

    override fun onSizeChanged(w: Int, h: Int, ow: Int, oh: Int) {
        super.onSizeChanged(w, h, ow, oh)
        buildShader()
    }

    override fun onDraw(canvas: Canvas) {
        if (data.size < 2) return
        val n = data.size
        val max = (data.maxOrNull() ?: 1f) * 1.15f
        val stepX = width.toFloat() / (n - 1)
        val pad = dp(3f)

        val pts = ArrayList<PointF>(n)
        data.forEachIndexed { i, v ->
            val x = i * stepX
            val y = height - pad - (v / max) * (height - pad * 2)
            pts.add(PointF(x, y))
        }

        path.reset()
        fillPath.reset()
        path.moveTo(pts[0].x, pts[0].y)
        for (i in 0 until n - 1) {
            val p1 = pts[i]
            val p2 = pts[i + 1]
            val mx = (p1.x + p2.x) / 2
            path.cubicTo(mx, p1.y, mx, p2.y, p2.x, p2.y)
        }
        fillPath.addPath(path)
        fillPath.lineTo(pts[n - 1].x, height.toFloat())
        fillPath.lineTo(0f, height.toFloat())
        fillPath.close()

        canvas.drawPath(fillPath, fillPaint)
        canvas.drawPath(path, linePaint)
        canvas.drawCircle(pts[n - 1].x - dp(1f), pts[n - 1].y, dp(2.6f), dotPaint)
    }
}
