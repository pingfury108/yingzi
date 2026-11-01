package io.yingzi.app

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.widget.ImageButton
import android.widget.ImageView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.button.MaterialButton

/** 配置分享：二维码 + 剪贴板导入导出 */
class ShareActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_share)
        val cfg = NodeConfig.load(this)
        val payload = ConfigShare.encode(cfg)

        findViewById<ImageButton>(R.id.back).setOnClickListener { finish() }
        findViewById<ImageView>(R.id.qr).setImageBitmap(ConfigShare.qr(payload, 720))
        findViewById<TextView>(R.id.summary).text =
            "${cfg.coordinator}\n出口 ${cfg.defaultExit} · 节点名 ${cfg.name}"

        findViewById<MaterialButton>(R.id.copy).setOnClickListener {
            val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            cm.setPrimaryClip(ClipData.newPlainText("yingzi 配置", payload))
            Toast.makeText(this, "已复制到剪贴板", Toast.LENGTH_SHORT).show()
        }

        findViewById<MaterialButton>(R.id.paste).setOnClickListener {
            val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val text = cm.primaryClip?.getItemAt(0)?.coerceToText(this)?.toString().orEmpty()
            if (text.isBlank()) {
                Toast.makeText(this, "剪贴板为空", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            val err = ConfigShare.import(this, text)
            if (err != null) {
                Toast.makeText(this, err, Toast.LENGTH_SHORT).show()
            } else {
                if (YzCore.nativeIsRunning()) {
                    startService(
                        Intent(this, YzVpnService::class.java).setAction(YzVpnService.ACTION_REBUILD)
                    )
                }
                Toast.makeText(this, "导入成功，已应用", Toast.LENGTH_SHORT).show()
                finish()
            }
        }
    }
}
