package io.yingzi.app

import android.content.Intent
import android.os.Bundle
import android.widget.EditText
import android.widget.ImageButton
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.button.MaterialButton

class SettingsActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)

        val cfg = NodeConfig.load(this)
        findViewById<EditText>(R.id.coordinator).setText(cfg.coordinator)
        findViewById<EditText>(R.id.name).setText(cfg.name)
        findViewById<EditText>(R.id.exit).setText(cfg.defaultExit)
        findViewById<EditText>(R.id.remoteDns).setText(cfg.remoteDns)
        findViewById<EditText>(R.id.directDns).setText(cfg.directDns)

        findViewById<ImageButton>(R.id.back).setOnClickListener { finish() }
        findViewById<android.view.View>(R.id.appsRow).setOnClickListener {
            startActivity(Intent(this, AppsActivity::class.java))
        }

        findViewById<MaterialButton>(R.id.save).setOnClickListener {
            val secretInput = findViewById<EditText>(R.id.secret).text.toString().trim()
            NodeConfig.save(
                this,
                secret = if (secretInput.isEmpty()) cfg.networkSecret else secretInput,
                coordinator = findViewById<EditText>(R.id.coordinator).text.toString().trim(),
                name = findViewById<EditText>(R.id.name).text.toString().trim(),
                exit = findViewById<EditText>(R.id.exit).text.toString().trim(),
                remoteDns = findViewById<EditText>(R.id.remoteDns).text.toString().trim(),
                directDns = findViewById<EditText>(R.id.directDns).text.toString().trim(),
            )
            if (YzCore.nativeIsRunning()) {
                startService(Intent(this, YzVpnService::class.java).setAction(YzVpnService.ACTION_RESTART))
            }
            Toast.makeText(this, "已保存", Toast.LENGTH_SHORT).show()
            finish()
        }
    }

    override fun onResume() {
        super.onResume()
        val mode = when (AppRules.mode(this)) {
            AppRules.INCLUDE -> "仅代理选中应用"
            AppRules.EXCLUDE -> "排除选中应用"
            else -> "全局代理"
        }
        val n = AppRules.selected(this).size
        findViewById<android.widget.TextView>(R.id.appsMode).text = mode
        findViewById<android.widget.TextView>(R.id.appsSub).text =
            if (AppRules.mode(this) == AppRules.GLOBAL) "所有应用走 VPN" else "已选 $n 个应用"
    }
}
