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
}
