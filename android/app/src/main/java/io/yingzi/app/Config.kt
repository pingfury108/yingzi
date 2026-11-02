package io.yingzi.app

import android.content.Context
import java.io.File

/**
 * 节点配置。当前为"首次运行内置默认值"，后续可做成设置页/二维码导入。
 * TODO(P6): 用 Keystore 加密保存 NS 与身份。
 */
data class NodeConfig(
    val networkSecret: String,
    val coordinator: String,
    val name: String,
    val defaultExit: String,
    val remoteDns: String,
    val directDns: String,
    val fakeIp: Boolean,
    val ipv6: Boolean,
) {
    companion object {
        // 与现有 6 节点同一网络（部署时生成）
        private const val DEFAULT_SECRET =
            "ce74e59db6980640c2a96376c629511a6c982d71f1fd4ac0dd2d575ea5f2fd06"

        fun load(ctx: Context): NodeConfig {
            val prefs = ctx.getSharedPreferences("yz", Context.MODE_PRIVATE)
            // 老版本默认名 "android" → 迁移成设备名，避免多台设备重名
            if (prefs.getString("name", null) == "android") {
                prefs.edit().putString("name", DeviceName.suggest(ctx)).apply()
            }
            // NS 优先从 Keystore 加密存储读取
            val secret = prefs.getString("secret_enc", null)
                ?.let { SecureStore.decrypt(ctx, it) }
                ?: prefs.getString("secret", null)
                ?: DEFAULT_SECRET
            return NodeConfig(
                networkSecret = secret,
                coordinator = prefs.getString("coordinator", "47.109.61.89:9000")!!,
                name = prefs.getString("name", null) ?: DeviceName.suggest(ctx),
                defaultExit = prefs.getString("exit", "overseas-hk")!!,
                remoteDns = prefs.getString("remoteDns", "exit://overseas-hk/1.1.1.1:53")!!,
                directDns = prefs.getString("directDns", "udp://223.5.5.5")!!,
                fakeIp = prefs.getBoolean("fakeIp", true),
                ipv6 = prefs.getBoolean("ipv6", false),
            )
        }

        /** 保存配置（NS 走 Keystore 加密） */
        fun save(
            ctx: Context,
            secret: String,
            coordinator: String,
            name: String,
            exit: String,
            remoteDns: String,
            directDns: String,
            fakeIp: Boolean = true,
            ipv6: Boolean = false,
        ) {
            ctx.getSharedPreferences("yz", Context.MODE_PRIVATE).edit().apply {
                putString("secret_enc", SecureStore.encrypt(ctx, secret))
                remove("secret") // 清掉明文
                putString("coordinator", coordinator)
                putString("name", name)
                putString("exit", exit)
                putString("remoteDns", remoteDns)
                putString("directDns", directDns)
                putBoolean("fakeIp", fakeIp)
                putBoolean("ipv6", ipv6)
                apply()
            }
        }

        /** 规则：广告拦截 + 国内直连 + 其余走默认出口 */
        fun rules(): List<String> = listOf(
            "geosite:category-ads-all=block",
            "geosite:cn=direct",
            "geoip:cn=direct",
            "geoip:private=direct",
        )

        fun geoipPath(ctx: Context): String = GeoData.geoip(ctx)
        fun geositePath(ctx: Context): String = GeoData.geosite(ctx)
    }
}
