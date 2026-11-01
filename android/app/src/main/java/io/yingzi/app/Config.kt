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
) {
    companion object {
        // 与现有 6 节点同一网络（部署时生成）
        private const val DEFAULT_SECRET =
            "ce74e59db6980640c2a96376c629511a6c982d71f1fd4ac0dd2d575ea5f2fd06"

        fun load(ctx: Context): NodeConfig {
            val prefs = ctx.getSharedPreferences("yz", Context.MODE_PRIVATE)
            return NodeConfig(
                networkSecret = prefs.getString("secret", DEFAULT_SECRET)!!,
                coordinator = prefs.getString("coordinator", "47.109.61.89:9000")!!,
                name = prefs.getString("name", "android")!!,
                defaultExit = prefs.getString("exit", "overseas-hk")!!,
                remoteDns = prefs.getString("remoteDns", "exit://overseas-hk/1.1.1.1:53")!!,
                directDns = prefs.getString("directDns", "udp://223.5.5.5")!!,
            )
        }

        /** 规则：广告拦截 + 国内直连 + 其余走默认出口 */
        fun rules(): List<String> = listOf(
            "geosite:category-ads-all=block",
            "geosite:cn=direct",
            "geoip:cn=direct",
            "geoip:private=direct",
        )

        fun geoipPath(ctx: Context): String = assetToFile(ctx, "geoip.dat")
        fun geositePath(ctx: Context): String = assetToFile(ctx, "geosite.dat")

        /** 把 asset 里的 geo 数据解压到 files 目录（首次启动） */
        private fun assetToFile(ctx: Context, name: String): String {
            val out = File(ctx.filesDir, name)
            if (out.exists() && out.length() > 0) return out.absolutePath
            try {
                ctx.assets.open(name).use { input ->
                    out.outputStream().use { output -> input.copyTo(output) }
                }
            } catch (_: Exception) {
                // 没有内置数据时返回空路径（核心会跳过 geo 规则）
                return ""
            }
            return out.absolutePath
        }
    }
}
