package io.yingzi.app

/** Rust 核心的 JNI 桥 */
object YzCore {
    init { System.loadLibrary("yz_android") }

    external fun nativeStart(configJson: String, vpnService: Any): String
    external fun nativeStop(): String
    external fun nativeStatus(): String
    external fun nativeEvents(): String
    external fun nativeSetRules(json: String): Boolean
    external fun nativeIsRunning(): Boolean
    external fun nativePushEvent(level: String, msg: String)
    external fun nativeDiagnose(): String
}
