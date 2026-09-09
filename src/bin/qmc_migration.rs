//! `qmc-migration` 插件入口：X8 NDJSON 服务环（format.migrate，network=false）。
//!
//! L3 高风险类：需主程序 ACK 闸确认后启用（PLUGIN_POLICY §3/§4）。
//! 变体分级见 `qmc.rs` 模块文档（静态表可迁移；STag/QTag 尾标变体 = 账号绑定
//! DRM，仅识别报告）。仅处理用户合法持有的本地文件；绝不联网、绝不改源。

fn main() {
    // 名字必须与 plugins/qmc-migration/plugin.json 的 name 逐字节一致
    // （ACK 闸 / Host 清单核对 / config.acked 均以该名为键）。
    // 扩展名声明与 plugin.json 逐项一致（PLUGIN_POLICY §4 按格式申报；
    // 含 STag/QTag 尾标系——识别也是能力，迁移层显式报告）。
    musicforge_format_plugins::serve(
        "qmc-migration",
        &[
            // 静态表变体（可直接迁移；mflac/mgg 无数字形态按附录 D 归静态表）
            "qmc0", "qmc3", "qmcmp3", "bkcmp3", // → mp3
            "qmcflac", "qmflac", "mflac", "bkcflac", // → flac
            "qmc2", "qmcogg", "mgg", // → ogg
            // 尾标系扩展名（STag/QTag：requires_ekey=true；migrate 层显式报告）
            "mflac0", "mflac1", "mgg0", "mgg1", "mggl",
        ],
        musicforge_format_plugins::qmc::handler,
    );
}
