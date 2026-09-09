//! `kwm-migration` 插件入口：X8 NDJSON 服务环（format.migrate，network=false）。
//!
//! L3 高风险类：需主程序 ACK 闸确认后启用（PLUGIN_POLICY §3/§4）。
//! 仅处理用户合法持有的本地文件；术语为「本地格式迁移/备份」，绝不联网。

fn main() {
    // 名字必须与 plugins/kwm-migration/plugin.json 的 name 逐字节一致
    // （ACK 闸 / Host 清单核对 / config.acked 均以该名为键）
    // RFC2-T1：扩展名声明与 plugin.json 逐项一致（PLUGIN_POLICY §4）
    musicforge_format_plugins::serve(
        "kwm-migration",
        &["kwm"],
        musicforge_format_plugins::kwm::handler,
    );
}
