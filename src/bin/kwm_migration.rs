//! `kwm-migration` 插件入口：X8 NDJSON 服务环（format.migrate，network=false）。
//!
//! L3 高风险类：需主程序 ACK 闸确认后启用（PLUGIN_POLICY §3/§4）。
//! 仅处理用户合法持有的本地文件；术语为「本地格式迁移/备份」，绝不联网。

fn main() {
    musicforge_format_plugins::serve(musicforge_format_plugins::kwm::handler);
}
