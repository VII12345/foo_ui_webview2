#pragma once
// ============================================
// WriteRulesOrder.h - 通用文件写入的入口判定
// ============================================
//
// 本头只依赖标准库，让 PathSecurity 与不链接 fb2k SDK 的测试使用同一份判定。
//
// 判定回答的问题是: 一条已解析的路径，file.* 写入是先被写白名单放行、作为受保护
// 系统路径拒绝，还是交给后面的信任来源继续判定。契约 (按此顺序):
//
//   1. 在写白名单里 → 放行。
//   2. 否则在黑名单里 → 拒绝 (受保护的系统路径)。
//   3. 两者都不在 → 继续 (监视目录、非系统卷、媒体库/播放列表)。
//
// 写白名单必须先判，理由与读取侧的 ReadRulesOrder.h 相同: 便携安装落在
// C:\Program Files\ 下时，profile (写白名单) 同时命中 Program Files (黑名单)。
// 黑名单先判会让主题永远写不了自己的 profile 数据——播放统计与自定义测量档案
// 都存在那里。黑名单退为第 2 步的兜底，仍然先于后面所有信任来源: Windows\、
// System32\、ProgramData\ 不在任何白名单里，照旧被拒；监视目录内的 junction
// 若落到这些位置，解析后的对象也到不了第 3 步。
//
// 判定对象是已解析的 canonical 路径，调用方在解析之后传入。
//
// ============================================

namespace write_rules {

enum class EntryDecision {
    // 写白名单命中 (profile / temp)。
    WriteWhitelist,
    // 不在写白名单、但在黑名单: 受保护的系统路径。
    ProtectedPath,
    // 两份名单都没有，交给后续信任来源。
    Continue,
};

inline EntryDecision DecideFileWriteEntry(bool inWriteWhitelist, bool inBlacklist) {
    if (inWriteWhitelist) return EntryDecision::WriteWhitelist;
    if (inBlacklist) return EntryDecision::ProtectedPath;
    return EntryDecision::Continue;
}

inline bool IsAdmitted(EntryDecision decision) {
    return decision == EntryDecision::WriteWhitelist;
}

inline bool IsRefused(EntryDecision decision) {
    return decision == EntryDecision::ProtectedPath;
}

}  // namespace write_rules
