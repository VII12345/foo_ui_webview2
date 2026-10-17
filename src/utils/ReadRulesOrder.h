#pragma once
// ============================================
// ReadRulesOrder.h - 系统盘读取判定的单点实现
// ============================================
//
// 本头只依赖标准库，让 PathSecurity 与不链接 fb2k SDK 的测试使用同一份判定。
//
// 判定回答的问题是: 一条已解析、已确认在系统盘上的路径，读取放不放行、是哪一步
// 决定的。契约 (按此顺序):
//
//   1. 在白名单里 → 放行。
//   2. 否则在黑名单里 → 拒绝 (受保护的系统路径)。
//   3. 两者都不在 → 拒绝 (系统盘上不在白名单)。
//
// 白名单必须先判。便携安装的 profile 与安装目录都在白名单里；安装目录落在
// C:\Program Files\ 下时 profile 同时命中黑名单 (Program Files 整棵都在黑名单)。
// 黑名单先判会把用户自己的配置目录一并拒掉——主题要读的播放统计库就在那儿。
// 黑名单退为第 2 步的兜底：Windows\、System32\、ProgramData\ 都不在任何白名单里，
// 照旧走到第 2 步被拒，两种拒绝的文案也仍然分得开。
//
// 非系统盘不走这里 (调用方在此之前直接放行)，所以本头不接盘符参数。
//
// ============================================

namespace read_rules {

enum class Decision {
    // 白名单命中。
    Whitelist,
    // 不在白名单、但在黑名单：受保护的系统路径。
    ProtectedPath,
    // 两份名单都没有。
    NotInWhitelist,
};

inline Decision Decide(bool inWhitelist, bool inBlacklist) {
    if (inWhitelist) return Decision::Whitelist;
    if (inBlacklist) return Decision::ProtectedPath;
    return Decision::NotInWhitelist;
}

inline bool IsAdmitted(Decision decision) {
    return decision == Decision::Whitelist;
}

}  // namespace read_rules
