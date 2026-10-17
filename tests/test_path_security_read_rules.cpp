// test_path_security_read_rules.cpp - system-drive read decisions and their order
//
// Pins the ordering inside PathSecurity::ApplyReadRules for system-drive paths.
// The decision itself lives in src/utils/ReadRulesOrder.h so that this test
// exercises the production code rather than a copy of it.
//
// A portable foobar2000 install puts its profile under the install directory,
// which can itself sit under C:\Program Files\. Both the profile and the
// portable install dir are whitelisted (InitializeWhitelist), and
// C:\Program Files\ is also blacklisted (InitializeBlacklist). When the
// blacklist decides first, that overlap refuses every read of the user's own
// configuration - including the stats database the theme reads. The whitelist
// therefore has to decide first, with the blacklist demoted to a backstop for
// system-drive paths that are in neither list.
//
// The decision enum is what keeps this observable: for a path that is both
// whitelisted and blacklisted, either order can be made to return "admitted",
// so only the deciding step proves the order. Windows\, System32\ and
// ProgramData\ are in no whitelist, so they still reach the blacklist and are
// still refused with the protected-path message; a path in neither list keeps
// the not-in-whitelist message, so the two refusals stay distinguishable.
//
// The real PathSecurity singleton constructor depends on core_api (profile /
// install paths, library_manager), so it is not unit-testable here. The
// ordering contract is therefore extracted into the SDK-free header, following
// the convention of test_path_security_traversal.cpp and
// test_path_security_unc_bypass.cpp.
//
// Mirrored production code (src/domain/PathSecurity.cpp): ApplyReadRules
// delegates its system-drive step to read_rules::Decide. Whenever that header
// changes, this file must be updated in the same change.
#include "pch.h"
#include "../src/utils/ReadRulesOrder.h"

namespace {

using read_rules::Decide;
using read_rules::Decision;
using read_rules::IsAdmitted;

} // namespace

// ============================================
// The portable-profile overlap
// ============================================

TEST(PathSecurityReadRules, PortableProfileUnderProgramFilesIsReadable) {
    // C:\Program Files\foobar2000\profile\foo_monthly_stats.db: profile and
    // portable install dir are whitelisted, C:\Program Files\ is blacklisted.
    EXPECT_EQ(Decide(/*inWhitelist=*/true, /*inBlacklist=*/true), Decision::Whitelist);
    EXPECT_TRUE(IsAdmitted(Decide(true, true)));
}

TEST(PathSecurityReadRules, TheOverlapIsDecidedByTheWhitelistNotTheBlacklist) {
    // The deciding step is the whole assertion: flipping the order would still
    // deny, but for the wrong reason and with the wrong message.
    EXPECT_NE(Decide(true, true), Decision::ProtectedPath);
    EXPECT_NE(Decide(true, true), Decision::NotInWhitelist);
}

TEST(PathSecurityReadRules, ProtectedPathsInNoWhitelistAreStillRefused) {
    // Windows\, System32\ and ProgramData\ are blacklisted and whitelisted by
    // nothing, so they still land on the blacklist step.
    EXPECT_EQ(Decide(/*inWhitelist=*/false, /*inBlacklist=*/true), Decision::ProtectedPath);
    EXPECT_FALSE(IsAdmitted(Decide(false, true)));
}

TEST(PathSecurityReadRules, SystemDrivePathInNeitherListKeepsItsOwnMessage) {
    // The two refusals stay distinguishable: this one never hits the blacklist.
    EXPECT_EQ(Decide(false, false), Decision::NotInWhitelist);
    EXPECT_FALSE(IsAdmitted(Decide(false, false)));
}

TEST(PathSecurityReadRules, WhiteListedPathThatIsNotBlacklistedIsAdmitted) {
    // The ordinary profile case: whitelisted, nothing blacklisted it.
    EXPECT_EQ(Decide(true, false), Decision::Whitelist);
    EXPECT_TRUE(IsAdmitted(Decide(true, false)));
}

// ============================================
// The header keeps the reviewed order
// ============================================

TEST(PathSecurityReadRules, OnlyTheWhitelistAdmits) {
    // IsAdmitted is the single predicate callers branch on; keeping it tied to
    // the whitelist step means a future step cannot admit silently.
    EXPECT_TRUE(IsAdmitted(Decision::Whitelist));
    EXPECT_FALSE(IsAdmitted(Decision::ProtectedPath));
    EXPECT_FALSE(IsAdmitted(Decision::NotInWhitelist));
}
