import XCTest
@testable import HBAISmartDNS

// Тесты чистой логики: систему не трогают (ни DNS, ни IPv6, ни пароля администратора).
// Запуск: swift test (на Mac или в GitHub Actions).
final class LogicTests: XCTestCase {

    // ---------- адреса ----------

    func testServiceAddresses() {
        XCTAssertEqual(Services.setOf("109.120.177.170"), 2)
        XCTAssertEqual(Services.setOf("45.88.163.92"), 2)
        XCTAssertEqual(Services.setOf("5.175.161.40"), 1)
        XCTAssertNil(Services.setOf("109.120.132.43"), "старый MagicDNS не выдаётся за сервис")
        XCTAssertEqual(Services.setOf("94.250.253.55"), 0)
        XCTAssertEqual(Services.setOf("212.109.195.93"), 0)
        XCTAssertEqual(Services.setOf("83.220.169.155"), 0, "прежний адрес Comss узнаётся")
        XCTAssertEqual(Services.setOf("111.88.96.50"), Services.xboxSet, "старый Xbox DNS узнаётся")
        XCTAssertNil(Services.setOf("192.168.1.1"))
        XCTAssertNil(Services.setOf("135.106.217.200"), "Astracat не выдаётся за сервис")
        XCTAssertNil(Services.setOf("193.233.112.67"), "российский GeoHide не выдаётся за сервис")
    }

    func testStaleAddresses() {
        XCTAssertTrue(Services.isStale("135.106.217.200"))
        XCTAssertTrue(Services.isStale("193.233.112.67"))
        XCTAssertTrue(Services.isStale("109.120.132.43"))
        XCTAssertTrue(Services.isStale("94.249.177.102"))
        XCTAssertTrue(Services.isStale("45.13.237.213"))
        XCTAssertFalse(Services.isStale("109.120.177.170"))
        XCTAssertFalse(Services.isStale("192.168.1.1"))
    }

    func testListsHaveSameLength() {
        for list in [Services.short, Services.opens, Services.site, Services.url] { XCTAssertEqual(list.count, Services.count) }
        XCTAssertEqual(Services.v4.count, Services.count)
        XCTAssertEqual(Services.name[Services.xboxSet], "Xbox DNS")
    }

    // ---------- проверка сайтов ----------

    func testDig() {
        XCTAssertEqual(Probe.parseDig("edge.cdn.net.\n1.2.3.4\n", timedOut: false), "1.2.3.4", "сначала CNAME, потом адрес")
        XCTAssertEqual(Probe.parseDig("", timedOut: false), "", "ответ без адреса")
        XCTAssertNil(Probe.parseDig(";; connection timed out; no servers could be reached", timedOut: false))
        XCTAssertNil(Probe.parseDig("", timedOut: true))
        XCTAssertEqual(Probe.verdict(nil), Probe.noDns)
        XCTAssertEqual(Probe.verdict("0.0.0.0"), Probe.zero)
        XCTAssertEqual(Probe.verdict(""), Probe.zero)
        XCTAssertNil(Probe.verdict("1.2.3.4"))
    }

    func testClassify() {
        XCTAssertEqual(Probe.classify("200 "), Probe.ok)
        XCTAssertEqual(Probe.classify("302 https://www.google.com/sorry/index"), Probe.captcha)
        XCTAssertEqual(Probe.classify("302 https://chatgpt.com/unsupported_country"), Probe.blocked)
        XCTAssertEqual(Probe.classify("302 https://x/Unsupported-Country"), Probe.blocked, "регистр не важен")
        XCTAssertEqual(Probe.classify("302 https://x/service-not-available"), Probe.blocked)
        XCTAssertEqual(Probe.classify("000 "), Probe.noLink)
    }

    private func res(_ ok: Int) -> [String] { (0..<6).map { $0 < ok ? Probe.ok : Probe.noLink } }

    func testBest() {
        XCTAssertEqual(Probe.best([res(5), res(4), res(6), nil], current: -1), 2, "больше сайтов")
        XCTAssertEqual(Probe.best([res(3), res(5), res(5), nil], current: -1), 1, "при равенстве — раньше в списке")
        XCTAssertEqual(Probe.best([res(5), res(3), res(5), nil], current: 2), 2, "при равенстве остаётся текущий")
        XCTAssertEqual(Probe.best([res(0), res(0), res(0), nil], current: 1), 1, "ничего не открывается — остаётся текущий")
        XCTAssertEqual(Probe.best([res(2), res(4), res(3), nil], current: Services.xboxSet), 1, "текущий Xbox не мешает")
        XCTAssertEqual(Probe.best([nil, res(0), res(0)], current: -1), 1, "непроверенный первым не выбирается")
    }

    // ---------- окно после включения ----------

    func testOutcome() {
        XCTAssertTrue(Model.reached(true, 2, 2))
        XCTAssertFalse(Model.reached(true, 2, 0), "хотели MagicDNS, а встал Comss")
        XCTAssertTrue(Model.reached(false, 2, nil))
        XCTAssertNil(Model.outcome(true, done: true, err: nil))
        XCTAssertEqual(Model.outcome(false, done: true, err: "IPv6"), "DNS выключен, но: IPv6")
        XCTAssertEqual(Model.outcome(true, done: false, err: "Отменено"), "Отменено")
        XCTAssertEqual(Model.outcome(true, done: false, err: nil), "Не получилось поменять DNS, попробуйте ещё раз")
    }

    // ---------- новая версия ----------

    func testUpdates() {
        XCTAssertEqual(Updates.tagOf("https://github.com/neiroseti-ai/hb-ai-xbox-dns/releases/tag/v1.23"), "1.23")
        XCTAssertNil(Updates.tagOf("https://github.com/login"))
        XCTAssertNil(Updates.tagOf(nil))
        XCTAssertTrue(Updates.isNewer("1.23", than: "1.22"))
        XCTAssertTrue(Updates.isNewer("1.3", than: "1.22"))
        XCTAssertFalse(Updates.isNewer("1.22", than: "1.22"))
        XCTAssertFalse(Updates.isNewer("1.21", than: "1.22"))
        XCTAssertFalse(Updates.isNewer("beta", than: "1.22"))
        XCTAssertFalse(Updates.isNewer("1,23", than: "1.22"))
    }

    // ---------- IPv6 и команды networksetup ----------

    func testParseInfo() {
        let auto = NetService.parse("Wi-Fi", "DHCP Configuration\nIP address: 192.168.1.5\nIPv6: Automatic\nIPv6 IP address: 2a02:2698:1::5\nIPv6 Router: fe80::1\n")
        XCTAssertEqual(auto, NetService(name: "Wi-Fi", ipv6Auto: true, hasGlobalIpv6: true))
        let linkOnly = NetService.parse("Wi-Fi", "IPv6: Automatic\nIPv6 IP address: none\n")
        XCTAssertFalse(linkOnly.hasGlobalIpv6)
        let off = NetService.parse("Wi-Fi", "IPv6: Off\n")
        XCTAssertFalse(off.ipv6Auto)
    }

    private let wifi6 = NetService(name: "Wi-Fi", ipv6Auto: true, hasGlobalIpv6: true)
    private let wifi4 = NetService(name: "Wi-Fi", ipv6Auto: true, hasGlobalIpv6: false)
    private let ns = "/usr/sbin/networksetup"
    private let flush = ["/usr/bin/dscacheutil -flushcache", "/usr/bin/killall -HUP mDNSResponder"]

    func testPlanWithoutIpv6() {
        let p = Dns.plan(set: 2, services: [wifi4], off: [])
        XCTAssertEqual(p.cmds, ["\(ns) -setdnsservers \"Wi-Fi\" 109.120.177.170 45.88.163.92"] + flush)
        XCTAssertEqual(p.off, [])
    }

    func testPlanTurnsIpv6OffAndRemembers() {
        let p = Dns.plan(set: 2, services: [wifi6], off: [])
        XCTAssertEqual(p.cmds, ["\(ns) -setdnsservers \"Wi-Fi\" 109.120.177.170 45.88.163.92", "\(ns) -setv6off \"Wi-Fi\""] + flush)
        XCTAssertEqual(p.off, ["Wi-Fi"])
    }

    func testPlanDisableRestoresOnlyRemembered() {
        let eth = NetService(name: "Ethernet", ipv6Auto: false, hasGlobalIpv6: false)   // IPv6 выключил сам человек
        let p = Dns.plan(set: nil, services: [NetService(name: "Wi-Fi", ipv6Auto: false, hasGlobalIpv6: false), eth], off: ["Wi-Fi"])
        XCTAssertEqual(p.cmds, ["\(ns) -setdnsservers \"Wi-Fi\" empty", "\(ns) -setdnsservers \"Ethernet\" empty",
                                "\(ns) -setv6automatic \"Wi-Fi\""] + flush)
        XCTAssertEqual(p.off, [])
    }

    func testPlanKeepsUnpluggedService() {
        let p = Dns.plan(set: nil, services: [wifi4], off: ["USB LAN"])
        XCTAssertFalse(p.cmds.contains { $0.contains("USB LAN") })
        XCTAssertEqual(p.off, ["USB LAN"], "служба пропала — запись остаётся до её возвращения")
    }

    func testPlanXboxRestoresIpv6() {
        let p = Dns.plan(set: Services.xboxSet, services: [NetService(name: "Wi-Fi", ipv6Auto: false, hasGlobalIpv6: false)], off: ["Wi-Fi"])
        XCTAssertTrue(p.cmds.contains("\(ns) -setv6automatic \"Wi-Fi\""))
        XCTAssertEqual(p.off, [])
    }

    func testPlanSwitchDoesNotTurnOffTwice() {
        let off = NetService(name: "Wi-Fi", ipv6Auto: false, hasGlobalIpv6: false)   // уже выключен программой
        let p = Dns.plan(set: 0, services: [off], off: ["Wi-Fi"])
        XCTAssertEqual(p.cmds, ["\(ns) -setdnsservers \"Wi-Fi\" 94.250.253.55 212.109.195.93"] + flush)
        XCTAssertEqual(p.off, ["Wi-Fi"])
    }

    func testQuote() {
        XCTAssertEqual(Dns.quote("Wi-Fi \"дом\""), "\"Wi-Fi \\\"дом\\\"\"")
    }
}
