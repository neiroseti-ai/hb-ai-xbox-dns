import XCTest
import CoreText
@testable import HBAISmartDNS

// Тесты чистой логики: систему не трогают (ни DNS, ни IPv6, ни пароля администратора).
// Запуск: swift test (на Mac или в GitHub Actions).
final class LogicTests: XCTestCase {

    // ---------- адреса ----------

    func testServiceAddresses() {
        XCTAssertNil(Services.setOf("217.144.190.216"))
        XCTAssertNil(Services.setOf("109.120.187.249"))
        XCTAssertNil(Services.setOf("109.120.177.170"), "адреса MagicDNS из 1.23–1.24 за сервис не выдаются: сервис с них переехал")
        XCTAssertNil(Services.setOf("45.88.163.92"))
        XCTAssertEqual(Services.setOf("153.80.200.170").map { Services.name[$0] }, "Перевал")
        for ip in ["179.236.130.10", "179.236.130.11", "31.31.207.68"] {
            XCTAssertNil(Services.setOf(ip), "Geodema и WebShift в программу не взяты: приложение к платному VPN")
            XCTAssertFalse(Services.isStale(ip))
        }
        XCTAssertEqual(Services.name, ["GeoHide", "Перевал", "Xbox DNS"])
        for (k, ips) in Services.v4.enumerated() {
            XCTAssertFalse(ips.isEmpty, "у сервиса \(Services.name[k]) есть адрес")
            for ip in ips {
                XCTAssertEqual(Services.setOf(ip), k, "адрес \(ip) узнаётся как адрес своего сервиса")
                XCTAssertFalse(Services.isStale(ip), "рабочий адрес \(ip) не помечен как старый")
            }
        }
        XCTAssertEqual(Set(Services.v4.flatMap { $0 }).count, Services.v4.flatMap { $0 }.count, "ни один адрес не принадлежит двум сервисам")
        XCTAssertNil(Services.setOf("143.20.64.192"))
        XCTAssertNil(Services.setOf("5.175.161.40"))
        XCTAssertEqual(Services.name[0], "GeoHide", "первым стоит сервис для нейросетей")
        XCTAssertNil(Services.setOf("109.120.132.43"), "старый MagicDNS не выдаётся за сервис")
        XCTAssertNil(Services.setOf("94.250.253.55"), "Comss не выдаётся за сервис: нейросети он больше не открывает")
        XCTAssertNil(Services.setOf("212.109.195.93"))
        XCTAssertNil(Services.setOf("83.220.169.155"), "прежний адрес Comss тоже")
        XCTAssertEqual(Services.setOf("111.88.96.50"), Services.xboxSet, "старый Xbox DNS узнаётся")
        XCTAssertNil(Services.setOf("192.168.1.1"))
        XCTAssertNil(Services.setOf("135.106.217.200"), "Astracat не выдаётся за сервис")
        XCTAssertEqual(Services.v4[0], ["193.233.112.88", "37.230.192.51"])
    }

    func testStaleAddresses() {
        XCTAssertTrue(Services.isStale("135.106.217.200"))
        XCTAssertFalse(Services.isStale("193.233.112.67"))
        XCTAssertTrue(Services.isStale("109.120.132.43"))
        XCTAssertTrue(Services.isStale("94.249.177.102"))
        XCTAssertTrue(Services.isStale("45.13.237.213"))
        XCTAssertTrue(Services.isStale("94.250.253.55"), "адреса Comss помечены как старые")
        XCTAssertTrue(Services.isStale("212.109.195.93"))
        XCTAssertTrue(Services.isStale("83.220.169.155"))
        XCTAssertTrue(Services.isStale("143.20.64.192"))
        XCTAssertTrue(Services.isStale("5.175.161.40"))
        XCTAssertTrue(Services.isStale("109.120.177.170"), "адреса MagicDNS из 1.23–1.24 помечены как старые")
        XCTAssertTrue(Services.isStale("45.88.163.92"))
        XCTAssertTrue(Services.isStale("217.144.190.216"))
        XCTAssertFalse(Services.isStale("192.168.1.1"))
    }

    func testListsHaveSameLength() {
        for list in [Services.short, Services.opens, Services.site, Services.url] { XCTAssertEqual(list.count, Services.count) }
        XCTAssertEqual(Services.v4.count, Services.count)
        XCTAssertEqual(Services.name[Services.xboxSet], "Xbox DNS")
        XCTAssertEqual(Probe.label.count, Probe.host.count)
        XCTAssertEqual(Probe.owner.count, Probe.host.count)
        XCTAssertEqual(Set(Probe.host).count, Probe.host.count, "сайты не повторяются")
        XCTAssertEqual(Array(Probe.label.prefix(6)), ["ChatGPT", "Claude", "Gemini", "ElevenLabs", "Grok", "Perplexity"], "первые шесть — как раньше")
        XCTAssertEqual(Probe.host[site("Copilot")], "copilot.com", "Copilot проверяется по имени, куда переадресует copilot.microsoft.com")
    }

    // Шрифты окна: имя, которое просит программа, должно быть записано в файле. С первой версии для Mac (1.2) по 1.24 программа просила
    // «Unbounded-ExtraBold» и «Manrope-…» (имена файлов), таких шрифтов нет, и окно рисовалось системным.
    func testFontNamesMatchFiles() {
        let res = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent("res")
        var found: [String] = []
        for file in ["Unbounded-ExtraBold.ttf", "Manrope-Bold.ttf", "Manrope-Medium.ttf"] {
            let list = CTFontManagerCreateFontDescriptorsFromURL(res.appendingPathComponent(file) as CFURL) as? [CTFontDescriptor] ?? []
            XCTAssertEqual(list.count, 1, file)
            for d in list {
                if let name = CTFontDescriptorCopyAttribute(d, kCTFontNameAttribute) as? String { found.append(name) }
            }
        }
        XCTAssertEqual(found, Fonts.names, "шрифт просят по имени из файла, иначе окно рисуется системным")
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

    func testRefused() {
        XCTAssertTrue(Probe.refused(";; ->>HEADER<<- opcode: QUERY, status: REFUSED, id: 1"), "отказ — не «адреса нет»")
        XCTAssertTrue(Probe.refused(";; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 2"))
        XCTAssertFalse(Probe.refused(";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 3"), "ответ без адресов")
        XCTAssertFalse(Probe.refused(";; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 4"), "такого имени нет")
        XCTAssertFalse(Probe.refused(""), "заголовка нет — считаем, что отказа не было")
    }

    func testDigAll() {
        XCTAssertEqual(Probe.parseDigAll("8.47.69.0\n8.6.112.0\n", timedOut: false), ["8.47.69.0", "8.6.112.0"], "оба адреса, по порядку")
        XCTAssertEqual(Probe.parseDig("8.47.69.0\n8.6.112.0\n", timedOut: false), "8.47.69.0", "первым считается первый")
        XCTAssertEqual(Probe.parseDigAll("edge.cdn.net.\n1.2.3.4\n", timedOut: false), ["1.2.3.4"], "CNAME — не адрес")
        XCTAssertEqual(Probe.parseDigAll("", timedOut: false), [], "ответ без адресов — пустой список")
        XCTAssertNil(Probe.parseDigAll("", timedOut: true))
        XCTAssertNil(Probe.parseDigAll(";; connection timed out; no servers could be reached", timedOut: false))
    }

    // ---------- сверка с обычными DNS: подменяет ли сервис адрес сайта ----------

    func testThrough() {
        let real: Set<String> = ["8.47.69.0", "8.6.112.0"]
        XCTAssertEqual(Probe.through(Probe.ok, "8.6.112.0", real), Probe.direct, "настоящий адрес — «напрямую», а не «открывается»")
        XCTAssertEqual(Probe.through(Probe.ok, "143.20.64.192", real), Probe.ok, "сервис подменил адрес — «открывается»")
        XCTAssertEqual(Probe.through(Probe.blocked, "8.6.112.0", real), Probe.blocked, "блок страны сайт назвал сам")
        XCTAssertEqual(Probe.through(Probe.noLink, "8.6.112.0", real), Probe.noLink)
        XCTAssertEqual(Probe.through(Probe.captcha, "8.6.112.0", real), Probe.captcha)
        XCTAssertEqual(Probe.through(Probe.ok, "8.6.112.0", []), Probe.ok, "сверять не с чем — верим ответу сайта")
        XCTAssertEqual(Probe.through(Probe.ok, "8.47.69.5", real), Probe.direct, "адрес из той же сети /24 — тоже настоящий")
        XCTAssertEqual(Probe.through(Probe.ok, "8.47.70.5", real), Probe.ok, "соседняя сеть — уже не настоящий")
        XCTAssertEqual(Probe.through(Probe.ok, "8.9.9.9", real), Probe.ok, "совпало только первое число — не настоящий")
        XCTAssertEqual(Probe.net24("160.79.104.10"), "160.79.104")
    }

    func testReachTriesNextNode() {
        let real: Set<String> = ["8.47.69.0", "8.6.112.0"]
        let two = ["143.20.64.192", "5.175.161.40"]
        var asked: [String] = []
        let secondAlive: (String, String) -> String = { _, ip in asked.append(ip); return ip == "5.175.161.40" ? Probe.ok : Probe.noLink }
        XCTAssertEqual(Probe.reach("claude.ai", two, real, ask: secondAlive), Probe.ok, "первый узел молчит, второй открывает")
        XCTAssertEqual(asked, two, "узлы спрашиваются по порядку")
        XCTAssertEqual(Probe.reach("claude.ai", two, real, ask: { _, _ in Probe.noLink }), Probe.noLink, "не отвечает ни один узел")
        XCTAssertEqual(Probe.reach("claude.ai", two, real, ask: { _, ip in ip == "143.20.64.192" ? Probe.blocked : Probe.ok }), Probe.blocked,
                       "берётся первый узел со связью, а не лучший ответ")
        XCTAssertEqual(Probe.reach("chatgpt.com", ["8.47.69.0", "8.6.112.0"], real, ask: { _, ip in ip == "8.6.112.0" ? Probe.ok : Probe.noLink }), Probe.direct,
                       "настоящий адрес после мёртвого — всё равно «напрямую»")
        XCTAssertEqual(Probe.reach("claude.ai", [], real, ask: { _, _ in Probe.ok }), Probe.noLink, "адресов нет")
        var count = 0
        _ = Probe.reach("claude.ai", ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5", "6.6.6.6"], real, ask: { _, _ in count += 1; return Probe.noLink })
        XCTAssertEqual(count, Probe.tries, "спрашиваем не больше tries узлов")
    }

    func testDirectIsNotGood() {
        let direct = Array(repeating: Probe.direct, count: Probe.host.count)
        XCTAssertEqual(Probe.good(direct), 0, "«напрямую» не считается открывшимся сайтом")
        XCTAssertEqual(Probe.best([direct, res(1), nil], current: 0), 1, "сервис, который всё пропускает, проигрывает")
        XCTAssertEqual(Set(Probe.control).count, 3, "сверка у трёх разных DNS")
        XCTAssertFalse(Probe.control.contains { Services.setOf($0) != nil || Services.isStale($0) }, "сервисы программы в сверку не попали")
    }

    func testClassify() {
        XCTAssertEqual(Probe.classify("200 "), Probe.ok)
        XCTAssertEqual(Probe.classify("302 https://www.google.com/sorry/index"), Probe.captcha)
        XCTAssertEqual(Probe.classify("302 https://chatgpt.com/unsupported_country"), Probe.blocked)
        XCTAssertEqual(Probe.classify("302 https://x/Unsupported-Country"), Probe.blocked, "регистр не важен")
        XCTAssertEqual(Probe.classify("302 https://x/service-not-available"), Probe.blocked)
        XCTAssertEqual(Probe.classify("000 "), Probe.noLink)
        XCTAssertEqual(Probe.classify("503 "), Probe.noLink, "сайт или прокси не справился — нет связи, а не «открывается»")
        XCTAssertEqual(Probe.classify("502 "), Probe.noLink)
        XCTAssertEqual(Probe.classify("451 "), Probe.blocked, "отказ по закону")
        XCTAssertEqual(Probe.classify("403 "), Probe.ok, "403 без слов о стране — так отвечает Claude до входа")
        XCTAssertEqual(Probe.classify("421 "), Probe.ok, "так отвечает корень api.openai.com через прокси")
        XCTAssertEqual(Probe.classify("302 https://example.com/page-5"), Probe.ok, "пятёрка не в начале — не код 5xx")
        XCTAssertEqual(Probe.classify(""), Probe.noLink, "curl ничего не вывел")
    }

    private func res(_ ok: Int) -> [String] { (0..<Probe.host.count).map { $0 < ok ? Probe.ok : Probe.noLink } }
    private func site(_ label: String) -> Int { Probe.label.firstIndex(of: label)! }

    /// Ответы сервиса по подписям сайтов; про остальные сайты сервис молчит.
    private func answers(_ pairs: [String: [String]]) -> [[String]?] {
        var ips = [[String]?](repeating: nil, count: Probe.host.count)
        for (label, list) in pairs { ips[site(label)] = list }
        return ips
    }

    /// Как в программе: два сервиса для нейросетей и Xbox, который не проверяется (nil).
    private func choices(_ a: Int, _ b: Int) -> [[String]?] { [res(a), res(b), nil] }

    func testBest() {
        XCTAssertNil(choices(0, 0)[Services.xboxSet], "в этом наборе Xbox — непроверенный")
        XCTAssertEqual(Probe.best(choices(4, 6), current: -1), 1, "больше сайтов")
        XCTAssertEqual(Probe.best(choices(5, 5), current: -1), 0, "при равенстве — раньше в списке")
        XCTAssertEqual(Probe.best(choices(5, 5), current: 1), 1, "при равенстве остаётся текущий")
        XCTAssertEqual(Probe.best(choices(0, 0), current: 1), 1, "ничего не открывается — остаётся текущий")
        XCTAssertEqual(Probe.best(choices(2, 4), current: Services.xboxSet), 1, "текущий Xbox не мешает")
        XCTAssertEqual(Probe.best(choices(0, 0), current: Services.xboxSet), 0, "текущий Xbox и ничего не открывается — первый проверенный, не Xbox")
        XCTAssertEqual(Probe.best([nil, res(0), res(0)], current: -1), 1, "непроверенный первым не выбирается")
    }

    func testBestKeepsCurrentForOneSite() {
        XCTAssertEqual(Probe.best(choices(11, 12), current: 0, margin: 2), 0, "DNS включён, лучший обогнал на один сайт — остаёмся")
        XCTAssertEqual(Probe.best(choices(11, 13), current: 0, margin: 2), 1, "обогнал на два — переключаемся")
        XCTAssertEqual(Probe.best(choices(11, 12), current: 0, margin: 1), 1, "DNS выключен — переключаемся и из-за одного сайта")
        XCTAssertEqual(Probe.best(choices(0, 1), current: 0, margin: 2), 1, "текущий не открывает ничего — уходим")
        XCTAssertEqual(Probe.best(choices(11, 12), current: 1, margin: 2), 1, "текущий сам лучший — остаётся")
        XCTAssertEqual(Probe.best(choices(9, 13), current: 0, margin: 2), 1, "среди обогнавших выбирается самый лучший")
        XCTAssertEqual(Probe.best(choices(13, 12), current: 1, margin: 2), 1, "текущий отстал на один сайт от первого в списке — остаётся")
    }

    func testBestNote() {
        let n = Probe.host.count
        XCTAssertEqual(Probe.bestNote(choices(11, 12), best: 1, top: 1), "Лучший сейчас: Перевал (12 из \(n))")
        XCTAssertEqual(Probe.bestNote(choices(11, 12), best: 0, top: 1), "Оставили GeoHide (11 из \(n)): у Перевал всего на сайт больше")
        XCTAssertEqual(Probe.bestNote(choices(12, 12), best: 1, top: 0), "Лучший сейчас: Перевал (12 из \(n))", "при равенстве текущий и назван лучшим")
        XCTAssertEqual(Probe.bestNote(choices(0, 0), best: 0, top: 0), "Сейчас ни один сервис не открывает нейросети")
    }

    // ---------- вторая сверка: прокси сервиса — адрес, отданный на сайты разных владельцев ----------

    func testShared() {
        XCTAssertEqual(Probe.shared(answers(["ChatGPT": ["179.236.130.10"], "Claude": ["179.236.130.10"]])), ["179.236.130"], "два владельца — прокси")
        XCTAssertEqual(Probe.shared(answers(["Gemini": ["142.250.154.101"], "NotebookLM": ["142.250.154.102"], "AI Studio": ["142.250.154.113"]])), [],
                       "только сайты Google — не прокси")
        XCTAssertEqual(Probe.shared(answers(["ChatGPT": ["5.175.161.3"], "Grok": ["5.175.161.40"]])).count, 1, "разные адреса одной сети /24 — один прокси")
        XCTAssertTrue(Probe.shared(answers(["ChatGPT": ["1.1.1.1", "5.175.161.3"], "Grok": ["2.2.2.2", "5.175.161.40"]])).contains("5.175.161"),
                      "смотрим все адреса ответа, а не только первый")
        XCTAssertEqual(Probe.shared(answers([:])), [], "сервис ни на что не ответил")
        for l in ["Gemini", "NotebookLM", "AI Studio"] { XCTAssertEqual(Probe.owner[site(l)], "Google") }
        for l in ["ChatGPT", "Sora", "API OpenAI"] { XCTAssertEqual(Probe.owner[site(l)], "OpenAI") }
        XCTAssertEqual(Probe.owner[site("Claude")], Probe.owner[site("API Claude")])
        XCTAssertNotEqual(Probe.owner[site("Claude")], "OpenAI")
    }

    func testKnown() {
        let proxy: Set<String> = ["179.236.130"], google: Set<String> = ["142.251.1.100"]
        XCTAssertTrue(Probe.known(google, ["142.250.154.101"], proxy).contains("142.250.154.101"), "адрес не из прокси — настоящий")
        XCTAssertFalse(Probe.known(google, ["179.236.130.10"], proxy).contains("179.236.130.10"), "адрес прокси настоящим не становится")
        XCTAssertTrue(Probe.known(google, ["179.236.130.10"], proxy).contains("142.251.1.100"), "ответы обычных DNS остаются")
        XCTAssertEqual(Probe.known(google, nil, proxy), google, "сервис промолчал — только ответы обычных DNS")
    }

    func testVerdictsLikeGeodema() {
        // 14.11.2026: Geodema сайты Google не подменяет и отдал для AI Studio настоящий адрес из сети, которую обычные DNS не назвали
        let google: Set<String> = ["142.251.1.100"]
        let res = Probe.verdicts(answers(["ChatGPT": ["179.236.130.10"], "Claude": ["179.236.130.10"], "AI Studio": ["142.250.154.101"]]),
                                 real: { $0 == "aistudio.google.com" ? google : [] }, ask: { _, _ in Probe.ok })
        XCTAssertEqual(res.count, Probe.host.count)
        XCTAssertEqual(res[site("AI Studio")], Probe.direct, "настоящий адрес Google — «напрямую», а не «открывается»")
        XCTAssertEqual(res[site("ChatGPT")], Probe.ok)
        XCTAssertEqual(res[site("Claude")], Probe.ok)
        XCTAssertEqual(res[site("Grok")], Probe.noDns, "про Grok сервис промолчал")
    }

    func testVerdictsOtherCases() {
        let silent: (String) -> Set<String> = { _ in [] }
        let opens: (String, String) -> String = { _, _ in Probe.ok }
        XCTAssertEqual(Probe.verdicts(answers(["ChatGPT": ["179.236.130.10"], "Claude": ["179.236.130.10"], "Spotify": ["151.101.67.42"]]),
                                      real: silent, ask: opens)[site("Spotify")], Probe.direct,
                       "обычные DNS молчат, но адрес отдан только одному сайту — «напрямую»")
        let cf = Probe.verdicts(answers(["ChatGPT": ["8.47.69.0"], "Grok": ["8.47.69.0"]]), real: { _ in ["8.47.69.0"] }, ask: opens)
        XCTAssertEqual(cf[site("ChatGPT")], Probe.direct, "общий адрес Cloudflare, названный обычными DNS, — «напрямую»")
        XCTAssertEqual(cf[site("Grok")], Probe.direct)
        let one = Probe.verdicts(answers(["ChatGPT": ["8.47.69.0"], "Grok": ["8.47.69.0"]]), real: { $0 == "grok.com" ? ["8.47.69.0"] : [] }, ask: opens)
        XCTAssertEqual([one[site("ChatGPT")], one[site("Grok")]], [Probe.direct, Probe.direct],
                       "общий адрес Cloudflare назван обычными DNS только для одного сайта — такая сеть не прокси, «напрямую» оба")
        let mixed = Probe.verdicts(answers(["ChatGPT": ["5.175.161.40"], "Grok": ["5.175.161.3"], "Perplexity": ["104.18.26.48"]]),
                                   real: { $0 == "www.perplexity.ai" ? ["104.18.26.48"] : ["8.47.69.0"] }, ask: opens)
        XCTAssertEqual([mixed[site("ChatGPT")], mixed[site("Grok")], mixed[site("Perplexity")]], [Probe.ok, Probe.ok, Probe.direct],
                       "сеть прокси, которую обычные DNS не называли, прокси и остаётся")
        let g = Probe.verdicts(answers(["Gemini": ["142.250.154.101"], "NotebookLM": ["142.250.154.101"], "AI Studio": ["142.250.154.101"]]), real: silent, ask: opens)
        XCTAssertEqual([g[site("Gemini")], g[site("NotebookLM")], g[site("AI Studio")]], [Probe.direct, Probe.direct, Probe.direct],
                       "один адрес на три сайта Google и больше ни на чей — все три «напрямую»")
        let named = Probe.verdicts(answers(["ChatGPT": ["1.1.1.1"], "Claude": ["1.1.1.1"], "Notion": ["1.1.1.9"]]), real: silent,
                                   ask: { h, ip in h == "www.notion.so" && ip == "1.1.1.9" ? Probe.blocked : h == "claude.ai" ? Probe.captcha : Probe.ok })
        XCTAssertEqual([named[site("ChatGPT")], named[site("Claude")], named[site("Notion")]], [Probe.ok, Probe.captcha, Probe.blocked],
                       "сайт спрашивают по его имени и адресу от сервиса")
        let zero = Probe.verdicts([[String]?](repeating: ["0.0.0.0"], count: Probe.host.count), real: silent, ask: { _, _ in Probe.ok })
        XCTAssertEqual(Set(zero), [Probe.zero], "сервис отвечает 0.0.0.0 на всё (как Xbox DNS) — «не пускает»")
        let empty = Probe.verdicts([[String]?](repeating: [], count: Probe.host.count), real: silent, ask: { _, _ in Probe.ok })
        XCTAssertEqual(Set(empty), [Probe.zero], "ответ без адресов — «не пускает»")
    }

    func testMemoAsksOnce() {
        let lock = NSLock()
        var calls = 0
        let memo = Probe.Memo { host in
            lock.lock(); calls += 1; lock.unlock()
            Thread.sleep(forTimeInterval: 0.05)
            return [host]
        }
        DispatchQueue.concurrentPerform(iterations: 8) { i in _ = memo.get(i % 2 == 0 ? "claude.ai" : "grok.com") }
        XCTAssertEqual(calls, 2, "по одному запросу на сайт, сколько бы потоков ни спрашивало")
        XCTAssertEqual(memo.get("claude.ai"), ["claude.ai"])
        XCTAssertEqual(memo.get("grok.com"), ["grok.com"])
        XCTAssertEqual(calls, 2)
    }

    func testColumns() {
        let left = Probe.column(0), right = Probe.column(1)
        XCTAssertEqual(left + right, Array(Probe.host.indices), "обе колонки вместе — все сайты по порядку")
        XCTAssertTrue(left.count - right.count == 1 || left.count - right.count == 2, "во второй колонке остаётся место под итог")
    }

    func testEachKeepsOrderAndDoesNotStarve() {
        // как «Найти лучший», с запасом: четыре набора проверок разом, в каждом все сайты, и каждая запускает программу
        let started = Date()
        let lock = NSLock()
        var codes: [Int32] = []
        var order: [[Int]] = []
        DispatchQueue.concurrentPerform(iterations: 4) { _ in
            let got: [Int] = Probe.each { k in
                let r = Shell.run("/bin/sleep", ["0.2"], timeout: 15)
                lock.lock(); codes.append(r.code); lock.unlock()
                return k
            }
            lock.lock(); order.append(got); lock.unlock()
        }
        XCTAssertEqual(codes.count, 4 * Probe.host.count)
        XCTAssertTrue(codes.allSatisfy { $0 == 0 }, "ни один запуск не упёрся в тайм-аут")
        XCTAssertTrue(order.allSatisfy { $0 == Array(Probe.host.indices) }, "результаты идут в порядке списка сайтов")
        XCTAssertLessThan(Date().timeIntervalSince(started), 12, "шестьдесят проверок по 0,2 с при двенадцати одновременных — около секунды")
    }

    // ---------- окно после включения ----------

    func testOutcome() {
        XCTAssertTrue(Model.reached(true, 2, 2))
        XCTAssertFalse(Model.reached(true, 2, 0), "хотели один сервис, а встал другой")
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
        let p = Dns.plan(set: 1, services: [wifi4], off: [])
        XCTAssertEqual(p.cmds, ["\(ns) -setdnsservers \"Wi-Fi\" 153.80.200.170"] + flush)
        XCTAssertEqual(p.off, [])
    }

    func testPlanSingleAddressService() {
        let pereval = Services.setOf("153.80.200.170")!
        let p = Dns.plan(set: pereval, services: [wifi4], off: [])
        XCTAssertEqual(p.cmds, ["\(ns) -setdnsservers \"Wi-Fi\" 153.80.200.170"] + flush, "у «Перевала» один адрес — ставится один DNS")
    }

    func testPlanTurnsIpv6OffAndRemembers() {
        let p = Dns.plan(set: 1, services: [wifi6], off: [])
        XCTAssertEqual(p.cmds, ["\(ns) -setdnsservers \"Wi-Fi\" 153.80.200.170", "\(ns) -setv6off \"Wi-Fi\""] + flush)
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
        XCTAssertEqual(p.cmds, ["\(ns) -setdnsservers \"Wi-Fi\" 193.233.112.88 37.230.192.51"] + flush)
        XCTAssertEqual(p.off, ["Wi-Fi"])
    }

    func testQuote() {
        XCTAssertEqual(Dns.quote("Wi-Fi \"дом\""), "\"Wi-Fi \\\"дом\\\"\"")
    }
}
