import Foundation

// Сервисы Smart DNS. Список тот же, что в XboxDns.cs (проверено 06.11.2026 из России): Comss.one открывает всё;
// GeoHide Европа — всё, кроме Gemini (капча), ElevenLabs через раз; MagicDNS переехал 04.11.2026 на новые адреса,
// Claude и Gemini через него пока не открываются. Astracat убран в 1.22, старые MagicDNS и 45.13.237.213 — в 1.23.
enum Services {
    static let name = ["Comss.one", "GeoHide EU", "MagicDNS", "Xbox DNS"]
    static let short = ["Comss", "GeoHide", "MagicDNS", "Xbox"]
    static let v4: [[String]] = [
        ["94.250.253.55", "212.109.195.93"],
        ["143.20.64.192", "5.175.161.40"],
        ["109.120.177.170", "45.88.163.92"],
        ["111.88.96.54", "111.88.96.55"],
    ]
    static let opens = [
        "ChatGPT, Claude, Gemini, ElevenLabs, Grok, Perplexity",
        "ChatGPT, Claude, Grok, Perplexity; ElevenLabs — через раз, Gemini — капча",
        "ChatGPT, ElevenLabs, Grok, Perplexity; Claude и Gemini — пока нет",
        "только Xbox Live, нейросети — нет",
    ]
    static let site = ["comss.ru", "geohide.ru", "magicdns.ru", "xbox-dns.ru"]
    static let url = ["https://www.comss.ru/", "https://geohide.ru/", "https://magicdns.ru/", "https://xbox-dns.ru/"]
    static let xboxSet = 3
    static var count: Int { name.count }
    // адреса из прежних версий, которые ещё работают: xbox-dns.ru 1.0 и прежний основной адрес Comss (до 1.22)
    static let oldSets: [String: Int] = ["111.88.96.50": 3, "111.88.96.51": 3, "83.220.169.155": 0]
    // нерабочие адреса прежних версий: российский узел GeoHide (1.1) и Astracat (1.2–1.21) — их не выдаём за сервис
    static let stale: Set<String> = ["159.194.200.33", "193.233.112.67", "135.106.217.200", "85.209.2.112",
                                     "109.120.132.43", "94.249.177.102", "45.13.237.213"]   // + MagicDNS до 04.11.2026 и второй GeoHide из 1.22

    /// Какому сервису принадлежит адрес DNS; nil — чужой адрес.
    static func setOf(_ address: String) -> Int? {
        let a = address.trimmingCharacters(in: .whitespaces).lowercased()
        for (k, ips) in v4.enumerated() where ips.contains(a) { return k }
        return oldSets[a]
    }

    static func isStale(_ address: String) -> Bool { stale.contains(address.trimmingCharacters(in: .whitespaces).lowercased()) }
}

enum Shell {
    /// Запуск программы с таймаутом. Возвращает код выхода и весь вывод (stdout + stderr).
    @discardableResult
    static func run(_ path: String, _ args: [String], timeout: TimeInterval = 20) -> (code: Int32, out: String) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        do { try p.run() } catch { return (-1, "\(error)") }
        let group = DispatchGroup()
        group.enter()
        var data = Data()
        DispatchQueue.global().async {
            data = pipe.fileHandleForReading.readDataToEndOfFile()
            p.waitUntilExit()
            group.leave()
        }
        if group.wait(timeout: .now() + timeout) == .timedOut {
            p.terminate()
            return (-2, "timeout")
        }
        return (p.terminationStatus, String(data: data, encoding: .utf8) ?? "")
    }
}

/// Сетевая служба macOS и её IPv6, как их показывает `networksetup -getinfo`.
struct NetService: Equatable {
    var name: String
    var ipv6Auto: Bool      // «IPv6: Automatic»; ручные настройки IPv6 программа не трогает
    var hasGlobalIpv6: Bool // есть адрес IPv6 не fe80 — значит, провайдер даёт IPv6

    /// Разбор вывода `networksetup -getinfo <служба>`.
    static func parse(_ name: String, _ info: String) -> NetService {
        var auto = false, global = false
        for raw in info.split(separator: "\n") {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("IPv6:") { auto = line.dropFirst(5).trimmingCharacters(in: .whitespaces).lowercased() == "automatic" }
            if line.hasPrefix("IPv6 IP address:") {
                let a = line.dropFirst(16).trimmingCharacters(in: .whitespaces).lowercased()
                if !a.isEmpty && a != "none" && !a.hasPrefix("fe80") { global = true }
            }
        }
        return NetService(name: name, ipv6Auto: auto, hasGlobalIpv6: global)
    }
}

// Смена DNS через стандартный networksetup. Права администратора macOS спрашивает сама (окно с паролем) —
// один раз на всё: DNS, IPv6 и сброс кэша идут одной командой.
enum Dns {
    static let setup = "/usr/sbin/networksetup"

    // IPv6. Если у провайдера есть IPv6, а у сервиса нет адресов IPv6, Mac может ходить к сайтам напрямую по IPv6,
    // мимо Smart DNS, и сайт пишет «недоступно в вашей стране». Поэтому на время Smart DNS IPv6 у таких служб
    // выключается (networksetup -setv6off) и потом возвращается в «Автоматически». Список служб, где его выключила
    // программа, лежит в Application Support и пишется до выключения; вернуть можно и вручную — см. README.
    static var offFile: URL {
        let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("HB AI Smart DNS")
        return dir.appendingPathComponent("ipv6-off.txt")
    }

    /// Сетевые службы (Wi-Fi, Ethernet и т.д.) без отключённых (они помечены звёздочкой).
    static func services() -> [String] {
        let r = Shell.run(setup, ["-listallnetworkservices"])
        return r.out.split(separator: "\n").dropFirst().map { String($0).trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("*") }
    }

    static func serviceInfo() -> [NetService] { services().map { NetService.parse($0, Shell.run(setup, ["-getinfo", $0]).out) } }

    static func dnsLines() -> [String] {
        services().flatMap { s in Shell.run(setup, ["-getdnsservers", s]).out.split(separator: "\n").map { String($0).trimmingCharacters(in: .whitespaces) } }
    }

    /// nil — DNS сервиса не стоит, иначе номер набора.
    static func activeSet() -> Int? {
        for line in dnsLines() { if let k = Services.setOf(line) { return k } }
        return nil
    }

    /// Стоят ли нерабочие адреса прежних версий.
    static func staleActive() -> Bool { dnsLines().contains { Services.isStale($0) } }

    static func readList() -> [String] {
        guard let s = try? String(contentsOf: offFile, encoding: .utf8) else { return [] }
        return s.split(separator: "\n").map { String($0).trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }

    static func writeList(_ names: [String]) {
        if names.isEmpty { try? FileManager.default.removeItem(at: offFile); return }
        try? FileManager.default.createDirectory(at: offFile.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? (names.joined(separator: "\n") + "\n").write(to: offFile, atomically: true, encoding: .utf8)
    }

    static func quote(_ s: String) -> String { "\"" + s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\"" }

    /// Команды для включения набора (set) или выключения (set == nil) и новый список служб с выключенным IPv6.
    /// Чистая функция: не трогает систему, поэтому проверяется тестами.
    static func plan(set: Int?, services: [NetService], off: [String]) -> (cmds: [String], off: [String]) {
        var cmds: [String] = []
        var list = off
        let present = Set(services.map { $0.name })
        let ownV6 = set == Services.xboxSet   // свой IPv6 есть только у Xbox DNS
        for s in services {
            cmds.append("\(setup) -setdnsservers \(quote(s.name)) " + (set.map { Services.v4[$0].joined(separator: " ") } ?? "empty"))
            if let _ = set, !ownV6, s.ipv6Auto, s.hasGlobalIpv6 {
                if !list.contains(s.name) { list.append(s.name) }
                cmds.append("\(setup) -setv6off \(quote(s.name))")
            }
        }
        if set == nil || ownV6 {
            // вернуть IPv6 там, где его выключила программа; отключённую сейчас службу оставить в списке
            for n in list where present.contains(n) { cmds.append("\(setup) -setv6automatic \(quote(n))") }
            list = list.filter { !present.contains($0) }
        }
        cmds.append("/usr/bin/dscacheutil -flushcache")
        cmds.append("/usr/bin/killall -HUP mDNSResponder")
        return (cmds, list)
    }

    static func enable(_ set: Int) -> String? { apply(set) }
    static func disable() -> String? { apply(nil) }

    /// nil — всё хорошо, иначе текст ошибки для окна.
    private static func apply(_ set: Int?) -> String? {
        let svcs = serviceInfo()
        if svcs.isEmpty { return "Не нашли сетевых подключений" }
        let before = readList()
        let p = plan(set: set, services: svcs, off: before)
        writeList(Array(Set(before + p.off)))   // до выключения IPv6: если что-то прервётся, программа знает, что возвращать
        let script = p.cmds.joined(separator: "; ")
        let esc = script.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
        let r = Shell.run("/usr/bin/osascript", ["-e", "do shell script \"\(esc)\" with administrator privileges"], timeout: 180)
        if r.code != 0 {
            writeList(before)
            if r.out.contains("-128") { return "Отменено: без пароля администратора DNS не поменять" }
            return "Не получилось: " + r.out.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        writeList(p.off)
        return nil
    }
}

// Новая версия: GitHub отвечает на /releases/latest переадресацией на /releases/tag/vX.YY — из неё берём номер.
// Без API и без ключей, один запрос при запуске; не получилось — молчим.
final class Updates: NSObject, URLSessionTaskDelegate {
    static let version = "1.23"
    static let page = "https://github.com/neiroseti-ai/hb-ai-xbox-dns/releases/latest"

    /// Номер версии из адреса переадресации; nil — адрес не про релиз.
    static func tagOf(_ location: String?) -> String? {
        guard let l = location, let r = l.range(of: "/tag/v", options: .backwards) else { return nil }
        let v = String(l[r.upperBound...]).trimmingCharacters(in: .whitespaces)
        return v.isEmpty ? nil : v
    }

    /// Новее ли версия: номера сравниваются как десятичные дроби (1.21 < 1.22 < 1.3), как их и выпускаем.
    static func isNewer(_ latest: String, than current: String) -> Bool {
        let ok = CharacterSet(charactersIn: "0123456789.")
        guard latest.unicodeScalars.allSatisfy({ ok.contains($0) }), current.unicodeScalars.allSatisfy({ ok.contains($0) }),
              let a = Decimal(string: latest, locale: Locale(identifier: "en_US_POSIX")),
              let b = Decimal(string: current, locale: Locale(identifier: "en_US_POSIX")) else { return false }
        return a > b
    }

    // не переходить по переадресации: нужен сам адрес
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }

    /// Номер новой версии или nil; вызывает done в любом случае.
    static func check(_ done: @escaping (String?) -> Void) {
        var rq = URLRequest(url: URL(string: page)!)
        rq.httpMethod = "HEAD"; rq.timeoutInterval = 8
        rq.setValue("HB-AI-Smart-DNS-mac/" + version, forHTTPHeaderField: "User-Agent")
        let session = URLSession(configuration: .ephemeral, delegate: Updates(), delegateQueue: nil)
        session.dataTask(with: rq) { _, resp, _ in
            let loc = (resp as? HTTPURLResponse)?.value(forHTTPHeaderField: "Location")
            let v = tagOf(loc)
            done(v != nil && isNewer(v!, than: version) ? v : nil)
            session.finishTasksAndInvalidate()
        }.resume()
    }
}
