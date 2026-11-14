import Foundation

// Проверка: спрашиваем DNS сервиса напрямую (dig), подключаемся к выданному адресу с именем сайта (curl --resolve)
// и смотрим ответ. Так видно, что получит человек, даже если DNS ещё не включён. dig и curl есть в каждой macOS.
// Адрес от сервиса сверяем с тем, что отвечают обычные DNS (control). Совпал — сервис этот сайт не подменяет,
// и человек попадает на него напрямую, как без программы. Так было с Comss.one в ноябре 2026: адреса настоящие,
// ChatGPT отвечал 403 без слов о стране, и версия 1.23 писала «открывается».
enum Probe {
    static let host = ["chatgpt.com", "claude.ai", "gemini.google.com", "elevenlabs.io", "grok.com", "www.perplexity.ai"]
    static let label = ["ChatGPT", "Claude", "Gemini", "ElevenLabs", "Grok", "Perplexity"]
    static let ok = "открывается", blocked = "блок страны", captcha = "капча Google", noLink = "нет связи", noDns = "DNS молчит", zero = "не пускает", direct = "напрямую"
    static let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36"

    // Обычные DNS для сверки. Яндекс и Google отвечают как для России, Quad9 — как для заграницы: у Cloudflare
    // для России свои адреса, и 14.11.2026 GeoHide отдавал для Perplexity настоящие, но «заграничные».
    static let control = ["77.88.8.8", "8.8.8.8", "9.9.9.9"]

    /// nil — сервер не ответил; "" — ответ без адреса; иначе первый IPv4.
    static func resolve(_ server: String, _ host: String) -> String? {
        guard let all = resolveAll(server, host) else { return nil }
        return all.first ?? ""
    }

    /// Все адреса IPv4 из ответа сервера, по порядку; пусто — адреса нет; nil — сервер не ответил.
    /// Спрашиваем дважды: UDP-пакет иногда теряется (27.10.2026 GeoHide раз в несколько запросов не отвечал).
    static func resolveAll(_ server: String, _ host: String) -> [String]? {
        let r = Shell.run("/usr/bin/dig", ["+short", "+time=3", "+tries=2", "@\(server)", host, "A"], timeout: 15)
        return parseDigAll(r.out, timedOut: r.code == -2)
    }

    /// Разбор вывода `dig +short`: первый адрес IPv4; "" — адреса нет; nil — сервер не ответил.
    static func parseDig(_ out: String, timedOut: Bool) -> String? {
        guard let all = parseDigAll(out, timedOut: timedOut) else { return nil }
        return all.first ?? ""
    }

    /// Разбор вывода `dig +short`: все адреса IPv4 по порядку; nil — сервер не ответил.
    static func parseDigAll(_ out: String, timedOut: Bool) -> [String]? {
        if timedOut || out.contains("timed out") || out.contains("no servers could be reached") { return nil }
        return out.split(separator: "\n").map { String($0).trimmingCharacters(in: .whitespaces) }
            .filter { $0.range(of: #"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"#, options: .regularExpression) != nil }
    }

    /// Что сказать по ответу DNS, не заходя на сайт; nil — адрес есть, надо проверять сайт.
    static func verdict(_ ip: String?) -> String? {
        guard let ip = ip else { return noDns }
        return ip == "" || ip == "0.0.0.0" ? zero : nil
    }

    static func site(_ host: String, _ ip: String) -> String {
        let r = Shell.run("/usr/bin/curl", ["-s", "-o", "/dev/null", "--connect-timeout", "5", "-m", "10", "--noproxy", "*", "-A", ua,
                                             "--resolve", "\(host):443:\(ip)", "-w", "%{http_code} %{redirect_url}", "https://\(host)/"], timeout: 15)
        return r.code == -2 ? noLink : classify(r.out)   // curl не уложился в срок — это не ответ сайта
    }

    /// Что видит человек по ответу curl («код адрес_переадресации»): капча Google, «недоступно в стране» или сайт.
    static func classify(_ out: String) -> String {
        if out.isEmpty || out.hasPrefix("000") { return noLink }
        let o = out.lowercased()
        if o.contains("/sorry/") { return captcha }
        for b in ["restrict", "unsupported", "unavailable", "not-available"] where o.contains(b) { return blocked }
        return ok
    }

    /// Настоящие адреса сайта: всё, что ответили обычные DNS. Пусто — ни один не ответил, сверять не с чем.
    /// Каждого спрашиваем до двух раз, как и сервис: «заграничные» адреса даёт один Quad9, и потерянный пакет
    /// от него два других не закроют. Спрашиваем по очереди: сайты и так проверяются параллельно,
    /// а каждый запуск dig занимает поток общей очереди.
    static func real(_ host: String) -> Set<String> {
        var found = Set<String>()
        for srv in control { found.formUnion(resolveAll(srv, host) ?? []) }
        return found
    }

    // Сервис отдаёт сразу несколько адресов своих узлов, в случайном порядке, и часть узлов бывает мёртвой:
    // 14.11.2026 у GeoHide не отвечали три-четыре из семи, и проверка по одному первому адресу через раз писала
    // «нет связи», хотя через соседний узел сайт открывался. Браузер в таком случае идёт к следующему адресу,
    // поэтому идём по первым tries адресам и берём ответ первого, с которым есть связь.
    static let tries = 4

    /// ask — как спросить сайт по адресу (в тестах подставной).
    static func reach(_ host: String, _ ips: [String], _ real: Set<String>, ask: (String, String) -> String = { Probe.site($0, $1) }) -> String {
        for ip in ips.prefix(tries) {
            let answer = ask(host, ip)
            if answer != noLink { return through(answer, ip, real) }
        }
        return noLink
    }

    /// Итог по сайту: answer — что ответил сайт по адресу ip от сервиса, real — настоящие адреса сайта.
    /// Адрес от сервиса настоящий — человек идёт на сайт напрямую, как без программы, и «открывается» тут
    /// ничего не значит (ChatGPT из России отвечает 403 без слов о стране): пишем «напрямую».
    /// Отказ по стране, капчу и обрыв связи сайт назвал сам — их оставляем как есть.
    static func through(_ answer: String, _ ip: String, _ real: Set<String>) -> String {
        answer == ok && isReal(ip, real) ? direct : answer
    }

    /// Настоящий ли адрес: совпал с ответом обычного DNS или лежит с ним в одной сети /24. У крупных сайтов адреса
    /// идут пачкой: 14.11.2026 обычные DNS называли для Perplexity 8.47.69.0, а российский узел GeoHide — 8.47.69.5.
    static func isReal(_ ip: String, _ real: Set<String>) -> Bool {
        let net = net24(ip)
        return real.contains { net24($0) == net }
    }

    /// Первые три числа адреса IPv4.
    static func net24(_ ip: String) -> String {
        guard let dot = ip.lastIndex(of: ".") else { return ip }
        return String(ip[..<dot])
    }

    /// Результат по каждому сайту для набора DNS; сайты проверяются параллельно.
    static func service(_ set: Int) -> [String] {
        var res = Array(repeating: noDns, count: host.count)
        let lock = NSLock()
        let group = DispatchGroup()
        for (k, h) in host.enumerated() {
            group.enter()
            DispatchQueue.global().async {
                var ips: [String]? = nil
                for srv in Services.v4[set] { ips = resolveAll(srv, h); if ips != nil { break } }
                let v = verdict(ips.map { $0.first ?? "" }) ?? reach(h, ips!, real(h))
                lock.lock(); res[k] = v; lock.unlock()
                group.leave()
            }
        }
        group.wait()
        return res
    }

    static func good(_ r: [String]?) -> Int { r?.filter { $0 == ok }.count ?? -1 }

    /// Сервис, где открылось больше всего сайтов; при равенстве остаётся текущий, чтобы не переключать DNS впустую,
    /// а без текущего среди проверенных — тот, что раньше в списке. Непроверенный (nil), например Xbox, не выбирается.
    static func best(_ all: [[String]?], current: Int) -> Int {
        var b = current >= 0 && current < all.count && all[current] != nil ? current : 0
        for k in all.indices where good(all[k]) > good(all[b]) { b = k }
        return b
    }
}
