import Foundation

// Проверка: спрашиваем DNS сервиса напрямую (dig), подключаемся к выданному адресу с именем сайта (curl --resolve)
// и смотрим ответ. Так видно, что получит человек, даже если DNS ещё не включён. dig и curl есть в каждой macOS.
// Адрес от сервиса сверяем с тем, что отвечают обычные DNS (control). Совпал — сервис этот сайт не подменяет,
// и человек попадает на него напрямую, как без программы. Так было с Comss.one в ноябре 2026: адреса настоящие,
// ChatGPT отвечал 403 без слов о стране, и версия 1.23 писала «открывается».
// Вторая сверка (shared, с 1.25): прокси — только адрес, который сервис отдал на сайты разных владельцев.
enum Probe {
    // Сайты для проверки, список тот же, что в XboxDns.cs. Первые шесть — как в прежних версиях, остальные добавлены
    // в 1.25: 14.11.2026 каждый из них напрямую из России отказывал по стране (сразу или после входа) либо не отвечал,
    // а через сервисы открывался. Copilot проверяется по copilot.com: туда переадресует copilot.microsoft.com,
    // а GeoHide подменял только первое имя. Mistral не взят: из России он открывается и без сервиса.
    static let host = ["chatgpt.com", "claude.ai", "gemini.google.com", "elevenlabs.io", "grok.com", "www.perplexity.ai",
                       "copilot.com", "sora.chatgpt.com", "notebooklm.google.com", "aistudio.google.com", "api.anthropic.com", "api.openai.com",
                       "openrouter.ai", "www.notion.so", "open.spotify.com"]
    static let label = ["ChatGPT", "Claude", "Gemini", "ElevenLabs", "Grok", "Perplexity",
                        "Copilot", "Sora", "NotebookLM", "AI Studio", "API Claude", "API OpenAI", "OpenRouter", "Notion", "Spotify"]
    // Чей сайт: по владельцам shared отличает прокси сервиса от настоящего адреса.
    static let owner = ["OpenAI", "Anthropic", "Google", "ElevenLabs", "xAI", "Perplexity",
                        "Microsoft", "OpenAI", "Google", "Google", "Anthropic", "OpenAI", "OpenRouter", "Notion", "Spotify"]
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

    /// Все адреса IPv4 из ответа сервера, по порядку; пусто — адреса нет; nil — сервер не ответил или отказал.
    /// Спрашиваем дважды: UDP-пакет иногда теряется (27.10.2026 GeoHide раз в несколько запросов не отвечал).
    /// На отказ сервера (REFUSED, SERVFAIL) `dig +short` печатает пустоту, как и на «адреса нет», поэтому пустой
    /// ответ переспрашиваем с заголовком: отказ — это nil, как в XboxDns.cs, и проверка идёт ко второму адресу сервиса.
    static func resolveAll(_ server: String, _ host: String) -> [String]? {
        let r = Shell.run("/usr/bin/dig", ["+short", "+time=3", "+tries=2", "@\(server)", host, "A"], timeout: 15)
        guard let ips = parseDigAll(r.out, timedOut: r.code == -2) else { return nil }
        if !ips.isEmpty { return ips }
        let h = Shell.run("/usr/bin/dig", ["+noall", "+comments", "+time=3", "+tries=2", "@\(server)", host, "A"], timeout: 15)
        return refused(h.out) ? nil : ips
    }

    /// Отказал ли сервер: в заголовке ответа dig есть статус, и он не NOERROR и не NXDOMAIN.
    static func refused(_ header: String) -> Bool {
        header.contains("status: ") && !header.contains("status: NOERROR") && !header.contains("status: NXDOMAIN")
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

    /// Что видит человек по ответу curl («код адрес_переадресации»): капча Google, «недоступно в стране», сайт
    /// или ничего. Код 5xx — сайт или прокси не справился, страна ни при чём: «нет связи». Код 451 — отказ по закону.
    /// Отличие от Windows: текст страницы здесь не читается, и отказ по стране, написанный только на самой странице
    /// (так отвечают Grok и API OpenAI), останется незамеченным.
    static func classify(_ out: String) -> String {
        if out.isEmpty || out.hasPrefix("000") || out.hasPrefix("5") { return noLink }
        let o = out.lowercased()
        if o.contains("/sorry/") { return captcha }
        if o.hasPrefix("451") { return blocked }
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

    /// Настоящие адреса сайта узнаём один раз, сколько бы сервисов о нём ни спросили: «Найти лучший» проверяет
    /// все сервисы разом, и иначе на каждый сайт каждого сервиса уходило бы по три запуска dig.
    final class Memo {
        private final class Cell { let lock = NSLock(); var value: Set<String>? }
        private let lock = NSLock()
        private var cells: [String: Cell] = [:]
        private let real: (String) -> Set<String>

        init(_ real: @escaping (String) -> Set<String>) { self.real = real }

        func get(_ host: String) -> Set<String> {
            lock.lock()
            let cell = cells[host] ?? Cell()
            cells[host] = cell
            lock.unlock()
            cell.lock.lock()
            defer { cell.lock.unlock() }
            if let v = cell.value { return v }
            let v = real(host)
            cell.value = v
            return v
        }
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

    /// Сети /24, которые сервис отдал на сайты хотя бы двух разных владельцев (ips[k] — ответ про host[k]).
    /// Так выглядит его прокси. Одной сверки с обычными DNS мало: у Google адресов тысячи, и 14.11.2026 сервис
    /// Geodema, который сайты Google не подменяет, отдал для AI Studio 142.250.154.101 — настоящий адрес из сети,
    /// которую обычные DNS не назвали. Версия 1.24 приняла бы его за прокси и написала «открывается».
    /// Общими бывают и настоящие адреса: у Cloudflare для России одни и те же 8.47.69.0 и 8.6.112.0 на ChatGPT,
    /// Grok, Perplexity и OpenRouter. Поэтому verdicts убирает отсюда сети, которые назвали обычные DNS.
    static func shared(_ ips: [[String]?]) -> Set<String> {
        var owners: [String: Set<String>] = [:]
        for (k, list) in ips.enumerated() {
            for ip in list ?? [] { owners[net24(ip), default: []].insert(owner[k]) }
        }
        return Set(owners.filter { $0.value.count > 1 }.keys)
    }

    /// Что считать настоящими адресами сайта: ответы обычных DNS и те адреса от сервиса (ips), чьих сетей нет
    /// среди его прокси (shared). Через настоящий адрес человек идёт на сайт напрямую.
    static func known(_ real: Set<String>, _ ips: [String]?, _ shared: Set<String>) -> Set<String> {
        real.union((ips ?? []).filter { !shared.contains(net24($0)) })
    }

    /// Результат по каждому сайту для набора DNS. real — где взять настоящие адреса сайта.
    static func service(_ set: Int, real: @escaping (String) -> Set<String> = { Probe.real($0) }) -> [String] {
        let ips: [[String]?] = each { k in
            for srv in Services.v4[set] { if let a = resolveAll(srv, host[k]) { return a } }
            return nil
        }
        return verdicts(ips, real: real)
    }

    /// Итог по всем сайтам из ответов DNS сервиса: ips[k] — адреса для host[k], nil — сервис не ответил.
    /// Сначала по всем ответам сразу видно, какие сети — прокси сервиса: общие для сайтов разных владельцев
    /// (shared), кроме тех, что обычные DNS назвали хоть для одного сайта, на который сервис дал адрес.
    /// Потом судим каждый сайт.
    static func verdicts(_ ips: [[String]?], real: @escaping (String) -> Set<String>,
                         ask: @escaping (String, String) -> String = { Probe.site($0, $1) }) -> [String] {
        let memo = Memo(real)   // настоящие адреса нужны дважды: здесь и когда судим сайт
        var common = shared(ips)
        if !common.isEmpty {
            let named: [Set<String>] = each { k in
                guard let list = ips[k], verdict(list.first ?? "") == nil else { return [] }
                return memo.get(host[k])
            }
            for found in named { for ip in found { common.remove(net24(ip)) } }
        }
        let proxy = common
        return each { k in
            guard let list = ips[k] else { return noDns }
            if let v = verdict(list.first ?? "") { return v }
            return reach(host[k], list, known(memo.get(host[k]), list, proxy), ask: ask)
        }
    }

    // Сайты проверяются разом, но не больше двенадцати одновременно на всю программу. Каждый запуск dig и curl
    // занимает два потока общей очереди, а потоков у неё 64. «Найти лучший» проверяет все сервисы сразу:
    // без предела десятки проверок заняли бы все потоки, и запуски ждали бы друг друга до тайм-аута.
    static let pool: OperationQueue = {
        let q = OperationQueue()
        q.maxConcurrentOperationCount = 12
        return q
    }()

    /// Одно и то же по каждому сайту; результаты в порядке списка. Из самой очереди pool не вызывать.
    static func each<T>(_ work: @escaping (Int) -> T) -> [T] {
        var res = [T?](repeating: nil, count: host.count)
        let lock = NSLock()
        let ops = host.indices.map { k in
            BlockOperation {
                let v = work(k)
                lock.lock(); res[k] = v; lock.unlock()
            }
        }
        pool.addOperations(ops, waitUntilFinished: true)
        return res.map { $0! }
    }

    static func good(_ r: [String]?) -> Int { r?.filter { $0 == ok }.count ?? -1 }

    /// Сервис, где открылось больше всего сайтов; при равенстве — тот, что раньше в списке.
    /// Текущий остаётся, если его никто не обогнал: чтобы не переключать DNS впустую. При margin 2 (DNS уже
    /// включён) он остаётся и тогда, когда лучший обогнал его всего на один сайт, а сам он что-то открывает:
    /// такая разница меняется от проверки к проверке, а смена сервиса меняет страну, из которой человека видят
    /// сайты, — за частую смену страны аккаунты блокируют. Непроверенный (nil), например Xbox, не выбирается.
    static func best(_ all: [[String]?], current: Int, margin: Int = 1) -> Int {
        var top = 0
        for k in all.indices where good(all[k]) > good(all[top]) { top = k }
        guard current >= 0, current < all.count, all[current] != nil else { return top }
        let lead = good(all[top]) - good(all[current])
        return lead <= 0 || (lead < margin && good(all[current]) > 0) ? current : top
    }

    /// Что написать после «Найти лучший»: best — на ком остановились, top — у кого открылось больше всего.
    static func bestNote(_ all: [[String]?], best: Int, top: Int) -> String {
        let good = Probe.good(all[best]), most = Probe.good(all[top])
        if most <= 0 { return "Сейчас ни один сервис не открывает нейросети" }
        let count = " (\(good) из \(host.count))"
        return good == most ? "Лучший сейчас: \(Services.name[best])\(count)"
            : "Оставили \(Services.name[best])\(count): у \(Services.name[top]) всего на сайт больше"
    }

    /// Какие сайты стоят в колонке окна (0 или 1): две колонки, во второй последняя ячейка остаётся под итог.
    static func column(_ col: Int) -> [Int] {
        let rows = host.count / 2 + 1
        return Array(col == 0 ? 0..<min(rows, host.count) : min(rows, host.count)..<host.count)
    }
}
