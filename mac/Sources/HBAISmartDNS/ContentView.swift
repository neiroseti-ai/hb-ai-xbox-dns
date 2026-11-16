import SwiftUI
import AppKit

final class Model: ObservableObject {
    @Published var active = false
    @Published var busy = false
    @Published var dnsSet = 0
    @Published var error: String?
    @Published var check: [String]?
    @Published var checkSet = -1
    @Published var checking = false
    @Published var bestNote: String?
    @Published var stale = false      // стоят нерабочие адреса прежних версий
    @Published var update: String?    // номер новой версии на GitHub

    init() {
        let cur = Dns.activeSet()
        active = cur != nil
        dnsSet = cur ?? 0
        stale = !active && Dns.staleActive()
        Updates.check { v in DispatchQueue.main.async { self.update = v } }
    }

    func toggle() { if !busy { apply(!active) } }

    // смена набора: если DNS уже включён, сразу переключаем адреса
    func pick(_ k: Int) {
        guard !busy, k != dnsSet else { return }
        dnsSet = k
        if active { apply(true) }
    }

    /// Встал ли нужный сервис (или, при выключении, никакой).
    static func reached(_ turnOn: Bool, _ set: Int, _ now: Int?) -> Bool { turnOn ? now == set : now == nil }

    /// Что написать после включения или выключения; nil — всё хорошо.
    /// Сбой при смене сервиса на включённом DNS тоже виден: «встал» сверяется с нужным сервисом, а не с «включён/выключен».
    static func outcome(_ turnOn: Bool, done: Bool, err: String?) -> String? {
        if done { return err.map { (turnOn ? "DNS включён, но: " : "DNS выключен, но: ") + $0 } }
        return err ?? "Не получилось поменять DNS, попробуйте ещё раз"
    }

    // note — подпись вместо обычной (её ставит «Найти лучший», он уже всё проверил)
    func apply(_ turnOn: Bool, note: String? = nil) {
        busy = true; error = nil; bestNote = note
        let set = dnsSet
        DispatchQueue.global().async {
            let err = turnOn ? Dns.enable(set) : Dns.disable()
            // macOS применяет DNS не мгновенно — ждём до трёх секунд
            var now = Dns.activeSet()
            for _ in 0..<5 where !Model.reached(turnOn, set, now) { Thread.sleep(forTimeInterval: 0.6); now = Dns.activeSet() }
            let done = Model.reached(turnOn, set, now)
            let staleNow = now == nil && Dns.staleActive()
            DispatchQueue.main.async {
                self.busy = false
                self.active = now != nil
                self.stale = staleNow
                if let n = now { self.dnsSet = n }
                self.error = Model.outcome(turnOn, done: done, err: err)
                if done && turnOn && note == nil { self.runCheck(set) }
            }
        }
    }

    // проверить выбранный сервис: DNS сервиса → прокси → сайт
    func runCheck(_ set: Int) {
        guard !checking else { return }
        checking = true; checkSet = set; check = nil; bestNote = nil
        DispatchQueue.global().async {
            let res = Probe.service(set)
            DispatchQueue.main.async { self.checking = false; self.check = res; self.checkSet = set }
        }
    }

    // перебрать все сервисы для нейросетей и выбрать тот, где открывается больше всего
    func runBest() {
        guard !checking else { return }
        checking = true; checkSet = -2; check = nil; bestNote = nil
        let current = dnsSet
        let wasActive = active
        DispatchQueue.global().async {
            var all = [[String]?](repeating: nil, count: Services.count)
            let lock = NSLock(); let group = DispatchGroup()
            let memo = Probe.Memo { Probe.real($0) }   // настоящие адреса сайта — один раз на все сервисы
            for s in 0..<Services.count where s != Services.xboxSet {   // Xbox DNS нейросети не открывает
                group.enter()
                DispatchQueue.global().async {
                    let r = Probe.service(s, real: { memo.get($0) })
                    lock.lock(); all[s] = r; lock.unlock()
                    group.leave()
                }
            }
            group.wait()
            let top = Probe.best(all, current: -1)
            DispatchQueue.main.async {
                // Пока шёл поиск, человек мог сменить сервис, включить или выключить DNS. Тогда DNS не трогаем,
                // в карточке оставляем выбранный сервис и просто называем лучший.
                let moved = self.busy || self.dnsSet != current || self.active != wasActive
                // включённый сервис из-за одного сайта не меняем: см. Probe.best
                let best = moved ? top : Probe.best(all, current: current, margin: self.active ? 2 : 1)
                let show = moved ? self.dnsSet : best
                self.checking = false; self.check = all[show]; self.checkSet = show
                let note = Probe.bestNote(all, best: best, top: top)
                // если не открывает ни один — DNS не трогаем
                if !moved && Probe.good(all[best]) > 0 && best != self.dnsSet {
                    self.dnsSet = best
                    if self.active { self.apply(true, note: note); return }
                }
                self.bestNote = note
            }
        }
    }
}

struct ContentView: View {
    @StateObject private var m = Model()
    @State private var pulse = false

    var body: some View {
        ZStack {
            Palette.bg
            RadialGradient(colors: [Palette.violet.opacity(0.38), .clear], center: .init(x: 0.95, y: 0.02), startRadius: 0, endRadius: 320)
            RadialGradient(colors: [Color(red: 60 / 255, green: 140 / 255, blue: 255 / 255).opacity(0.22), .clear], center: .init(x: 0.0, y: 0.75), startRadius: 0, endRadius: 280)
            VStack(alignment: .leading, spacing: 0) {
                pill.padding(.top, 34)
                title.padding(.top, 14)
                toggle.padding(.top, 14).frame(maxWidth: .infinity)
                status.padding(.top, 12).frame(maxWidth: .infinity)
                segments.padding(.top, 14)
                card.padding(.top, 12)
                vkButton.padding(.top, 12)
                footer.padding(.top, 12)
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 28)
        }
        .ignoresSafeArea()
        .preferredColorScheme(.dark)
    }

    // плашка сверху: ведёт на сайт сервиса
    var pill: some View {
        Button { open(Services.url[m.dnsSet]) } label: {
            HStack(spacing: 8) {
                Circle().fill(Palette.yellow).frame(width: 10, height: 10)
                Text("Smart DNS " + Updates.version + " · " + Services.site[m.dnsSet]).font(Fonts.bold(11)).foregroundColor(Palette.soft)
            }
            .padding(.horizontal, 16).padding(.vertical, 8)
            .background(Capsule().fill(Palette.violet.opacity(0.16)))
            .overlay(Capsule().stroke(Palette.violet.opacity(0.45)))
        }
        .buttonStyle(.plain)
    }

    var title: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("Доступ").font(Fonts.head(22)).foregroundColor(.white)
            Text("к сервисам").font(Fonts.head(22)).foregroundColor(Palette.ink)
                .padding(.horizontal, 4)
                .background(RoundedRectangle(cornerRadius: 8).fill(Palette.yellow))
        }
    }

    var toggle: some View {
        Button { m.toggle() } label: {
            ZStack {
                Circle().fill(m.active ? Palette.yellow : Palette.card)
                    .overlay(Circle().stroke(m.active ? Palette.yellow : Color(red: 70 / 255, green: 70 / 255, blue: 88 / 255), lineWidth: 3))
                    .shadow(color: (m.active ? Palette.yellow : Palette.violet).opacity(m.active || m.busy ? (pulse ? 0.55 : 0.25) : 0), radius: 34)
                if m.busy {
                    Circle().trim(from: 0, to: 0.25).stroke(Palette.violet, style: StrokeStyle(lineWidth: 5, lineCap: .round))
                        .frame(width: 134, height: 134)
                        .rotationEffect(.degrees(pulse ? 360 : 0))
                        .animation(.linear(duration: 1).repeatForever(autoreverses: false), value: pulse)
                }
                VStack(spacing: 6) {
                    Image(systemName: "power").font(.system(size: 40, weight: .bold))
                        .foregroundColor(m.active ? Palette.ink : .white)
                    Text(m.active ? "ВКЛ" : "ВЫКЛ").font(Fonts.head(10)).foregroundColor(m.active ? Palette.ink : Palette.soft)
                }
            }
            .frame(width: 150, height: 150)
        }
        .buttonStyle(.plain)
        .disabled(m.busy)
        .onAppear { withAnimation(.easeInOut(duration: 1.2).repeatForever()) { pulse = true } }
    }

    var status: some View {
        VStack(spacing: 6) {
            Text(m.busy ? "Применяем настройки…" : m.active ? "DNS включён" : m.stale ? "Стоят старые адреса DNS" : "DNS выключен")
                .font(Fonts.head(15)).foregroundColor(m.active && !m.busy ? Palette.yellow : .white)
            Text(m.error ?? m.bestNote ?? (m.busy ? "Секунду" : m.active ? Services.name[m.dnsSet] + ": " + Services.opens[m.dnsSet]
                 : m.stale ? "Через них нейросети не откроются. Нажмите кнопку — поставим рабочие" : "Обычный DNS от роутера или провайдера"))
                .font(Fonts.med(10.5)).foregroundColor(m.error != nil ? Color(red: 1, green: 138 / 255, blue: 138 / 255) : Palette.muted)
                .multilineTextAlignment(.center).frame(maxWidth: 380)
        }
    }

    var segments: some View {
        HStack(spacing: 0) {
            ForEach(0..<Services.count, id: \.self) { k in
                Button { m.pick(k) } label: {
                    Text(Services.short[k]).font(Fonts.bold(9)).lineLimit(1)
                        .foregroundColor(k == m.dnsSet ? Palette.ink : Palette.soft)
                        .frame(maxWidth: .infinity).frame(height: 40)
                        .background(RoundedRectangle(cornerRadius: 12).fill(k == m.dnsSet ? Palette.yellow : .clear))
                        // без этого невыбранный сервис нажимался только по самому слову: прозрачная заливка в кнопку не входит
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            }
        }
        .padding(5)
        .background(RoundedRectangle(cornerRadius: 16).fill(Palette.card))
        .overlay(RoundedRectangle(cornerRadius: 16).stroke(Palette.line))
    }

    // карточка проверки: адреса, кнопки и что открывается через выбранный сервис
    var card: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 10) {
                Text("DNS").font(Fonts.bold(9.5)).foregroundColor(Palette.violet)
                Text(Services.v4[m.dnsSet].joined(separator: "  /  ")).font(Fonts.med(10)).foregroundColor(Palette.text)
            }
            HStack {
                small(m.checking && m.checkSet == m.dnsSet ? "Проверяем…" : "Проверить " + Services.short[m.dnsSet]) { m.runCheck(m.dnsSet) }
                Spacer()
                small(m.checking && m.checkSet == -2 ? "Ищем…" : "Найти лучший") { m.runBest() }
            }
            // результаты по сайтам: две колонки, как в версии для Windows; под второй — сколько открывается
            let shown: [String]? = m.checkSet == m.dnsSet ? m.check : nil
            HStack(alignment: .top, spacing: 0) {
                ForEach(0..<2, id: \.self) { col in
                    VStack(alignment: .leading, spacing: 5) {
                        ForEach(Probe.column(col), id: \.self) { i in
                            row(i, shown.map { $0[i] })
                        }
                        if col == 1, let res = shown {
                            Text("Открывается \(Probe.good(res)) из \(res.count)").font(Fonts.bold(8)).foregroundColor(Palette.soft)
                                .frame(height: 13)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }
        .padding(14)
        .background(RoundedRectangle(cornerRadius: 16).fill(Palette.card))
        .overlay(RoundedRectangle(cornerRadius: 16).stroke(Palette.line))
    }

    // строка результата: точка, сайт и слово; высота задана, чтобы колонки стояли ровно и карточка не меняла рост
    private func row(_ i: Int, _ r: String?) -> some View {
        HStack(spacing: 6) {
            Circle().fill(dot(r)).frame(width: 9, height: 9)
            Text(Probe.label[i]).font(Fonts.med(9.5)).foregroundColor(Palette.text).lineLimit(1).frame(width: 72, alignment: .leading)
            if let r = r { Text(r).font(Fonts.bold(8)).foregroundColor(dot(r)).lineLimit(1) }
        }
        .frame(height: 13)
    }

    private func dot(_ r: String?) -> Color {
        guard let r = r else { return Color(red: 70 / 255, green: 70 / 255, blue: 88 / 255) }
        if r == Probe.ok { return Palette.green }
        if r == Probe.captcha { return Palette.yellow }
        if r == Probe.direct { return Palette.muted }   // сервис этот сайт не трогает: не успех и не поломка
        return Palette.red
    }

    private func small(_ text: String, _ action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Text(text).font(Fonts.bold(9)).foregroundColor(m.checking ? Palette.muted : Palette.soft)
                .frame(width: 160, height: 30)
                .background(RoundedRectangle(cornerRadius: 10).fill(m.checking ? Palette.card : Palette.violet.opacity(0.16)))
                .overlay(RoundedRectangle(cornerRadius: 10).stroke(m.checking ? Palette.line : Palette.violet.opacity(0.45)))
        }
        .buttonStyle(.plain)
        .disabled(m.checking)
    }

    // кнопка группы ВКонтакте или, если вышла новая версия, жёлтая «Скачать версию …»
    var vkButton: some View {
        Button { open(m.update != nil ? Updates.page : "https://vk.com/neiroseti_ai") } label: {
            Text(m.update.map { "Скачать версию \($0)  →" } ?? "Наша группа ВКонтакте  →").font(Fonts.head(11.5))
                .foregroundColor(m.update != nil ? Palette.ink : .white)
                .frame(maxWidth: .infinity).frame(height: 46)
                .background(RoundedRectangle(cornerRadius: 16).fill(m.update != nil
                    ? AnyShapeStyle(Palette.yellow)
                    : AnyShapeStyle(LinearGradient(colors: [Color(red: 124 / 255, green: 92 / 255, blue: 1), Color(red: 76 / 255, green: 124 / 255, blue: 1)], startPoint: .leading, endPoint: .trailing))))
        }
        .buttonStyle(.plain)
    }

    var footer: some View {
        HStack {
            Button { open("https://vk.com/neiroseti_ai") } label: { Text("HB AI").font(Fonts.head(13)).foregroundColor(Palette.violet) }.buttonStyle(.plain)
            Spacer()
            Button { open("https://vk.com/neiroseti_ai") } label: { Text("vk.com/neiroseti_ai").font(Fonts.med(9.5)).foregroundColor(Palette.muted) }.buttonStyle(.plain)
        }
    }

    private func open(_ s: String) { if let u = URL(string: s) { NSWorkspace.shared.open(u) } }
}
