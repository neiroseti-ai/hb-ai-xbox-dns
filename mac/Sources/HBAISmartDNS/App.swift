// HB AI · Smart DNS 1.25 для macOS — те же сервисы, такая же проверка (текст страницы не читается, см. Probe.classify)
// и то же уведомление о новой версии, что в версии для Windows.
import SwiftUI
import CoreText

@main
struct HBAISmartDNSApp: App {
    init() { Fonts.register() }

    var body: some Scene {
        WindowGroup("HB AI · Smart DNS") {
            ContentView()
                // Высота под 13-дюймовый MacBook: на экране 1440x900 под строкой меню и над Dock остаётся около 800.
                // Скрытый заголовок добавляет к высоте 28, поэтому здесь 752: окно выходит 440x780. Содержимое идёт
                // от самого верха окна (ignoresSafeArea) и занимает 740 при статусе в одну строку, около 755 в две
                // и 769 в три (замер 16.11.2026 на macOS 15 в GitHub Actions). До этой правки окно было 808.
                .frame(width: 440, height: 752)
        }
        .windowStyle(.hiddenTitleBar)
        .windowResizability(.contentSize)
    }
}

enum Fonts {
    // Шрифты лежат в Contents/Resources; если не нашлись, SwiftUI подставит системный.
    static func register() {
        guard let dir = Bundle.main.resourceURL else { return }
        for name in ["Unbounded-ExtraBold.ttf", "Manrope-Bold.ttf", "Manrope-Medium.ttf"] {
            let url = dir.appendingPathComponent(name)
            CTFontManagerRegisterFontsForURL(url as CFURL, .process, nil)
        }
    }
    // Имена — те, что записаны внутри файлов (PostScript), а не имена файлов: шрифты в res урезаны и переименованы.
    // До 1.25 здесь стояли «Unbounded-ExtraBold» и «Manrope-…», таких шрифтов нет, и окно рисовалось системным.
    static let names = ["HBUnbounded", "HBManropeBold", "HBManropeMedium"]
    static func head(_ s: CGFloat) -> Font { .custom(names[0], size: s) }
    static func bold(_ s: CGFloat) -> Font { .custom(names[1], size: s) }
    static func med(_ s: CGFloat) -> Font { .custom(names[2], size: s) }
}

enum Palette {
    static let bg = Color(red: 7 / 255, green: 7 / 255, blue: 11 / 255)
    static let violet = Color(red: 140 / 255, green: 112 / 255, blue: 255 / 255)
    static let yellow = Color(red: 255 / 255, green: 224 / 255, blue: 102 / 255)
    static let muted = Color(red: 141 / 255, green: 141 / 255, blue: 154 / 255)
    static let soft = Color(red: 207 / 255, green: 200 / 255, blue: 255 / 255)
    static let card = Color(red: 17 / 255, green: 17 / 255, blue: 24 / 255)
    static let line = Color(red: 38 / 255, green: 38 / 255, blue: 48 / 255)
    static let ink = Color(red: 11 / 255, green: 11 / 255, blue: 16 / 255)
    static let green = Color(red: 80 / 255, green: 200 / 255, blue: 130 / 255)
    static let red = Color(red: 255 / 255, green: 110 / 255, blue: 110 / 255)
    static let text = Color(red: 233 / 255, green: 233 / 255, blue: 242 / 255)
}
