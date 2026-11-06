// HB AI · Smart DNS 1.23 для macOS — те же сервисы, та же проверка и то же уведомление о новой версии, что в версии для Windows.
import SwiftUI
import CoreText

@main
struct HBAISmartDNSApp: App {
    init() { Fonts.register() }

    var body: some Scene {
        WindowGroup("HB AI · Smart DNS") {
            ContentView()
                .frame(width: 440, height: 820)
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
    static func head(_ s: CGFloat) -> Font { .custom("Unbounded-ExtraBold", size: s) }
    static func bold(_ s: CGFloat) -> Font { .custom("Manrope-Bold", size: s) }
    static func med(_ s: CGFloat) -> Font { .custom("Manrope-Medium", size: s) }
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
