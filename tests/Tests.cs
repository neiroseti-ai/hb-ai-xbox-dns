// Тесты Smart DNS. Сборка и запуск: test.bat (тот же csc, без NuGet и фреймворков).
// DNS компьютера тесты не меняют: проверка адресов идёт через подставной DNS-сервер на 127.0.0.1.
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Threading;
using System.Windows.Forms;

namespace HbAi.XboxDns
{
    static class Tests
    {
        static readonly List<KeyValuePair<string, Action>> all = new List<KeyValuePair<string, Action>>();
        static void T(string name, Action a) { all.Add(new KeyValuePair<string, Action>(name, a)); }

        static void Eq<X>(X expected, X actual, string what = "")
        {
            if (!Equals(expected, actual))
                throw new Exception(what + " ждали «" + expected + "», получили «" + actual + "»");
        }

        [STAThread]
        static int Main()
        {
            DnsReplies();
            BestService();
            KnownAddresses();
            SiteAnswers();
            NewVersion();
            WindowDrag();
            Switching();
            AfterSwitch();

            int failed = 0;
            foreach (var t in all)
            {
                try { t.Value(); Console.WriteLine("ok    " + t.Key); }
                catch (Exception e)
                {
                    failed++;
                    var inner = e is TargetInvocationException ? e.InnerException : e;
                    Console.WriteLine("FAIL  " + t.Key + ": " + inner.Message);
                }
            }
            Console.WriteLine(failed == 0 ? "все " + all.Count + " прошли" : failed + " из " + all.Count + " упали");
            return failed;
        }

        // ---------- ответы DNS: подставной сервер на 127.0.0.1:53 отвечает заранее собранным пакетом ----------

        static byte[] Name(string host)
        {
            var b = new List<byte>();
            foreach (var p in host.Split('.')) { b.Add((byte)p.Length); b.AddRange(System.Text.Encoding.ASCII.GetBytes(p)); }
            b.Add(0);
            return b.ToArray();
        }

        static byte[] Rr(byte[] owner, int type, byte[] data)
        {
            var b = new List<byte>(owner);
            b.AddRange(new byte[] { (byte)(type >> 8), (byte)type, 0, 1, 0, 0, 0, 60, (byte)(data.Length >> 8), (byte)data.Length });
            b.AddRange(data);
            return b.ToArray();
        }

        static readonly byte[] ToQuestion = { 0xC0, 12 };   // указатель на имя из вопроса

        // ответ = запрос с флагом «ответ» и числом записей + сами записи
        // header — поправить заголовок ответа (номер запроса, код ответа); silentFirst — первый запрос «потерять»
        static string Ask(string host, Func<byte[], byte[][]> answers, Action<List<byte>> header = null, bool silentFirst = false)
        {
            var srv = new UdpClient(new IPEndPoint(IPAddress.Loopback, 53));
            var th = new Thread(() =>
            {
                try
                {
                    var from = new IPEndPoint(IPAddress.Any, 0);
                    var q = srv.Receive(ref from);
                    if (silentFirst) q = srv.Receive(ref from);
                    var rr = answers(q);
                    if (rr == null) return;
                    var r = new List<byte>(q);
                    r[2] = 0x81; r[3] = 0x80; r[6] = 0; r[7] = (byte)rr.Length;
                    if (header != null) header(r);
                    foreach (var x in rr) r.AddRange(x);
                    srv.Send(r.ToArray(), r.Count, from);
                }
                catch (SocketException) { }
            });
            th.IsBackground = true; th.Start();
            try { return Probe.Resolve("127.0.0.1", host); }
            finally { srv.Close(); th.Join(1000); }
        }

        static void DnsReplies()
        {
            T("DNS: обычный ответ с адресом", () =>
                Eq("1.2.3.4", Ask("chatgpt.com", q => new[] { Rr(ToQuestion, 1, new byte[] { 1, 2, 3, 4 }) })));

            T("DNS: сначала CNAME, потом адрес", () =>
                Eq("5.6.7.8", Ask("claude.ai", q =>
                {
                    // CNAME указывает на edge.cdn.net, его имя лежит сразу после 12 байт заголовка, вопроса и 12 байт записи
                    int at = q.Length + 12;
                    return new[] { Rr(ToQuestion, 5, Name("edge.cdn.net")), Rr(new byte[] { 0xC0, (byte)at }, 1, new byte[] { 5, 6, 7, 8 }) };
                })));

            T("DNS: имя записи — метка и указатель (сжатие RFC 1035)", () =>
                Eq("9.9.9.9", Ask("chatgpt.com", q =>
                {
                    // «www» + указатель на «chatgpt.com» в вопросе
                    return new[] { Rr(new byte[] { 3, (byte)'w', (byte)'w', (byte)'w', 0xC0, 12 }, 1, new byte[] { 9, 9, 9, 9 }) };
                })));

            T("DNS: сервис отвечает 0.0.0.0", () =>
                Eq(Probe.Zero, Probe.Verdict(Ask("gemini.google.com", q => new[] { Rr(ToQuestion, 1, new byte[4]) }))));

            T("DNS: ответ без адресов", () =>
                Eq(Probe.Zero, Probe.Verdict(Ask("grok.com", q => new byte[0][]))));

            T("DNS: обрезанный ответ — как молчание, а не «не пускает»", () =>
                Eq(Probe.NoDns, Probe.Verdict(Ask("grok.com", q =>
                {
                    var rr = Rr(ToQuestion, 5, Name("edge.cdn.net"));
                    rr[11] = 60;   // длина данных 60 байт, а в пакете их меньше
                    return new[] { rr };
                }))));

            T("DNS: ответ с чужим номером запроса не принимается", () =>
                Eq(Probe.NoDns, Probe.Verdict(Ask("chatgpt.com", q => new[] { Rr(ToQuestion, 1, new byte[] { 1, 2, 3, 4 }) }, h => h[0] ^= 0xFF))));

            T("DNS: «такого имени нет» (NXDOMAIN) — не пускает", () =>
                Eq(Probe.Zero, Probe.Verdict(Ask("chatgpt.com", q => new byte[0][], h => h[3] = 0x83))));

            T("DNS: сервер отказал (REFUSED) — как молчание", () =>
                Eq(Probe.NoDns, Probe.Verdict(Ask("chatgpt.com", q => new byte[0][], h => h[3] = 0x85))));

            T("DNS: первый запрос потерялся — второй находит адрес", () =>
                Eq("1.2.3.4", Ask("chatgpt.com", q => new[] { Rr(ToQuestion, 1, new byte[] { 1, 2, 3, 4 }) }, null, true)));

            T("DNS: сервер молчит", () =>
                Eq(Probe.NoDns, Probe.Verdict(Ask("grok.com", q => null))));
        }

        // ---------- «Найти лучший» ----------

        static string[] Res(int ok)
        {
            return Enumerable.Range(0, Probe.Host.Length).Select(i => i < ok ? Probe.Ok : Probe.NoLink).ToArray();
        }

        static void BestService()
        {
            T("Лучший — где открылось больше сайтов", () =>
                Eq(2, Probe.Best(new[] { Res(5), Res(4), Res(6), Res(6), null }, -1)));

            T("При равенстве выбирается первый по списку", () =>
                Eq(1, Probe.Best(new[] { Res(3), Res(5), Res(5), Res(2), null }, -1)));

            T("Xbox DNS (не проверялся) лучшим не становится", () =>
                Eq(0, Probe.Best(new[] { Res(0), Res(0), Res(0), Res(0), null }, -1)));

            T("Капча Google не считается открывшимся сайтом", () =>
                Eq(1, Probe.Best(new[] {
                    new[] { Probe.Ok, Probe.Captcha, Probe.Captcha, Probe.Ok, Probe.Ok, Probe.Ok },
                    Res(5), null, null, null }, -1)));

            T("При равенстве остаётся текущий сервис", () =>
                Eq(2, Probe.Best(new[] { Res(5), Res(3), Res(5), Res(1), null }, 2)));

            T("Если ни один не открывает, остаётся текущий", () =>
                Eq(3, Probe.Best(new[] { Res(0), Res(0), Res(0), Res(0), null }, 3)));

            T("Текущий Xbox (не проверялся) не мешает выбрать лучший", () =>
                Eq(1, Probe.Best(new[] { Res(2), Res(4), Res(3), Res(0), null }, 4)));

            T("Непроверенный сервис не выбирается, даже если стоит первым", () =>
                Eq(1, Probe.Best(new[] { null, Res(0), Res(0) }, -1)));
        }

        // ---------- какой сервис стоит в Windows ----------

        static void KnownAddresses()
        {
            T("Адрес MagicDNS узнаётся", () => Eq(2, Dns.SetOf("109.120.177.170")));
            T("Второй адрес MagicDNS узнаётся", () => Eq(2, Dns.SetOf("45.88.163.92")));
            T("Новый второй адрес GeoHide узнаётся", () => Eq(1, Dns.SetOf("5.175.161.40")));
            T("Старый адрес MagicDNS (до 04.11) не выдаётся за сервис", () => Eq(-1, Dns.SetOf("109.120.132.43")));
            T("Старые адреса MagicDNS помечены как старые", () => Eq(true, Dns.IsStale("109.120.132.43") && Dns.IsStale("94.249.177.102")));
            T("Замолчавший адрес GeoHide из 1.22 помечен как старый", () => Eq(true, Dns.IsStale("45.13.237.213")));
            T("Второй адрес Comss узнаётся", () => Eq(0, Dns.SetOf("212.109.195.93")));
            T("Новый основной адрес Comss узнаётся", () => Eq(0, Dns.SetOf("94.250.253.55")));
            T("Прежний адрес Comss (до 1.22) узнаётся как Comss", () => Eq(0, Dns.SetOf("83.220.169.155")));
            T("IPv6 Xbox с зоной и заглавными буквами узнаётся", () => Eq(Dns.XboxSet, Dns.SetOf("2A00:AB00:1233:26::51%12")));
            T("Адрес Xbox DNS из версии 1.0 узнаётся", () => Eq(Dns.XboxSet, Dns.SetOf("111.88.96.50")));
            T("Нерабочий адрес GeoHide из версии 1.1 не выдаётся за сервис", () => Eq(-1, Dns.SetOf("193.233.112.67")));
            T("Нерабочий адрес GeoHide из версии 1.1 помечен как старый", () => Eq(true, Dns.IsStale("193.233.112.67")));
            T("Адрес Astracat из версий 1.2–1.21 помечен как старый", () => Eq(true, Dns.IsStale("135.106.217.200")));
            T("Рабочий адрес MagicDNS не старый", () => Eq(false, Dns.IsStale("109.120.177.170")));
            T("DNS роутера не старый", () => Eq(false, Dns.IsStale("192.168.1.1")));
            T("DNS роутера — не сервис", () => Eq(-1, Dns.SetOf("192.168.1.1")));
            T("Google 8.8.8.8 — не сервис", () => Eq(-1, Dns.SetOf("8.8.8.8")));
        }

        // ---------- ответ сайта ----------

        static void SiteAnswers()
        {
            T("Обычная страница — открывается", () =>
                Eq(Probe.Ok, Probe.Classify("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n")));
            T("Редирект на капчу Google", () =>
                Eq(Probe.Captcha, Probe.Classify("HTTP/1.1 302 Found\r\nLocation: https://www.google.com/sorry/index?continue=x\r\n\r\n")));
            T("Редирект на страницу unsupported_country", () =>
                Eq(Probe.Blocked, Probe.Classify("HTTP/1.1 302 Found\r\nLocation: https://chatgpt.com/unsupported_country\r\n\r\n")));
            T("Редирект на geo-restricted, заголовок заглавными", () =>
                Eq(Probe.Blocked, Probe.Classify("HTTP/1.1 307\r\nLOCATION: /geo-restricted\r\n\r\n")));
            T("Редирект на страницу …-unavailable-in-region", () =>
                Eq(Probe.Blocked, Probe.Classify("HTTP/1.1 302\r\nLocation: /app-unavailable-in-region\r\n\r\n")));
            T("Редирект на страницу …/not-available", () =>
                Eq(Probe.Blocked, Probe.Classify("HTTP/1.1 302\r\nLocation: /service-not-available\r\n\r\n")));
            T("Адрес страницы блока заглавными буквами", () =>
                Eq(Probe.Blocked, Probe.Classify("HTTP/1.1 302\r\nLocation: /Unsupported-Country\r\n\r\n")));
        }

        // ---------- новая версия ----------

        static void NewVersion()
        {
            T("Номер версии из переадресации GitHub", () =>
                Eq("1.23", Updates.TagOf("https://github.com/neiroseti-ai/hb-ai-xbox-dns/releases/tag/v1.23")));
            T("Переадресация не на релиз — номера нет", () => Eq(null, Updates.TagOf("https://github.com/login")));
            T("Тег без «v» — не наш формат, номера нет", () => Eq(null, Updates.TagOf("https://github.com/neiroseti-ai/hb-ai-xbox-dns/releases/tag/1.23")));
            T("Нет переадресации — номера нет", () => Eq(null, Updates.TagOf(null)));
            T("1.23 новее 1.22", () => Eq(true, Updates.IsNewer("1.23", "1.22")));
            T("1.3 новее 1.22 (номера как десятичные дроби)", () => Eq(true, Updates.IsNewer("1.3", "1.22")));
            T("Та же версия — не новее", () => Eq(false, Updates.IsNewer("1.22", "1.22")));
            T("Старая версия на GitHub — не новее", () => Eq(false, Updates.IsNewer("1.21", "1.22")));
            T("Непонятный номер — не новее", () => Eq(false, Updates.IsNewer("beta", "1.22")));
            T("Запятая в номере — не новее (а не 123)", () => Eq(false, Updates.IsNewer("1,23", "1.22")));

            T("Кнопка «Скачать версию …» вместо кнопки группы, когда вышла новая", () =>
            {
                MainForm.ForceScale = 1f;
                using (var f = new MainForm())
                using (var plain = new Bitmap(440, 852))
                using (var upd = new Bitmap(440, 852))
                {
                    f.DrawToBitmap(plain, new Rectangle(0, 0, 440, 852));
                    typeof(MainForm).GetField("update", BindingFlags.NonPublic | BindingFlags.Instance).SetValue(f, "1.23");
                    f.DrawToBitmap(upd, new Rectangle(0, 0, 440, 852));
                    // середина кнопки: была фиолетовой, стала жёлтой
                    Eq(true, plain.GetPixel(60, 750).B > 200, "до:");
                    Eq(true, upd.GetPixel(60, 750).R > 200 && upd.GetPixel(60, 750).B < 150, "после:");
                }
            });
        }

        // ---------- окно: перетаскивание ----------

        static void WindowDrag()
        {
            T("Окно не уезжает, если нажали на кнопку сервиса и повели мышь", () =>
            {
                MainForm.ForceScale = 1f;
                using (var f = new MainForm())
                {
                    f.Location = new Point(300, 200);
                    int set = (int)typeof(MainForm).GetField("dnsSet", BindingFlags.NonPublic | BindingFlags.Instance).GetValue(f);
                    var seg = ((Rectangle[])typeof(MainForm).GetField("rSeg", BindingFlags.NonPublic | BindingFlags.Instance).GetValue(f))[set];
                    // нажатие на уже выбранный сервис ничего не включает и DNS не трогает
                    Mouse(f, "OnMouseDown", new Point(seg.X + seg.Width / 2, seg.Y + seg.Height / 2));
                    Mouse(f, "OnMouseMove", new Point(220, 470));   // свободное место под статусом
                    Eq(new Point(300, 200), f.Location, "окно:");
                }
            });

            T("Каждое нажатие решает заново: после перетаскивания нажали на сервис — окно стоит", () =>
            {
                MainForm.ForceScale = 1f;
                using (var f = new MainForm())
                {
                    f.Location = new Point(300, 200);
                    int set = (int)typeof(MainForm).GetField("dnsSet", BindingFlags.NonPublic | BindingFlags.Instance).GetValue(f);
                    var seg = ((Rectangle[])typeof(MainForm).GetField("rSeg", BindingFlags.NonPublic | BindingFlags.Instance).GetValue(f))[set];
                    Mouse(f, "OnMouseDown", new Point(220, 470));   // тянули с пустого места, отпускание не дошло
                    Mouse(f, "OnMouseDown", new Point(seg.X + seg.Width / 2, seg.Y + seg.Height / 2));
                    var before = f.Location;
                    Mouse(f, "OnMouseMove", new Point(250, 480));
                    Eq(before, f.Location, "окно:");
                }
            });

            T("Окно тянется за мышью с пустого места", () =>
            {
                MainForm.ForceScale = 1f;
                using (var f = new MainForm())
                {
                    f.Location = new Point(300, 200);
                    Mouse(f, "OnMouseDown", new Point(220, 470));
                    Mouse(f, "OnMouseMove", new Point(250, 480));
                    Eq(new Point(330, 210), f.Location, "окно:");
                }
            });
        }

        static void Mouse(Form f, string handler, Point p)
        {
            typeof(Control).GetMethod(handler, BindingFlags.NonPublic | BindingFlags.Instance)
                .Invoke(f, new object[] { new MouseEventArgs(MouseButtons.Left, 1, p.X, p.Y, 0) });
        }

        // ---------- что пишет окно после включения или выключения ----------

        static void AfterSwitch()
        {
            T("Включили нужный сервис — ошибки нет", () => Eq(null, MainForm.Outcome(true, MainForm.Reached(true, 2, 2), null, true)));
            T("Хотели MagicDNS, а встал Comss — это сбой", () => Eq(false, MainForm.Reached(true, 2, 0)));
            T("Выключили — сервиса нет, ошибки нет", () => Eq(null, MainForm.Outcome(false, MainForm.Reached(false, 2, -1), null, true)));
            T("Включили, но IPv6 не выключился — «DNS включён, но: …»", () =>
                Eq("DNS включён, но: IPv6 не выключился на «Wi-Fi»: нет доступа", MainForm.Outcome(true, true, "IPv6 не выключился на «Wi-Fi»: нет доступа", true)));
            T("Выключили, но IPv6 не вернулся — «DNS выключен, но: …», а не «включён»", () =>
                Eq("DNS выключен, но: IPv6 не включился на «Wi-Fi»: нет доступа", MainForm.Outcome(false, true, "IPv6 не включился на «Wi-Fi»: нет доступа", true)));
            T("Без прав администратора — просьба запустить от администратора", () =>
                Eq("Не получилось: запустите от имени администратора", MainForm.Outcome(true, false, "Access denied", false)));
            T("С правами, но Windows отказала — причина первой строкой", () =>
                Eq("Не получилось поменять DNS: Ошибка 5", MainForm.Outcome(true, false, "Ошибка 5\nвторая строка", true)));
            T("С правами, ошибки нет, но сервис не встал — попробовать ещё раз", () =>
                Eq("Не получилось поменять DNS, попробуйте ещё раз", MainForm.Outcome(true, false, null, true)));
            T("Длинная причина обрезается до 70 знаков", () =>
                Eq(true, MainForm.Outcome(true, false, new string('x', 200), true).EndsWith("…")));
        }

        // ---------- включение и выключение: подставная Windows записывает, что с ней сделали ----------

        sealed class FakeNet : INet
        {
            public readonly List<string> Log = new List<string>();
            public readonly Dictionary<string, bool> V6On = new Dictionary<string, bool>();   // GUID → IPv6 включён
            public List<Nic> Nics = new List<Nic>();
            public HashSet<string> Refuse = new HashSet<string>();                           // имена, где Windows отказывает
            public bool Has6 = true;

            public FakeNet(params string[] names) { foreach (var n in names) Plug(n); }
            public void Plug(string name)
            {
                Nics.Add(new Nic { Guid = "{" + name + "}", Name = name, Index = 10 + Nics.Count, HasIpv6 = Has6 });
                if (!V6On.ContainsKey("{" + name + "}")) V6On["{" + name + "}"] = true;
            }
            public void Unplug(string name) { Nics.RemoveAll(n => n.Name == name); }
            string NameOf(string g) { return g.Trim('{', '}'); }

            public Nic[] Up() { return Nics.ToArray(); }
            public void SetDns(Nic n, int v, string[] servers)
            {
                if (v == 6 && !V6On[n.Guid]) return;   // IPv6 выключен — IPv6-DNS у подключения нет, как в Windows
                Log.Add((v == 6 ? "dns6 " : "dns ") + n.Index + " " + (servers == null ? "reset" : string.Join(",", servers)));
            }
            public Bind Ipv6(string g)
            {
                if (!Nics.Any(n => n.Guid == g) && !V6On.ContainsKey(g)) return null;
                return Nics.Any(n => n.Guid == g) ? new Bind { Name = NameOf(g), On = V6On[g] } : null;
            }
            public void SetIpv6(string g, bool on)
            {
                if (Refuse.Contains(NameOf(g))) throw new InvalidOperationException("нет доступа");
                V6On[g] = on; Log.Add((on ? "v6on " : "v6off ") + NameOf(g));
            }
            public void ClearCache() { }
            public string Take() { var s = string.Join("; ", Log.ToArray()); Log.Clear(); return s; }
        }

        static string ListFile() { return Path.Combine(Path.GetTempPath(), "hbdns_" + Guid.NewGuid().ToString("N"), "ipv6-off.txt"); }
        static string Listed(string f) { return File.Exists(f) ? string.Join(",", File.ReadAllLines(f)) : ""; }
        static string Restore(FakeNet net, string f)
        {
            return (string)typeof(Dns).GetMethod("Restore6", BindingFlags.NonPublic | BindingFlags.Static)
                .Invoke(null, new object[] { net, f, new Dns.Errors() });
        }
        const int Magic = 2;
        const string MagicDns = "dns6 10 reset; dns 10 109.120.177.170,45.88.163.92";

        static void Switching()
        {
            T("Без IPv6 у провайдера кнопка только ставит DNS", () =>
            {
                var net = new FakeNet { Has6 = false }; net.Plug("Wi-Fi"); string f = ListFile();
                Eq(null, Dns.Enable(Magic, net, f));
                Eq(MagicDns, net.Take());
            });

            T("Есть IPv6, у сервиса его нет — IPv6 на подключении выключается и запоминается", () =>
            {
                var net = new FakeNet("Wi-Fi"); string f = ListFile();
                Eq(null, Dns.Enable(Magic, net, f));
                Eq(MagicDns + "; v6off Wi-Fi", net.Take());
                Eq("{Wi-Fi}", Listed(f), "запомнено:");
            });

            T("Выключение DNS возвращает IPv6 и забывает запись", () =>
            {
                var net = new FakeNet("Wi-Fi"); string f = ListFile();
                Dns.Enable(Magic, net, f); net.Take();
                Eq(null, Dns.Disable(net, f));
                Eq("dns 10 reset; v6on Wi-Fi", net.Take());
                Eq("", Listed(f), "запомнено:");
            });

            T("Смена сервиса не выключает IPv6 второй раз; второе выключение DNS IPv6 не трогает", () =>
            {
                var net = new FakeNet("Wi-Fi"); string f = ListFile();
                Dns.Enable(Magic, net, f); net.Take();
                Dns.Enable(0, net, f);
                Eq("dns 10 94.250.253.55,212.109.195.93", net.Take());
                Dns.Disable(net, f);
                Eq("dns 10 reset; v6on Wi-Fi", net.Take());
                Dns.Disable(net, f);
                Eq("dns 10 reset; dns6 10 reset", net.Take());
            });

            T("Xbox DNS со своими IPv6-адресами возвращает IPv6", () =>
            {
                var net = new FakeNet("Wi-Fi"); string f = ListFile();
                Dns.Enable(Magic, net, f); net.Take();
                Dns.Enable(Dns.XboxSet, net, f);
                Eq("dns 10 111.88.96.54,111.88.96.55; v6on Wi-Fi", net.Take());
            });

            T("IPv6, выключенный самим человеком, программа не включает", () =>
            {
                var net = new FakeNet("Wi-Fi", "Ethernet"); string f = ListFile();
                net.V6On["{Ethernet}"] = false;
                Dns.Enable(Magic, net, f);
                Eq("dns6 10 reset; dns 10 109.120.177.170,45.88.163.92; v6off Wi-Fi; dns 11 109.120.177.170,45.88.163.92", net.Take());
                Dns.Disable(net, f);
                Eq("dns 10 reset; dns 11 reset; v6on Wi-Fi", net.Take());
            });

            T("Адаптер отсоединили — запись остаётся, IPv6 вернётся, когда подключат", () =>
            {
                var net = new FakeNet("Wi-Fi", "USB LAN"); string f = ListFile();
                Dns.Enable(Magic, net, f); net.Take();
                net.Unplug("USB LAN");
                Dns.Disable(net, f);
                Eq("dns 10 reset; v6on Wi-Fi", net.Take());
                Eq("{USB LAN}", Listed(f), "запомнено:");
                net.Plug("USB LAN");
                Eq(null, Restore(net, f));
                Eq("v6on USB LAN", net.Take());
                Eq("", Listed(f), "запомнено:");
            });

            T("Windows не дала включить IPv6 — запись остаётся, ошибка видна", () =>
            {
                var net = new FakeNet("Wi-Fi"); string f = ListFile();
                Dns.Enable(Magic, net, f); net.Take();
                net.Refuse.Add("Wi-Fi");
                Eq("IPv6 не включился на «Wi-Fi»: нет доступа", Dns.Disable(net, f));
                Eq("{Wi-Fi}", Listed(f), "запомнено:");
            });

            T("Windows не дала выключить IPv6 — DNS всё равно стоит на всех подключениях, ошибка видна", () =>
            {
                var net = new FakeNet("Wi-Fi", "Ethernet"); string f = ListFile();
                net.Refuse.Add("Wi-Fi");
                Eq("IPv6 не выключился на «Wi-Fi»: нет доступа", Dns.Enable(Magic, net, f));
                Eq("dns6 10 reset; dns 10 109.120.177.170,45.88.163.92; dns6 11 reset; dns 11 109.120.177.170,45.88.163.92; v6off Ethernet", net.Take());
            });

            T("Имя подключения с квадратными скобками и кириллицей", () =>
            {
                var net = new FakeNet("VPN [work]", "Беспроводная сеть"); string f = ListFile();
                Dns.Enable(Magic, net, f); net.Take();
                Dns.Disable(net, f);
                Eq("dns 10 reset; dns 11 reset; v6on VPN [work]; v6on Беспроводная сеть", net.Take());
            });

            T("Возврат IPv6 при запуске программы DNS не трогает", () =>
            {
                var net = new FakeNet("Wi-Fi"); string f = ListFile();
                Dns.Enable(Magic, net, f); net.Take();
                Restore(net, f);
                Eq("v6on Wi-Fi", net.Take());
                Restore(net, f);
                Eq("", net.Take());
            });
        }
    }
}
