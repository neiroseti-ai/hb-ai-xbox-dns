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
            RealAddress();
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
            return Served(answers, () => Probe.Resolve("127.0.0.1", host), header, silentFirst);
        }

        // подставной сервер отвечает на один запрос (на второй, если silentFirst), пока выполняется call
        static X Served<X>(Func<byte[], byte[][]> answers, Func<X> call, Action<List<byte>> header = null, bool silentFirst = false, string bind = "127.0.0.1")
        {
            var srv = new UdpClient(new IPEndPoint(IPAddress.Parse(bind), 53));
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
            try { return call(); }
            finally { srv.Close(); th.Join(1000); }
        }

        static readonly byte[][] TwoA = { Rr(ToQuestion, 1, new byte[] { 8, 47, 69, 0 }), Rr(ToQuestion, 1, new byte[] { 8, 6, 112, 0 }) };

        // обычные DNS для сверки на время теста — подставной сервер
        static X WithControl<X>(Func<X> call)
        {
            var saved = Probe.Control;
            Probe.Control = new[] { "127.0.0.1" };
            try { return call(); }
            finally { Probe.Control = saved; }
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

            T("DNS: в ответе два адреса — возвращаются оба, по порядку", () =>
                Eq("8.47.69.0,8.6.112.0", string.Join(",", Served(q => TwoA, () => Probe.ResolveAll("127.0.0.1", "chatgpt.com")))));

            T("DNS: из двух адресов первым считается первый", () =>
                Eq("8.47.69.0", Ask("chatgpt.com", q => TwoA)));

            T("DNS: CNAME между адресами не теряет второй адрес", () =>
                Eq("1.1.1.1,2.2.2.2", string.Join(",", Served(q => new[] {
                    Rr(ToQuestion, 1, new byte[] { 1, 1, 1, 1 }), Rr(ToQuestion, 5, Name("edge.cdn.net")), Rr(ToQuestion, 1, new byte[] { 2, 2, 2, 2 }) },
                    () => Probe.ResolveAll("127.0.0.1", "claude.ai")))));

            T("DNS: адрес есть, а следующая запись оборвана — адрес не теряется", () =>
                Eq("1.2.3.4", Ask("grok.com", q =>
                {
                    var cut = Rr(ToQuestion, 5, Name("edge.cdn.net"));
                    cut[11] = 60;   // длина данных 60 байт, а в пакете их меньше
                    return new[] { Rr(ToQuestion, 1, new byte[] { 1, 2, 3, 4 }), cut };
                })));

            T("DNS: ответ без адресов — пустой список, а не «не ответил»", () =>
                Eq(0, Served(q => new byte[0][], () => Probe.ResolveAll("127.0.0.1", "grok.com")).Length));

            T("DNS: сервер молчит — списка нет", () =>
                Eq(null, Served(q => null, () => Probe.ResolveAll("127.0.0.1", "grok.com"))));
        }

        // ---------- сверка с обычными DNS: подменяет ли сервис адрес сайта ----------

        static void RealAddress()
        {
            T("Сверка: настоящие адреса сайта — всё, что ответил обычный DNS", () =>
            {
                var real = WithControl(() => Served(q => TwoA, () => Probe.Real("chatgpt.com")));
                Eq("8.47.69.0,8.6.112.0", string.Join(",", real.OrderBy(x => x == "8.47.69.0" ? 0 : 1)));
            });

            T("Сверка: обычные DNS молчат — настоящих адресов нет, сверять не с чем", () =>
                Eq(0, WithControl(() => Served(q => null, () => Probe.Real("chatgpt.com"))).Count));

            T("Сверка: ответы разных обычных DNS складываются", () =>
            {
                var saved = Probe.Control;
                Probe.Control = new[] { "127.0.0.1", "127.0.0.2" };
                try
                {
                    var real = Served(q => new[] { Rr(ToQuestion, 1, new byte[] { 8, 47, 69, 0 }) },
                        () => Served(q => new[] { Rr(ToQuestion, 1, new byte[] { 104, 18, 26, 48 }) },
                            () => Probe.Real("www.perplexity.ai"), null, false, "127.0.0.2"));
                    Eq("104.18.26.48,8.47.69.0", string.Join(",", real.OrderBy(x => x, StringComparer.Ordinal)));
                }
                finally { Probe.Control = saved; }
            });

            T("Сверка: первый запрос обычному DNS потерялся — второй находит адреса", () =>
                Eq(2, WithControl(() => Served(q => TwoA, () => Probe.Real("chatgpt.com"), null, true)).Count));

            T("Сверка идёт у трёх разных DNS, а не у одного", () =>
                Eq(3, Probe.Control.Distinct().Count()));

            T("Сервисы «Кнопки» в обычные DNS для сверки не попали", () =>
                Eq(false, Probe.Control.Any(c => Dns.SetOf(c) >= 0 || Dns.IsStale(c))));

            var real2 = new HashSet<string> { "8.47.69.0", "8.6.112.0" };
            var none = new HashSet<string>();

            T("Сервис отдал настоящий адрес, сайт ответил без слов о стране — «напрямую», а не «открывается»", () =>
                Eq(Probe.Direct, Probe.Through(Probe.Ok, "8.6.112.0", real2)));

            T("Сервис подменил адрес, сайт ответил — «открывается»", () =>
                Eq(Probe.Ok, Probe.Through(Probe.Ok, "143.20.64.192", real2)));

            T("Настоящий адрес, сайт сам назвал блок страны — остаётся «блок страны»", () =>
                Eq(Probe.Blocked, Probe.Through(Probe.Blocked, "8.6.112.0", real2)));

            T("Настоящий адрес, связи нет — остаётся «нет связи»", () =>
                Eq(Probe.NoLink, Probe.Through(Probe.NoLink, "8.6.112.0", real2)));

            T("Настоящий адрес, капча — остаётся «капча Google»", () =>
                Eq(Probe.Captcha, Probe.Through(Probe.Captcha, "8.6.112.0", real2)));

            T("Сверять не с чем — верим ответу сайта, как раньше", () =>
                Eq(Probe.Ok, Probe.Through(Probe.Ok, "8.6.112.0", none)));

            T("Адрес из той же сети /24, что настоящий, — тоже настоящий: «напрямую»", () =>
                Eq(Probe.Direct, Probe.Through(Probe.Ok, "8.47.69.5", real2)));

            T("Адрес из соседней сети — уже не настоящий", () =>
                Eq(Probe.Ok, Probe.Through(Probe.Ok, "8.47.70.5", real2)));

            T("Совпало только первое число адреса — не настоящий", () =>
                Eq(Probe.Ok, Probe.Through(Probe.Ok, "8.9.9.9", real2)));

            T("Сеть адреса — первые три числа", () => Eq("160.79.104", Probe.Net24("160.79.104.10")));

            var two = new[] { "143.20.64.192", "5.175.161.40" };

            T("Первый узел сервиса не отвечает, второй открывает сайт — «открывается», а не «нет связи»", () =>
                Eq(Probe.Ok, Probe.Pick(two, new[] { Probe.NoLink, Probe.Ok }, real2)));

            T("Не отвечает ни один узел — «нет связи»", () =>
                Eq(Probe.NoLink, Probe.Pick(two, new[] { Probe.NoLink, Probe.NoLink }, real2)));

            T("Берётся первый по порядку узел со связью, как в браузере, а не лучший ответ", () =>
                Eq(Probe.Blocked, Probe.Pick(two, new[] { Probe.Blocked, Probe.Ok }, real2)));

            T("Пустой список адресов — «нет связи» (до этого в программе не доходит: пустой ответ — «не пускает»)", () =>
                Eq(Probe.NoLink, Probe.Pick(new string[0], new string[0], real2)));

            T("Настоящий адрес после мёртвого — всё равно «напрямую»", () =>
                Eq(Probe.Direct, Probe.Pick(new[] { "8.47.69.0", "8.6.112.0" }, new[] { Probe.NoLink, Probe.Ok }, real2)));

            T("Сверка идёт по тому адресу, который ответил: подменённый — «открывается», хотя рядом настоящий", () =>
                Eq(Probe.Ok, Probe.Pick(new[] { "8.6.112.0", "143.20.64.192" }, new[] { Probe.NoLink, Probe.Ok }, real2)));

            // подставной сайт: по адресам из alive отвечает answer, по остальным связи нет
            Func<string, string, Func<string, string, string>> web = (alive, answer) => (h, ip) => alive.Split(',').Contains(ip) ? answer : Probe.NoLink;
            var six = new[] { "1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5", "6.6.6.6" };

            T("Три узла сервиса мертвы, четвёртый открывает сайт — «открывается»", () =>
                Eq(Probe.Ok, Probe.Reach("claude.ai", six, real2, web("4.4.4.4", Probe.Ok))));

            T("Жив только пятый узел — «нет связи»: дальше четвёртого не идём", () =>
                Eq(Probe.NoLink, Probe.Reach("claude.ai", six, real2, web("5.5.5.5,6.6.6.6", Probe.Ok))));

            T("Спрашиваются ровно первые четыре адреса из ответа сервиса", () =>
            {
                var asked = new List<string>();
                Probe.Reach("claude.ai", six, real2, (h, ip) => { lock (asked) asked.Add(ip); return Probe.NoLink; });
                Eq("1.1.1.1,2.2.2.2,3.3.3.3,4.4.4.4", string.Join(",", asked.OrderBy(x => x)));
            });

            T("Сайт спрашивают по его имени", () =>
                Eq(Probe.Ok, Probe.Reach("claude.ai", six, real2, (h, ip) => h == "claude.ai" ? Probe.Ok : Probe.NoLink)));

            Func<string, ICollection<string>> noReal = h => { throw new Exception("настоящие адреса не нужны"); };
            Func<string, string, string> noSite = (h, ip) => { throw new Exception("на сайт ходить не нужно"); };

            T("Сервис не ответил — «DNS молчит», на сайт не ходим", () =>
                Eq(Probe.NoDns, Probe.Judge("claude.ai", null, noReal, noSite)));

            T("Сервис ответил без адресов — «не пускает», на сайт не ходим", () =>
                Eq(Probe.Zero, Probe.Judge("claude.ai", new string[0], noReal, noSite)));

            T("Сервис ответил 0.0.0.0 — «не пускает», на сайт не ходим", () =>
                Eq(Probe.Zero, Probe.Judge("claude.ai", new[] { "0.0.0.0" }, noReal, noSite)));

            T("Как Comss в ноябре 2026: адреса настоящие, сайт отвечает — «напрямую», а не «открывается»", () =>
                Eq(Probe.Direct, Probe.Judge("chatgpt.com", new[] { "8.47.69.0", "8.6.112.0" },
                    h => h == "chatgpt.com" ? (ICollection<string>)real2 : none, (h, ip) => Probe.Ok)));

            T("Как GeoHide 14.11.2026: адреса узлов, первый мёртвый — «открывается»", () =>
                Eq(Probe.Ok, Probe.Judge("claude.ai", new[] { "45.13.237.213", "5.175.161.40" },
                    h => new HashSet<string> { "160.79.104.10" }, web("5.175.161.40", Probe.Ok))));

            T("Настоящий адрес и отказ по стране от самого сайта — «блок страны»", () =>
                Eq(Probe.Blocked, Probe.Judge("claude.ai", new[] { "160.79.104.10" },
                    h => new HashSet<string> { "160.79.104.10" }, (h, ip) => Probe.Blocked)));

            T("«Напрямую» не считается открывшимся сайтом", () =>
                Eq(0, Probe.Good(Enumerable.Repeat(Probe.Direct, Probe.Host.Length).ToArray())));

            T("Сервис, который всё пропускает напрямую, проигрывает тому, что открыл один сайт", () =>
                Eq(1, Probe.Best(new[] { Enumerable.Repeat(Probe.Direct, Probe.Host.Length).ToArray(), Res(1), null }, 0)));

            T("«Напрямую» рисуется серым: не зелёным, как успех, и не красным, как отказ", () =>
            {
                var color = typeof(MainForm).GetMethod("ResultColor", BindingFlags.NonPublic | BindingFlags.Static);
                Func<string, Color> field = n => (Color)typeof(MainForm).GetField(n, BindingFlags.NonPublic | BindingFlags.Static).GetValue(null);
                Eq(field("Muted"), (Color)color.Invoke(null, new object[] { Probe.Direct, Color.Red }));
                Eq(field("OkGreen"), (Color)color.Invoke(null, new object[] { Probe.Ok, Color.Red }));
                Eq(Color.Red, (Color)color.Invoke(null, new object[] { Probe.Blocked, Color.Red }));
            });
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
            T("Адрес MagicDNS узнаётся", () => Eq(1, Dns.SetOf("109.120.177.170")));
            T("Второй адрес MagicDNS узнаётся", () => Eq(1, Dns.SetOf("45.88.163.92")));
            T("Адрес GeoHide узнаётся", () => Eq(0, Dns.SetOf("143.20.64.192")));
            T("Новый второй адрес GeoHide узнаётся", () => Eq(0, Dns.SetOf("5.175.161.40")));
            T("Старый адрес MagicDNS (до 04.11) не выдаётся за сервис", () => Eq(-1, Dns.SetOf("109.120.132.43")));
            T("Старые адреса MagicDNS помечены как старые", () => Eq(true, Dns.IsStale("109.120.132.43") && Dns.IsStale("94.249.177.102")));
            T("Замолчавший адрес GeoHide из 1.22 помечен как старый", () => Eq(true, Dns.IsStale("45.13.237.213")));
            T("Адреса Comss из 1.22–1.23 за сервис не выдаются: нейросети он больше не открывает", () =>
                Eq(true, Dns.SetOf("94.250.253.55") == -1 && Dns.SetOf("212.109.195.93") == -1));
            T("Прежний адрес Comss (до 1.22) за сервис не выдаётся", () => Eq(-1, Dns.SetOf("83.220.169.155")));
            T("Адреса Comss помечены как старые — программа предложит поставить рабочие", () =>
                Eq(true, Dns.IsStale("94.250.253.55") && Dns.IsStale("212.109.195.93") && Dns.IsStale("83.220.169.155")));
            T("Рабочие адреса GeoHide не старые", () => Eq(false, Dns.IsStale("143.20.64.192") || Dns.IsStale("5.175.161.40")));
            T("У каждого сервиса есть адреса, подпись, сайт и ссылка", () =>
                Eq(true, new[] { Dns.Short.Length, Dns.V4.Length, Dns.V6.Length, Dns.Opens.Length, Dns.Site.Length, Dns.Url.Length }.All(n => n == Dns.Count)));
            T("Xbox DNS стоит на своём номере", () => Eq("Xbox DNS", Dns.Name[Dns.XboxSet]));
            T("Первым в списке, который включает кнопка, стоит сервис для нейросетей", () => Eq("GeoHide EU", Dns.Name[0]));
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
            T("Включили нужный сервис — ошибки нет", () => Eq(null, MainForm.Outcome(true, MainForm.Reached(true, 1, 1), null, true)));
            T("Хотели MagicDNS, а встал GeoHide — это сбой", () => Eq(false, MainForm.Reached(true, 1, 0)));
            T("Выключили — сервиса нет, ошибки нет", () => Eq(null, MainForm.Outcome(false, MainForm.Reached(false, 1, -1), null, true)));
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
        const int Magic = 1;
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
                Eq("dns 10 143.20.64.192,5.175.161.40", net.Take());
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
