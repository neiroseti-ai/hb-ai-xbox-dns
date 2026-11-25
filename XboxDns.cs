// HB AI · Smart DNS 1.26 — переключатель Smart DNS (GeoHide, «Перевал», xbox-dns.ru) со встроенной проверкой и уведомлением о новой версии.
// Сборка: build.bat (csc из .NET Framework 4, есть в каждой Windows 10/11). DNS и IPv6 меняются через CIM, без PowerShell.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Text;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace HbAi.XboxDns
{
    static class Dns
    {
        // Сервисы Smart DNS. Проверено 24.11.2026 из России (МГТС, Москва) по 15 сайтам из Probe.Host,
        // tools/probe_dns.py и research/idei/2026-11-24-knopka-kandidaty. Сколько открывает каждый, меняется за дни.
        // GeoHide с 1.26 стоит на адресах своего основного узла (их отдают имена geohide.ru и dns.geohide.ru):
        // 193.233.112.88 и 37.230.192.51. На каждый сайт они отдают четыре прокси: 193.233.112.67 и 193.233.112.88
        // открывают (Claude и ChatGPT видят Германию), 193.233.112.68 и 159.194.200.33 24.11.2026 не отвечали —
        // проверка перебирает до четырёх адресов. Открывает ChatGPT, Claude, ElevenLabs, Grok и ещё девять;
        // Gemini и Perplexity — нет. Европейский узел из 1.22–1.25 (5.175.161.40, 143.20.64.192) 24.11.2026 не работал:
        // первый адрес молчал, у второго все прокси недоступны. В 1.1–1.25 этот узел считался «российским, из России
        // не открывается» и его адреса 159.194.200.33, 193.233.112.67 были в списке старых — 24.11.2026 это неверно.
        // «Перевал» (pereval.top), с 1.25: ChatGPT, Claude, Gemini, Grok и ещё шесть; адрес у него один.
        // MagicDNS убран в 1.26: его обычный DNS (217.144.190.216, 109.120.187.249) 24.11.2026 молчал, а на magicdns.ru
        // вместо адресов IPv4 стоит «СКОРО». Отвечает он только по шифрованному DNS (dns.magicdns.ru), которого
        // программа пока не ставит.
        // Ни один сервис не открывает сайты, заблокированные в России (проверка 14.11 и 24.11.2026).
        // Geodema (179.236.130.10, 179.236.130.11) и WebShift (31.31.207.68) работают, но в программу не взяты:
        // оба — бесплатное приложение к платному VPN того же оператора, и страница сервиса его рекламирует.
        // Comss.one убран в 1.24: адреса нейросетей подменяет через раз (24.11.2026 — 3 сайта из 17).
        // Astracat (135.106.217.200, 85.209.2.112) не отвечает — убран в 1.22.
        // xbox-dns.ru с 10.10.2026 на нейросети отвечает 0.0.0.0, оставлен только для Xbox Live.
        public static readonly string[] Name = { "GeoHide", "Перевал", "Xbox DNS" };
        public static readonly string[] Short = { "GeoHide", "Перевал", "Xbox" };
        public static readonly string[][] V4 = {
            new[] { "193.233.112.88", "37.230.192.51" },
            new[] { "153.80.200.170" },
            new[] { "111.88.96.54", "111.88.96.55" } };
        public static readonly string[][] V6 = {
            new string[0], new string[0],
            new[] { "2a00:ab00:1233:26::50", "2a00:ab00:1233:26::51" } };
        // Что сервис открывает, меняется за дни, поэтому подпись отсылает к кнопке «Проверить».
        public static readonly string[] Opens = {
            "ChatGPT, Claude, ElevenLabs, Grok и другие; Gemini — нет. Точнее — «Проверить»",
            "ChatGPT, Claude, Gemini, Grok и другие; ElevenLabs — нет. Точнее — «Проверить»",
            "только Xbox Live, нейросети — нет" };
        public static readonly string[] Site = { "geohide.ru", "pereval.top", "xbox-dns.ru" };
        public static readonly string[] Url = { "https://geohide.ru/", "https://pereval.top/", "https://xbox-dns.ru/" };
        public static int Count { get { return Name.Length; } }
        public const int XboxSet = 2;
        // Адреса из прежних версий. Старый xbox-dns.ru (1.0) — тот же сервис для Xbox.
        // Если стоят адреса, через которые нейросети сейчас не открываются, программа не выдаёт их за рабочий сервис,
        // а предлагает нажать кнопку и поставить рабочие.
        static readonly string[] XboxOld = { "111.88.96.50", "111.88.96.51" };
        static readonly string[] Stale = { "135.106.217.200", "85.209.2.112",           // Astracat (1.2–1.21)
            "109.120.132.43", "94.249.177.102", "109.120.177.170", "45.88.163.92",    // MagicDNS до 04.11.2026 и из 1.23–1.24
            "217.144.190.216", "109.120.187.249",                                     // MagicDNS из 1.25: обычный DNS молчит с 17–24.11.2026
            "94.250.253.55", "212.109.195.93", "83.220.169.155",                      // Comss.one (1.1–1.23)
            "5.175.161.40", "143.20.64.192", "45.13.237.213" };                       // европейский узел GeoHide (1.22–1.25): 24.11.2026 не работал

        // -1 — DNS сервиса не стоит, иначе номер набора (IPv4 определяет набор)
        public static int ActiveSet()
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up || ni.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                    continue;
                foreach (var ip in ni.GetIPProperties().DnsAddresses)
                {
                    int k = SetOf(ip.ToString());
                    if (k >= 0) return k;
                }
            }
            return -1;
        }

        // какому сервису принадлежит адрес DNS; -1 — чужой адрес
        public static int SetOf(string address)
        {
            string s = address.Split('%')[0].ToLowerInvariant();
            for (int k = 0; k < V4.Length; k++) if (V4[k].Contains(s) || V6[k].Contains(s)) return k;
            if (XboxOld.Contains(s)) return XboxSet;
            return -1;
        }

        // адрес из прежних версий, который больше не работает
        public static bool IsStale(string address) { return Stale.Contains(address.Split('%')[0].ToLowerInvariant()); }

        // стоят ли в Windows нерабочие адреса прежних версий
        public static bool StaleActive()
        {
            return NetworkInterface.GetAllNetworkInterfaces()
                .Where(ni => ni.OperationalStatus == OperationalStatus.Up && ni.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .Any(ni => ni.GetIPProperties().DnsAddresses.Any(ip => IsStale(ip.ToString())));
        }

        // Включить сервис, выключить DNS сервиса, вернуть IPv6. Возвращают текст ошибок или null.
        public static string Enable(int set) { return Enable(set, Net, Off6File); }
        public static string Disable() { return Disable(Net, Off6File); }
        public static string RestoreIpv6() { return File.Exists(Off6File) ? Restore6(Net, Off6File, new Errors()) : null; }

        internal static INet Net = new CimNet();

        // IPv6. Если у провайдера есть IPv6, а у сервиса нет адресов IPv6, Windows продолжает спрашивать IPv6-DNS
        // провайдера и ходит на сайты напрямую по IPv6 — мимо Smart DNS, и сайт пишет «недоступно в вашей стране».
        // Поэтому на время Smart DNS IPv6 на таких подключениях выключается — тем же способом, что ставится DNS.
        // Список подключений (их GUID: имя можно поменять) лежит в ProgramData и пишется до выключения. Запись
        // снимается только после удачного возврата: отсоединённый адаптер или отказ Windows оставляют её, и IPv6
        // вернётся при следующем выключении DNS или при запуске программы.
        internal static readonly string Off6File = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "HB AI Smart DNS", "ipv6-off.txt");

        internal sealed class Errors
        {
            readonly System.Collections.Generic.List<string> list = new System.Collections.Generic.List<string>();
            public void Try(string what, Action a)
            {
                try { a(); }
                catch (Exception e) { list.Add(what + ": " + (e.InnerException ?? e).Message.Trim()); }
            }
            public void Add(string s) { list.Add(s); }
            public string Text { get { return list.Count == 0 ? null : string.Join("\n", list.ToArray()); } }
        }

        internal static string Enable(int set, INet net, string listFile)
        {
            var err = new Errors();
            bool own6 = V6[set].Length > 0;
            var off = ReadList(listFile);
            foreach (var n in net.Up())
            {
                // Сначала IPv6, потом IPv4: сброс DNS через CIM сбрасывает подключение целиком, оба протокола
                // (проверено 27.10.2026 на Windows 11), и поставленный раньше IPv4 пропадал.
                // Свой IPv6 есть только у Xbox DNS; у остальных IPv6-DNS возвращается к роутеру, а не остаётся от прошлого сервиса.
                err.Try("IPv6-DNS на «" + n.Name + "»", () => net.SetDns(n, 6, own6 ? V6[set] : null));
                err.Try("DNS на «" + n.Name + "»", () => net.SetDns(n, 4, V4[set]));
                if (own6 || !n.HasIpv6) continue;
                var b = net.Ipv6(n.Guid);
                if (b == null || !b.On) continue;
                if (!off.Contains(n.Guid)) { off.Add(n.Guid); WriteList(listFile, off); }
                err.Try("IPv6 не выключился на «" + n.Name + "»", () => net.SetIpv6(n.Guid, false));
            }
            if (own6) Restore6(net, listFile, err);
            err.Try("Кэш DNS", net.ClearCache);
            return err.Text;
        }

        internal static string Disable(INet net, string listFile)
        {
            var err = new Errors();
            foreach (var n in net.Up())
            {
                err.Try("DNS на «" + n.Name + "»", () => net.SetDns(n, 4, null));
                err.Try("IPv6-DNS на «" + n.Name + "»", () => net.SetDns(n, 6, null));
            }
            Restore6(net, listFile, err);
            err.Try("Кэш DNS", net.ClearCache);
            return err.Text;
        }

        // включить IPv6 там, где его выключила программа; кого не вышло — оставить в списке
        static string Restore6(INet net, string listFile, Errors err)
        {
            var left = new System.Collections.Generic.List<string>();
            foreach (var g in ReadList(listFile))
            {
                var b = net.Ipv6(g);
                if (b == null) { left.Add(g); continue; }          // адаптер отсоединён — вернём, когда появится
                if (b.On) continue;                                // уже включён
                try { net.SetIpv6(g, true); }
                catch (Exception e) { left.Add(g); err.Add("IPv6 не включился на «" + b.Name + "»: " + (e.InnerException ?? e).Message.Trim()); }
            }
            WriteList(listFile, left);
            return err.Text;
        }

        static System.Collections.Generic.List<string> ReadList(string f)
        {
            return File.Exists(f) ? File.ReadAllLines(f).Select(l => l.Trim()).Where(l => l.Length > 0).ToList() : new System.Collections.Generic.List<string>();
        }

        static void WriteList(string f, System.Collections.Generic.List<string> ids)
        {
            if (ids.Count == 0) { if (File.Exists(f)) File.Delete(f); return; }
            Directory.CreateDirectory(Path.GetDirectoryName(f));
            File.WriteAllLines(f, ids.ToArray());
        }

        public static bool IsAdmin()
        {
            using (var id = WindowsIdentity.GetCurrent())
                return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }
    }

    // Подключение, как его видит программа
    sealed class Nic { public string Guid, Name; public int Index; public bool HasIpv6; }
    sealed class Bind { public string Name; public bool On; }

    // Всё, чем программа меняет Windows. В тестах подменяется записью в журнал.
    interface INet
    {
        Nic[] Up();                                   // работающие подключения
        void SetDns(Nic n, int ipVersion, string[] servers);   // servers == null — DNS от роутера
        Bind Ipv6(string guid);                       // протокол IPv6 на подключении; null — подключения нет
        void SetIpv6(string guid, bool on);
        void ClearCache();
    }

    // Настоящая Windows: через CIM, на нём же работают команды Set-DnsClientServerAddress и
    // Disable-NetAdapterBinding. PowerShell программа не запускает.
    sealed class CimNet : INet
    {
        const string Ns = @"root\StandardCimv2";

        public Nic[] Up()
        {
            return NetworkInterface.GetAllNetworkInterfaces()
                .Where(ni => ni.OperationalStatus == OperationalStatus.Up && ni.NetworkInterfaceType != NetworkInterfaceType.Loopback
                          && ni.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
                .Select(ni =>
                {
                    var p = ni.GetIPProperties();
                    int index = -1;
                    try { index = p.GetIPv4Properties().Index; } catch (NetworkInformationException) { }
                    if (index < 0) try { index = p.GetIPv6Properties().Index; } catch (NetworkInformationException) { }
                    return new Nic
                    {
                        Guid = ni.Id.ToUpperInvariant(), Name = ni.Name, Index = index,
                        HasIpv6 = p.UnicastAddresses.Any(a => a.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
                                                           && !a.Address.IsIPv6LinkLocal && !System.Net.IPAddress.IsLoopback(a.Address))
                    };
                })
                .Where(n => n.Index >= 0).ToArray();
        }

        public void SetDns(Nic n, int ipVersion, string[] servers)
        {
            using (var s = Microsoft.Management.Infrastructure.CimSession.Create(null))
            {
                var inst = s.QueryInstances(Ns, "WQL", "SELECT * FROM MSFT_DNSClientServerAddress WHERE InterfaceIndex = " + n.Index +
                                                      " AND AddressFamily = " + (ipVersion == 6 ? 23 : 2)).FirstOrDefault();
                if (inst == null) return;   // у подключения нет этого протокола (например, IPv6 выключен)
                using (var o = new Microsoft.Management.Infrastructure.Options.CimOperationOptions())
                {
                    if (servers == null) o.SetCustomOption("ResetServerAddresses", true, false);
                    else o.SetCustomOption("ServerAddresses", servers, Microsoft.Management.Infrastructure.CimType.StringArray, false);
                    s.ModifyInstance(Ns, inst, o);
                }
            }
        }

        static Microsoft.Management.Infrastructure.CimInstance Binding(Microsoft.Management.Infrastructure.CimSession s, string guid)
        {
            return s.QueryInstances(Ns, "WQL", "SELECT * FROM MSFT_NetAdapterBindingSettingData WHERE InstanceID = '" +
                                    guid.Replace("'", "") + "::ms_tcpip6'").FirstOrDefault();
        }

        public Bind Ipv6(string guid)
        {
            using (var s = Microsoft.Management.Infrastructure.CimSession.Create(null))
            {
                var b = Binding(s, guid);
                return b == null ? null : new Bind { Name = (string)b.CimInstanceProperties["Name"].Value, On = (bool)b.CimInstanceProperties["Enabled"].Value };
            }
        }

        public void SetIpv6(string guid, bool on)
        {
            using (var s = Microsoft.Management.Infrastructure.CimSession.Create(null))
            {
                var b = Binding(s, guid);
                if (b == null) throw new InvalidOperationException("подключение не найдено");
                var r = s.InvokeMethod(Ns, b, on ? "Enable" : "Disable", new Microsoft.Management.Infrastructure.CimMethodParametersCollection());
                if (r.ReturnValue != null && Convert.ToInt64(r.ReturnValue.Value) != 0) throw new InvalidOperationException("Windows вернула код " + r.ReturnValue.Value);
            }
        }

        public void ClearCache()
        {
            using (var s = Microsoft.Management.Infrastructure.CimSession.Create(null))
                s.InvokeMethod(Ns, "MSFT_DNSClientCache", "Clear", new Microsoft.Management.Infrastructure.CimMethodParametersCollection());
        }
    }

    // Проверка: спрашиваем DNS сервиса напрямую (UDP, порт 53), подключаемся к выданному адресу по TLS с именем
    // сайта и смотрим ответ. Так видно, что получит человек, даже если DNS ещё не включён.
    // Адрес от сервиса сверяем с тем, что отвечают обычные DNS (Control). Совпал — сервис этот сайт не подменяет,
    // и человек попадает на него напрямую, как без программы. Так было с Comss.one в ноябре 2026: адреса настоящие,
    // ChatGPT отвечал 403 без слов о стране, и версия 1.23 писала «открывается».
    // Вторая сверка (Shared, с 1.25): прокси — только адрес, который сервис отдал на сайты разных владельцев.
    static class Probe
    {
        // Сайты для проверки. Первые шесть — как в прежних версиях, остальные добавлены в 1.25: 14.11.2026 каждый
        // из них напрямую из России отказывал по стране (сразу или после входа) либо не отвечал, а через сервисы
        // открывался. Copilot проверяется по copilot.com: туда переадресует copilot.microsoft.com, а GeoHide
        // подменял только первое имя — после переадресации человек оказывался на сайте напрямую.
        // Mistral в список не взят: из России он открывается и без сервиса.
        public static readonly string[] Host = { "chatgpt.com", "claude.ai", "gemini.google.com", "elevenlabs.io", "grok.com", "www.perplexity.ai",
            "copilot.com", "sora.chatgpt.com", "notebooklm.google.com", "aistudio.google.com", "api.anthropic.com", "api.openai.com",
            "openrouter.ai", "www.notion.so", "open.spotify.com" };
        public static readonly string[] Label = { "ChatGPT", "Claude", "Gemini", "ElevenLabs", "Grok", "Perplexity",
            "Copilot", "Sora", "NotebookLM", "AI Studio", "API Claude", "API OpenAI", "OpenRouter", "Notion", "Spotify" };
        // Чей сайт: по владельцам Shared отличает прокси сервиса от настоящего адреса.
        public static readonly string[] Owner = { "OpenAI", "Anthropic", "Google", "ElevenLabs", "xAI", "Perplexity",
            "Microsoft", "OpenAI", "Google", "Google", "Anthropic", "OpenAI", "OpenRouter", "Notion", "Spotify" };
        public const string Ok = "открывается", Blocked = "блок страны", Captcha = "капча Google", NoLink = "нет связи", NoDns = "DNS молчит", Zero = "не пускает", Direct = "напрямую";

        // Обычные DNS для сверки. Яндекс отвечает как для России, Quad9 и AdGuard — как для заграницы: у Cloudflare
        // для России свои адреса, и 14.11.2026 GeoHide отдавал для Perplexity настоящие, но «заграничные».
        // До 1.26 третьим был Google 8.8.8.8: 24.11.2026 из Москвы (МГТС) он не отвечал, как и Cloudflare 1.1.1.1.
        internal static string[] Control = { "77.88.8.8", "9.9.9.9", "94.140.14.14" };

        // Первый адрес IPv4, который отдал сервер. "" — сервер ответил, но адреса нет; null — не ответил.
        public static string Resolve(string server, string host)
        {
            return First(ResolveAll(server, host));
        }

        // первый адрес ответа: "" — ответ без адресов, null — ответа нет
        internal static string First(string[] ips) { return ips == null ? null : ips.Length == 0 ? "" : ips[0]; }

        // Все адреса IPv4 из ответа сервера, по порядку. Пусто — адреса нет (NXDOMAIN или пустой ответ);
        // null — сервер не ответил, отказал или ответ не наш (тогда пробуем второй адрес сервиса).
        public static string[] ResolveAll(string server, string host)
        {
            var q = new MemoryStream();
            var w = new BinaryWriter(q);
            w.Write(new byte[] { QueryId >> 8, QueryId & 0xFF, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0 });
            foreach (var part in host.Split('.')) { w.Write((byte)part.Length); w.Write(Encoding.ASCII.GetBytes(part)); }
            w.Write(new byte[] { 0, 0, 1, 0, 1 });
            // UDP-пакет иногда теряется (проверка 27.10.2026: GeoHide раз в несколько запросов не отвечал),
            // поэтому спрашиваем до двух раз, прежде чем считать, что сервер молчит.
            var data = q.ToArray();
            for (int attempt = 0; attempt < 2; attempt++)
            {
                try
                {
                    using (var u = new System.Net.Sockets.UdpClient())
                    {
                        u.Client.ReceiveTimeout = 2500;
                        var ep = new System.Net.IPEndPoint(System.Net.IPAddress.Parse(server), 53);
                        u.Send(data, data.Length, ep);
                        string[] ips = ParseAll(u.Receive(ref ep));
                        if (ips != null) return ips;
                    }
                }
                catch (System.Net.Sockets.SocketException) { }
            }
            return null;
        }

        const int QueryId = 0x2a2a;

        // Адреса IPv4 из ответа DNS. Пусто — сервер ответил, но адреса нет (NXDOMAIN или пустой ответ);
        // null — ответ не наш, битый или сервер отказал.
        internal static string[] ParseAll(byte[] r)
        {
            try
            {
                if (!OurAnswer(r)) return null;
                int rcode = r[3] & 0x0F;
                if (rcode == 3) return new string[0];   // такого имени нет
                if (rcode != 0) return null;            // сервер отказал
                int i = 12;
                for (int n = 0; n < (r[4] << 8 | r[5]); n++) i = SkipName(r, i) + 4;
                return AllA(r, i, r[6] << 8 | r[7]);
            }
            catch (IndexOutOfRangeException) { return null; }
            catch (FormatException) { return null; }
        }

        // ответ на наш запрос: длина заголовка, номер запроса, флаг «это ответ»
        static bool OurAnswer(byte[] r) { return r.Length >= 12 && (r[0] << 8 | r[1]) == QueryId && (r[2] & 0x80) != 0; }

        // адреса IPv4 среди записей ответа, начиная с i
        static string[] AllA(byte[] r, int i, int answers)
        {
            var found = new System.Collections.Generic.List<string>();
            try
            {
                for (int n = 0; n < answers; n++)
                {
                    i = SkipName(r, i);
                    int type = r[i] << 8 | r[i + 1], cls = r[i + 2] << 8 | r[i + 3], len = r[i + 8] << 8 | r[i + 9];
                    i += 10;
                    if (i + len > r.Length) return Cut(found);   // запись длиннее пакета
                    if (type == 1 && cls == 1 && len == 4) found.Add(r[i] + "." + r[i + 1] + "." + r[i + 2] + "." + r[i + 3]);
                    i += len;
                }
                return found.ToArray();
            }
            catch (IndexOutOfRangeException) { return Cut(found); }
            catch (FormatException) { return Cut(found); }
        }

        // ответ оборвался: отдаём адреса, которые успели прочитать; ни одного — null, как будто сервер не ответил
        static string[] Cut(System.Collections.Generic.List<string> found) { return found.Count > 0 ? found.ToArray() : null; }

        // Настоящие адреса сайта: всё, что ответили обычные DNS. Пусто — ни один не ответил, сверять не с чем.
        // Каждого спрашиваем до двух раз, как и сервис: «заграничные» адреса даёт один Quad9, и потерянный
        // пакет от него два других не закроют.
        public static System.Collections.Generic.HashSet<string> Real(string host)
        {
            var real = new System.Collections.Generic.HashSet<string>();
            Together(Control.Length, n =>
            {
                var ips = ResolveAll(Control[n], host);
                if (ips != null) lock (real) foreach (var ip in ips) real.Add(ip);
            });
            return real;
        }

        // Итог по сайту: site — что ответил сайт по адресу ip от сервиса, real — настоящие адреса сайта.
        // Адрес от сервиса настоящий — человек идёт на сайт напрямую, как без программы, и «открывается» тут
        // ничего не значит (ChatGPT из России отвечает 403 без слов о стране): пишем «напрямую».
        // Отказ по стране, капчу и обрыв связи сайт назвал сам — их оставляем как есть.
        public static string Through(string site, string ip, System.Collections.Generic.ICollection<string> real)
        {
            return site == Ok && IsReal(ip, real) ? Direct : site;
        }

        // Настоящий ли адрес: совпал с ответом обычного DNS или лежит с ним в одной сети /24. У крупных сайтов
        // адреса идут пачкой: 14.11.2026 обычные DNS называли для Perplexity 8.47.69.0, а российский узел
        // GeoHide — 8.47.69.5, и точное сравнение такой адрес не узнавало.
        public static bool IsReal(string ip, System.Collections.Generic.ICollection<string> real)
        {
            string net = Net24(ip);
            return real.Any(r => Net24(r) == net);
        }

        // первые три числа адреса IPv4
        internal static string Net24(string ip) { int dot = ip.LastIndexOf('.'); return dot < 0 ? ip : ip.Substring(0, dot); }

        // Сети /24, которые сервис отдал на сайты хотя бы двух разных владельцев (ips[k] — ответ про Host[k]).
        // Так выглядит его прокси. Одной сверки с обычными DNS мало: у Google адресов тысячи, и 14.11.2026 сервис
        // Geodema, который сайты Google не подменяет, отдал для AI Studio 142.250.154.101 — настоящий адрес из сети,
        // которую обычные DNS не назвали. Версия 1.24 приняла бы его за прокси и написала «открывается».
        // Общими бывают и настоящие адреса: у Cloudflare для России одни и те же 8.47.69.0 и 8.6.112.0 на ChatGPT,
        // Grok, Perplexity и OpenRouter. Поэтому Verdicts убирает отсюда сети, которые назвали обычные DNS.
        internal static HashSet<string> Shared(string[][] ips)
        {
            var owners = new Dictionary<string, HashSet<string>>();
            for (int k = 0; k < ips.Length; k++)
                foreach (var ip in ips[k] ?? new string[0])
                {
                    HashSet<string> o;
                    if (!owners.TryGetValue(Net24(ip), out o)) owners[Net24(ip)] = o = new HashSet<string>();
                    o.Add(Owner[k]);
                }
            return new HashSet<string>(owners.Where(p => p.Value.Count > 1).Select(p => p.Key));
        }

        // Что считать настоящими адресами сайта: ответы обычных DNS и те адреса от сервиса (ips), чьих сетей нет
        // среди его прокси (shared). Через настоящий адрес человек идёт на сайт напрямую.
        internal static ICollection<string> Known(ICollection<string> real, string[] ips, ICollection<string> shared)
        {
            var known = new HashSet<string>(real);
            foreach (var ip in ips ?? new string[0]) if (!shared.Contains(Net24(ip))) known.Add(ip);
            return known;
        }

        // Настоящие адреса сайта узнаём один раз, сколько бы сервисов о нём ни спросили: «Найти лучший» проверяет
        // все сервисы разом, и иначе обычным DNS уходило бы по три запроса на каждый сайт каждого сервиса.
        internal static Func<string, ICollection<string>> Once(Func<string, ICollection<string>> real)
        {
            var seen = new Dictionary<string, Lazy<ICollection<string>>>();
            return host =>
            {
                Lazy<ICollection<string>> v;
                lock (seen) if (!seen.TryGetValue(host, out v)) seen[host] = v = new Lazy<ICollection<string>>(() => real(host));
                return v.Value;
            };
        }

        // Имя в DNS — метки, которые кончаются нулём или ссылкой (два байта 11xxxxxx) на имя выше в пакете.
        // Ссылка может стоять и после нескольких меток (например, «www» + ссылка на «example.com»).
        static int SkipName(byte[] r, int i)
        {
            while (true)
            {
                int b = r[i];
                if (b == 0) return i + 1;
                if ((b & 0xC0) == 0xC0) return i + 2;
                if ((b & 0xC0) != 0) throw new FormatException("неизвестный тип метки");
                i += b + 1;
            }
        }

        public static string Site(string host, string ip)
        {
            try
            {
                using (var tcp = new System.Net.Sockets.TcpClient())
                {
                    var ar = tcp.BeginConnect(ip, 443, null, null);
                    if (!ar.AsyncWaitHandle.WaitOne(6000) || !tcp.Connected) return NoLink;
                    tcp.EndConnect(ar);
                    tcp.ReceiveTimeout = 8000; tcp.SendTimeout = 8000;
                    using (var ssl = new System.Net.Security.SslStream(tcp.GetStream(), false, (s, c, ch, e) => NameFits(e)))
                    {
                        ssl.AuthenticateAsClient(host, null, (System.Security.Authentication.SslProtocols)(3072 | 12288), false);
                        var req = Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: " + host +
                            "\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36" +
                            "\r\nAccept: text/html\r\nConnection: close\r\n\r\n");
                        ssl.Write(req, 0, req.Length); ssl.Flush();
                        var buf = new byte[16384]; int got = 0, n;
                        while (got < buf.Length && (n = ssl.Read(buf, got, buf.Length - got)) > 0)
                        { got += n; if (Encoding.ASCII.GetString(buf, 0, got).Contains("\r\n\r\n")) break; }
                        return Classify(Encoding.ASCII.GetString(buf, 0, got));
                    }
                }
            }
            catch { return NoLink; }
        }

        // Сертификат должен быть выписан на имя сайта. Прокси Smart DNS пересылает соединение как есть, и сертификат
        // приходит от самого сайта (15.11.2026 так было у всех сервисов программы). Сертификат на другое имя — это
        // страница-заглушка сервиса, а не сайт: связи с сайтом нет. Сертификат на чужое имя так же отвергает curl
        // в версии для Mac. Цепочку доверия здесь не проверяем (антивирус с проверкой HTTPS подставляет свою),
        // а curl проверяет: это второе, кроме текста страницы, отличие проверки на Mac.
        internal static bool NameFits(System.Net.Security.SslPolicyErrors errors)
        {
            return (errors & System.Net.Security.SslPolicyErrors.RemoteCertificateNameMismatch) == 0;
        }

        // Что видит человек по ответу сайта: капча Google, страница «недоступно в вашей стране», сайт или ничего.
        // answer — заголовки и то начало страницы, что пришло вместе с ними.
        // Код 5xx или пустой ответ — сайт или прокси не справился, страна ни при чём: «нет связи».
        // Отказ по стране ищем по коду 451 и по одному слову в адресе переадресации. В остальных заголовках и в тексте
        // страницы такие слова встречаются сами по себе (на copilot.com 14.11.2026 в коде страницы было
        // «Client Hints unavailable»), поэтому в тексте страницы ищем только целые фразы отказа.
        public static string Classify(string answer)
        {
            answer = answer.ToLowerInvariant();
            if (!answer.StartsWith("http/", StringComparison.Ordinal)) return NoLink;
            int end = answer.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            var lines = (end < 0 ? answer : answer.Substring(0, end)).Split('\n');
            string code = (lines[0].Split(' ').Skip(1).FirstOrDefault() ?? "").Trim();
            string to = lines.FirstOrDefault(l => l.StartsWith("location:", StringComparison.Ordinal)) ?? "";
            if (code.StartsWith("5", StringComparison.Ordinal)) return NoLink;
            if (to.Contains("/sorry/")) return Captcha;
            if (code == "451" || new[] { "restrict", "unsupported", "unavailable", "not-available" }.Any(to.Contains)) return Blocked;
            if (end >= 0 && PageRefusal.Any(answer.Substring(end).Contains)) return Blocked;
            return Ok;
        }

        // Фразы отказа по стране в тексте страницы. Cloudflare на запрос программы отвечает простым текстом
        // «error code: 1009» (страна закрыта владельцем сайта), а на запрос с Accept-Encoding — страницей
        // «…used Cloudflare to restrict access». Остальные — OpenAI и xAI.
        static readonly string[] PageRefusal = { "error code: 1009", "restrict access", "unsupported_country", "not available in your region", "not available in your country" };

        // результат по каждому сайту для набора DNS
        public static string[] Service(int set) { return Service(set, Real); }

        // real — где взять настоящие адреса сайта: в программе Real или он же через Once
        internal static string[] Service(int set, Func<string, ICollection<string>> real)
        {
            var ips = Each(k =>
            {
                string[] a = null;
                foreach (var srv in Dns.V4[set]) { a = ResolveAll(srv, Host[k]); if (a != null) break; }
                return a;
            });
            return Verdicts(ips, real, Site);
        }

        // Итог по всем сайтам из ответов DNS сервиса: ips[k] — адреса для Host[k], null — сервис не ответил.
        // Сначала по всем ответам сразу видно, какие сети — прокси сервиса: общие для сайтов разных владельцев
        // (Shared), кроме тех, что обычные DNS назвали хоть для одного сайта, на который сервис дал адрес.
        // Потом судим каждый сайт.
        internal static string[] Verdicts(string[][] ips, Func<string, ICollection<string>> real, Func<string, string, string> ask)
        {
            var once = Once(real);   // настоящие адреса нужны дважды: здесь и когда судим сайт
            var proxy = Shared(ips);
            if (proxy.Count > 0)
                foreach (var found in Each(k => Verdict(First(ips[k])) == null ? once(Host[k]) : null))
                    foreach (var ip in found ?? new string[0]) proxy.Remove(Net24(ip));
            return Each(k => Judge(Host[k], ips[k], h => Known(once(h), ips[k], proxy), ask));
        }

        // одно и то же по каждому сайту, все сайты разом
        static X[] Each<X>(Func<int, X> work)
        {
            var res = new X[Host.Length];
            Together(Host.Length, k => res[k] = work(k));
            return res;
        }

        // Сделать work(0) … work(count - 1) разом, каждое в своём потоке, и дождаться всех. Что упало в потоке,
        // отдаём вызвавшему: необработанное исключение в потоке закрывает всю программу, а прогон тестов обрывает
        // на полуслове.
        internal static void Together(int count, Action<int> work)
        {
            Exception failed = null;
            var th = Enumerable.Range(0, count).Select(n => new Thread(() =>
            {
                try { work(n); }
                catch (Exception e) { failed = e; }
            }) { IsBackground = true }).ToArray();
            foreach (var x in th) x.Start();
            foreach (var x in th) x.Join();
            if (failed != null) throw new Exception(failed.Message, failed);
        }

        // Сервис отдаёт сразу несколько адресов своих узлов, в случайном порядке, и часть узлов бывает мёртвой:
        // 14.11.2026 у GeoHide не отвечали три-четыре из семи, и проверка по одному первому адресу через раз писала
        // «нет связи», хотя через соседний узел сайт открывался. Браузер в таком случае идёт к следующему адресу,
        // поэтому смотрим первые Tries адресов разом и берём ответ первого по порядку, с которым есть связь.
        internal const int Tries = 4;

        // Итог по сайту из ответа DNS сервиса: ips — адреса от сервиса (null — сервис не ответил), real — где взять
        // настоящие адреса сайта, ask — как спросить сайт по адресу. В программе это Real и Site, в тестах — подставные.
        internal static string Judge(string host, string[] ips, Func<string, System.Collections.Generic.ICollection<string>> real, Func<string, string, string> ask)
        {
            return Verdict(First(ips)) ?? Reach(host, ips, real(host), ask);
        }

        internal static string Reach(string host, string[] ips, System.Collections.Generic.ICollection<string> real, Func<string, string, string> ask)
        {
            var take = ips.Take(Tries).ToArray();
            var site = new string[take.Length];
            Together(take.Length, n => site[n] = ask(host, take[n]));
            return Pick(take, site, real);
        }

        // ответ первого по порядку адреса, с которым есть связь; связи нет ни с одним — «нет связи»
        public static string Pick(string[] ips, string[] site, System.Collections.Generic.ICollection<string> real)
        {
            for (int n = 0; n < ips.Length; n++) if (site[n] != NoLink) return Through(site[n], ips[n], real);
            return NoLink;
        }

        // что сказать по ответу DNS, не заходя на сайт; null — адрес есть, надо проверять сайт
        public static string Verdict(string ip)
        {
            if (ip == null) return NoDns;
            if (ip == "" || ip == "0.0.0.0") return Zero;
            return null;
        }

        public static int Good(string[] res) { return res == null ? -1 : res.Count(x => x == Ok); }

        // Сервис, где открылось больше всего сайтов; при равенстве — тот, что раньше в списке.
        // Текущий остаётся, если его никто не обогнал: чтобы не переключать DNS впустую. При margin 2 (DNS уже
        // включён) он остаётся и тогда, когда лучший обогнал его всего на один сайт, а сам он что-то открывает:
        // такая разница меняется от проверки к проверке, а смена сервиса меняет страну, из которой человека
        // видят сайты, — за частую смену страны аккаунты блокируют.
        // Непроверенный сервис (null), например Xbox DNS, выбран не будет.
        public static int Best(string[][] all, int current, int margin = 1)
        {
            int top = 0;
            for (int k = 0; k < all.Length; k++) if (Good(all[k]) > Good(all[top])) top = k;
            if (current < 0 || current >= all.Length || all[current] == null) return top;
            int lead = Good(all[top]) - Good(all[current]);
            return lead <= 0 || lead < margin && Good(all[current]) > 0 ? current : top;
        }

        // Что написать после «Найти лучший»: best — на ком остановились, top — у кого открылось больше всего.
        internal static string BestNote(string[][] all, int best, int top)
        {
            int good = Good(all[best]), most = Good(all[top]);
            if (most <= 0) return "Сейчас ни один сервис не открывает нейросети";
            string count = " (" + good + " из " + Host.Length + ")";
            return good == most ? "Лучший сейчас: " + Dns.Name[best] + count
                : "Оставили " + Dns.Name[best] + count + ": у " + Dns.Name[top] + " всего на сайт больше";
        }
    }

    class MainForm : Form
    {
        internal const string Version = "1.26";   // та же версия в app.manifest (1.2.6.0) и в первой строке файла
        static readonly Color Bg = Color.FromArgb(7, 7, 11);
        static readonly Color Violet = Color.FromArgb(140, 112, 255);
        static readonly Color Yellow = Color.FromArgb(255, 224, 102);
        static readonly Color Muted = Color.FromArgb(141, 141, 154);
        static readonly Color Soft = Color.FromArgb(207, 200, 255);
        static readonly Color CardBg = Color.FromArgb(17, 17, 24);
        static readonly Color CardLine = Color.FromArgb(38, 38, 48);
        static readonly Color Ink = Color.FromArgb(11, 11, 16);          // тёмный текст на жёлтом
        static readonly Color Light = Color.FromArgb(233, 233, 242);
        static readonly Color OkGreen = Color.FromArgb(80, 200, 130);
        static readonly Color Bad = Color.FromArgb(255, 138, 138);
        static readonly Color BadDot = Color.FromArgb(255, 110, 110);
        static readonly Color VioletFill = Color.FromArgb(40, 124, 92, 255);
        static readonly Color VioletLine = Color.FromArgb(115, 124, 92, 255);

        readonly PrivateFontCollection fonts = new PrivateFontCollection();
        FontFamily fHead, fBold, fMed;
        bool active, busy, stale;
        string update;   // номер новой версии на GitHub; null — новой нет или не узнали
        int dnsSet;
        string error;
        float pulse;
        Rectangle rToggle, rClose, rMin, rSite, rGroup, rBrand, rVk, rCheck, rBest;
        readonly Rectangle[] rSeg = new Rectangle[Dns.Count];
        string[] check; int checkSet = -1; bool checking; string bestNote;
        // окно тянется, только если кнопку мыши нажали на пустом месте
        Point dragFrom; bool dragging;
        // Разметка в «логических» пикселях окна (как при 100 %), на экран всё умножается на S = DPI / 96.
        // Сверху вниз: кнопка, статус с подписью, выбор сервиса, карточка проверки, кнопка группы, подвал.
        // Результаты проверки стоят в две колонки по Rows строк; последняя ячейка второй колонки — итог.
        const int LW = 440, ToggleY = 186, ToggleD = 170, StatusY = ToggleY + ToggleD + 20, SetsY = StatusY + 80, SetsH = 48,
            CardY = SetsY + SetsH + 14, RowH = 20, ColW = 170;
        static readonly int Rows = Probe.Host.Length / 2 + 1, CardH = 82 + Rows * RowH + 10,
            VkY = CardY + CardH + 14, FootY = VkY + 50 + 14, LH = FootY + 40;
        float S = 1f;
        internal static float ForceScale;
        readonly System.Windows.Forms.Timer anim = new System.Windows.Forms.Timer();

        public MainForm()
        {
            LoadFonts();
            Text = "HB AI · Smart DNS";
            FormBorderStyle = FormBorderStyle.None;
            StartPosition = FormStartPosition.CenterScreen;
            BackColor = Bg;
            DoubleBuffered = true;
            try { Icon = new Icon(Assembly.GetExecutingAssembly().GetManifestResourceStream("app.ico")); } catch { }
            ApplyScale(ForceScale > 0 ? ForceScale : WindowDpi() / 96f, Screen.FromPoint(Cursor.Position).WorkingArea);

            rClose = new Rectangle(LW - 58, 22, 36, 36);
            rMin = new Rectangle(LW - 100, 22, 36, 36);
            rToggle = new Rectangle((LW - ToggleD) / 2, ToggleY, ToggleD, ToggleD);

            anim.Interval = 30;
            anim.Tick += (s, e) => { pulse = (pulse + 0.035f) % 1f; if (busy || active) Invalidate(ToScreen(rToggleGlow())); };
            anim.Start();

            int cur = Dns.ActiveSet();
            active = cur >= 0;
            dnsSet = cur >= 0 ? cur : 0;
            stale = !active && Dns.StaleActive();
            if (!active && ForceScale <= 0) ThreadPool.QueueUserWorkItem(_ => Dns.RestoreIpv6());
            // о новой версии узнаём в фоне; при снимке окна (--shot) в сеть не ходим
            if (ForceScale <= 0)
                ThreadPool.QueueUserWorkItem(_ => { string v = Updates.Newer(Version); if (v != null) Ui(() => { update = v; Invalidate(); }); });
            int segW = (LW - 56) / Dns.Count;
            for (int k = 0; k < Dns.Count; k++) rSeg[k] = new Rectangle(28 + k * segW, SetsY, segW, SetsH);
            MouseDown += OnDown;
            MouseMove += OnMove;
            MouseUp += (s, e) => dragging = false;
        }

        Rectangle rToggleGlow() { var r = rToggle; r.Inflate(40, 40); return r; }

        protected override void Dispose(bool disposing)
        {
            if (disposing) { anim.Dispose(); fonts.Dispose(); }
            base.Dispose(disposing);
        }

        [DllImport("user32.dll")] static extern uint GetDpiForWindow(IntPtr hwnd);

        float WindowDpi()
        {
            try { uint d = GetDpiForWindow(Handle); if (d > 0) return d; } catch { }   // Windows 10 1607+
            using (var g0 = CreateGraphics()) return g0.DpiX;
        }

        // Размер окна под масштаб: окно целиком должно влезать в рабочую область экрана
        // (на ноутбуке 1080p при 150 % высота окна × 1,5 больше экрана — тогда окно уменьшается целиком).
        void ApplyScale(float scale, Rectangle wa)
        {
            S = ForceScale > 0 ? ForceScale : Math.Min(scale, Math.Min((wa.Height - 24f) / LH, (wa.Width - 24f) / LW));
            ClientSize = new Size((int)Math.Round(LW * S), (int)Math.Round(LH * S));
            var old = Region;
            Region = RoundRegion(ClientRectangle, (int)Math.Round(22 * S));
            if (old != null) old.Dispose();
            if (IsHandleCreated && Visible)
                Location = new Point(Math.Max(wa.Left, Math.Min(Left, wa.Right - Width)), Math.Max(wa.Top, Math.Min(Top, wa.Bottom - Height)));
            Invalidate();
        }

        // Масштаб Windows поменяли на ходу или окно перенесли на другой монитор
        protected override void WndProc(ref Message m)
        {
            const int WM_DPICHANGED = 0x02E0;
            if (m.Msg == WM_DPICHANGED)
            {
                int dpi = (int)((long)m.WParam & 0xFFFF);
                var sug = (RECT)Marshal.PtrToStructure(m.LParam, typeof(RECT));
                var wa = Screen.FromRectangle(Rectangle.FromLTRB(sug.Left, sug.Top, sug.Right, sug.Bottom)).WorkingArea;
                Location = new Point(sug.Left, sug.Top);
                ApplyScale(dpi / 96f, wa);
                m.Result = IntPtr.Zero;
                return;
            }
            base.WndProc(ref m);
        }

        [StructLayout(LayoutKind.Sequential)] struct RECT { public int Left, Top, Right, Bottom; }

        Rectangle ToScreen(Rectangle r) { return Rectangle.FromLTRB((int)Math.Floor(r.Left * S), (int)Math.Floor(r.Top * S), (int)Math.Ceiling(r.Right * S), (int)Math.Ceiling(r.Bottom * S)); }
        Point ToLogical(Point p) { return new Point((int)(p.X / S), (int)(p.Y / S)); }
        // Размер шрифта в пунктах при 100 %; задаём в пикселях, чтобы его масштабировал ScaleTransform, а не DPI второй раз.
        static Font Pt(FontFamily fam, float pt) { return new Font(fam, pt * 96f / 72f, GraphicsUnit.Pixel); }

        void LoadFonts()
        {
            foreach (var name in new[] { "Unbounded-ExtraBold.ttf", "Manrope-Bold.ttf", "Manrope-Medium.ttf" })
            {
                using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream(name))
                {
                    if (s == null) continue;
                    var data = new byte[s.Length];
                    for (int got = 0, n; got < data.Length; got += n)   // Read может отдать меньше, чем просили
                        if ((n = s.Read(data, got, data.Length - got)) == 0) throw new EndOfStreamException(name);
                    IntPtr ptr = Marshal.AllocCoTaskMem(data.Length);
                    Marshal.Copy(data, 0, ptr, data.Length);
                    fonts.AddMemoryFont(ptr, data.Length);
                }
            }
            fHead = Find("HB Unbounded", "Segoe UI");
            fBold = Find("HB Manrope Bold", "Segoe UI");
            fMed = Find("HB Manrope Medium", "Segoe UI");
        }

        FontFamily Find(string name, string fallback)
        {
            foreach (var f in fonts.Families) if (f.Name.StartsWith(name)) return f;
            return new FontFamily(fallback);
        }

        static Region RoundRegion(Rectangle r, int rad) { using (var p = RoundPath(r, rad)) return new Region(p); }

        static GraphicsPath RoundPath(RectangleF r, float rad)
        {
            var p = new GraphicsPath();
            float d = rad * 2;
            p.AddArc(r.X, r.Y, d, d, 180, 90);
            p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
            p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
            p.CloseFigure();
            return p;
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.ScaleTransform(S, S);
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = TextRenderingHint.AntiAliasGridFit;

            // фон: мягкое фиолетовое свечение, как на обложках сообщества
            Glow(g, new RectangleF(LW - 330, -260, 560, 520), Color.FromArgb(95, 124, 92, 255));
            Glow(g, new RectangleF(-260, 460, 520, 460), Color.FromArgb(55, 60, 140, 255));

            DrawTop(g);
            DrawToggle(g);
            DrawStatus(g);
            DrawSets(g);
            DrawCheck(g);
            DrawFooter(g);
        }

        static readonly StringFormat Center = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center };

        // скруглённая плашка с заливкой и обводкой
        static void Panel(Graphics g, RectangleF r, float rad, Color fill, Color line)
        {
            using (var path = RoundPath(r, rad))
            using (var b = new SolidBrush(fill))
            using (var pen = new Pen(line))
            { g.FillPath(b, path); g.DrawPath(pen, path); }
        }

        // Снимок окна без самого окна, для --shot и тестов. Windows не даёт окну стать выше экрана, и DrawToBitmap
        // на невысоком экране оставлял низ снимка пустым.
        internal Bitmap Snapshot()
        {
            var bmp = new Bitmap((int)Math.Round(LW * S), (int)Math.Round(LH * S));
            using (var g = Graphics.FromImage(bmp))
            {
                g.Clear(BackColor);
                using (var e = new PaintEventArgs(g, new Rectangle(Point.Empty, bmp.Size))) OnPaint(e);
            }
            return bmp;
        }

        // плашка с сайтом сервиса, крестик, «свернуть» и заголовок
        void DrawTop(Graphics g)
        {
            using (var f = Pt(fBold, 11f))
            {
                string pill = "Smart DNS " + Version + " · " + Dns.Site[dnsSet];
                var sz = g.MeasureString(pill, f);
                var pr = new RectangleF(30, 24, sz.Width + 46, 34);
                rSite = Rectangle.Round(pr);
                Panel(g, pr, 17, VioletFill, VioletLine);
                using (var b = new SolidBrush(Yellow)) g.FillEllipse(b, pr.X + 16, pr.Y + 12, 10, 10);
                using (var b = new SolidBrush(Soft)) g.DrawString(pill, f, b, pr.X + 32, pr.Y + (34 - sz.Height) / 2 + 1);
            }
            using (var pen = new Pen(Muted, 2f))
            {
                int c = 9;
                var m = new Point(rClose.X + rClose.Width / 2, rClose.Y + rClose.Height / 2);
                g.DrawLine(pen, m.X - c, m.Y - c, m.X + c, m.Y + c);
                g.DrawLine(pen, m.X + c, m.Y - c, m.X - c, m.Y + c);
                var n = new Point(rMin.X + rMin.Width / 2, rMin.Y + rMin.Height / 2);
                g.DrawLine(pen, n.X - c, n.Y + 4, n.X + c, n.Y + 4);
            }
            using (var f = Pt(fHead, 22f))
            using (var b = new SolidBrush(Color.White))
            {
                g.DrawString("Доступ", f, b, 28, 82);
                string hl = "к сервисам";
                var sz = g.MeasureString(hl, f);
                using (var path = RoundPath(new RectangleF(28, 124, sz.Width + 6, sz.Height - 2), 8))
                using (var yb = new SolidBrush(Yellow)) g.FillPath(yb, path);
                using (var db = new SolidBrush(Ink)) g.DrawString(hl, f, db, 31, 124);
            }
        }

        void DrawStatus(Graphics g)
        {
            string status = busy ? "Применяем настройки…" : active ? "DNS включён" : stale ? "Стоят старые адреса DNS" : "DNS выключен";
            using (var f = Pt(fHead, 15f))
            using (var b = new SolidBrush(active && !busy ? Yellow : Color.White))
                Centered(g, status, f, b, StatusY);
            using (var f = Pt(fMed, 10.5f))
            using (var b = new SolidBrush(error != null ? Bad : Muted))
                Centered(g, StatusNote(), f, b, StatusY + 34, LW - 60);
        }

        string StatusNote()
        {
            if (error != null) return error;
            if (bestNote != null) return bestNote;
            if (busy) return "Секунду";
            if (!active && stale) return "Через них нейросети не откроются. Нажмите кнопку — поставим рабочие";
            return active ? Dns.Name[dnsSet] + ": " + Dns.Opens[dnsSet] : "Обычный DNS от роутера или провайдера";
        }

        // выбор сервиса
        void DrawSets(Graphics g)
        {
            Panel(g, new RectangleF(28, SetsY, LW - 56, SetsH), 16, CardBg, CardLine);
            for (int k = 0; k < Dns.Count; k++)
            {
                var sr = new RectangleF(rSeg[k].X + 4, rSeg[k].Y + 5, rSeg[k].Width - 8, rSeg[k].Height - 10);
                bool on = k == dnsSet;
                if (on)
                    using (var path = RoundPath(sr, 12))
                    using (var b = new SolidBrush(Yellow)) g.FillPath(b, path);
                using (var f = Pt(fBold, 8.5f))
                using (var b = new SolidBrush(on ? Ink : Soft))
                    g.DrawString(Dns.Short[k], f, b, sr, Center);
            }
        }

        // карточка проверки: адреса, кнопки и что открывается через выбранный сервис
        void DrawCheck(Graphics g)
        {
            var card = new RectangleF(28, CardY, LW - 56, CardH);
            Panel(g, card, 16, CardBg, CardLine);
            using (var fl = Pt(fBold, 9.5f))
            using (var fv = Pt(fMed, 10f))
            using (var bl = new SolidBrush(Violet))
            using (var bv = new SolidBrush(Light))
            {
                g.DrawString("DNS", fl, bl, card.X + 18, card.Y + 14);
                g.DrawString(string.Join("  /  ", Dns.V4[dnsSet]), fv, bv, card.X + 58, card.Y + 12);
            }
            rCheck = new Rectangle((int)card.X + 18, (int)card.Y + 40, 160, 30);
            rBest = new Rectangle((int)card.Right - 18 - 160, (int)card.Y + 40, 160, 30);
            DrawSmall(g, rCheck, checking && checkSet == dnsSet ? "Проверяем…" : "Проверить " + Dns.Short[dnsSet], !checking);
            DrawSmall(g, rBest, checking && checkSet == -2 ? "Ищем…" : "Найти лучший", !checking);
            // результаты по сайтам: две колонки по Rows строк, в последней ячейке — сколько открывается
            bool forThis = check != null && checkSet == dnsSet;
            using (var fn = Pt(fMed, 9.5f))
            using (var fs = Pt(fBold, 8f))
            {
                for (int i = 0; i <= Probe.Host.Length; i++)
                {
                    int col = i / Rows;
                    float x = card.X + 18 + col * ColW, y = card.Y + 82 + (i % Rows) * RowH;
                    if (i == Probe.Host.Length)
                    {
                        if (forThis)
                            using (var b = new SolidBrush(Soft))
                                g.DrawString("Открывается " + Probe.Good(check) + " из " + check.Length, fs, b, x, y + 2);
                        break;
                    }
                    string r = forThis ? check[i] : null;
                    using (var b = new SolidBrush(r == null ? Color.FromArgb(70, 70, 88) : ResultColor(r, BadDot))) g.FillEllipse(b, x, y + 4, 9, 9);
                    using (var b = new SolidBrush(Light)) g.DrawString(Probe.Label[i], fn, b, x + LabelAt, y);
                    if (r != null)
                        using (var b = new SolidBrush(ResultColor(r, Bad)))
                            g.DrawString(r, fs, b, x + WordAt(col), y + 2);
                }
            }
        }

        // Где в строке результата стоят подпись сайта и слово-результат, от левого края колонки.
        // Вторая колонка шире первой (ColW), и слово в ней стоит дальше: там самая длинная подпись, NotebookLM.
        const int LabelAt = 14;
        static int WordAt(int col) { return col == 0 ? 92 : 100; }

        // «напрямую» — серым: сервис этот сайт не трогает, это не успех и не поломка
        static Color ResultColor(string r, Color bad) { return r == Probe.Ok ? OkGreen : r == Probe.Captcha ? Yellow : r == Probe.Direct ? Muted : bad; }

        // кнопка группы ВКонтакте (или «Скачать версию …», если вышла новая) и подвал
        void DrawFooter(Graphics g)
        {
            rVk = new Rectangle(28, VkY, LW - 56, 50);
            using (var path = RoundPath(rVk, 16))
                if (update != null)
                    using (var b = new SolidBrush(Yellow)) g.FillPath(b, path);
                else
                    using (var b = new LinearGradientBrush(rVk, Color.FromArgb(124, 92, 255), Color.FromArgb(76, 124, 255), LinearGradientMode.Horizontal))
                        g.FillPath(b, path);
            using (var f = Pt(fHead, 11.5f))
            using (var b = new SolidBrush(update != null ? Ink : Color.White))
                g.DrawString(update != null ? "Скачать версию " + update + "  →" : "Наша группа ВКонтакте  →", f, b, rVk, Center);
            using (var fb = Pt(fHead, 13f))
            using (var bb = new SolidBrush(Violet))
                g.DrawString("HB AI", fb, bb, 28, FootY);
            using (var f = Pt(fMed, 9.5f))
            using (var b = new SolidBrush(Muted))
            {
                var t = "vk.com/neiroseti_ai";
                var sz = g.MeasureString(t, f);
                rGroup = new Rectangle((int)(LW - 28 - sz.Width), FootY + 5, (int)sz.Width, (int)sz.Height);
                g.DrawString(t, f, b, rGroup.X, rGroup.Y);
                rBrand = new Rectangle(28, FootY - 2, 110, 30);
            }
        }

        void DrawSmall(Graphics g, Rectangle r, string text, bool enabled)
        {
            Panel(g, r, 10, enabled ? VioletFill : Color.FromArgb(24, 24, 32), enabled ? VioletLine : CardLine);
            using (var f = Pt(fBold, 9f))
            using (var b = new SolidBrush(enabled ? Soft : Muted))
                g.DrawString(text, f, b, r, Center);
        }

        void DrawToggle(Graphics g)
        {
            var r = new RectangleF(rToggle.X, rToggle.Y, rToggle.Width, rToggle.Height);
            if (active || busy)
            {
                float k = (float)(0.5 + 0.5 * Math.Sin(pulse * Math.PI * 2));
                var gr = r; gr.Inflate(28 + 10 * k, 28 + 10 * k);
                Glow(g, gr, Color.FromArgb((int)(busy ? 60 : 90 + 40 * k), active ? Yellow : Violet));
            }
            // кольцо
            using (var b = new SolidBrush(active ? Yellow : CardBg)) g.FillEllipse(b, r);
            using (var pen = new Pen(active ? Yellow : Color.FromArgb(70, 70, 88), 3f)) g.DrawEllipse(pen, r);
            if (busy)
            {
                using (var pen = new Pen(Violet, 5f) { StartCap = LineCap.Round, EndCap = LineCap.Round })
                {
                    var ar = r; ar.Inflate(-10, -10);
                    g.DrawArc(pen, ar, pulse * 360f, 90f);
                }
            }
            // значок питания; размеры заданы для кнопки 200×200 и уменьшаются вместе с ней
            float z = r.Width / 200f;
            var c = new PointF(r.X + r.Width / 2, r.Y + r.Height / 2 - 14 * z);
            using (var pen = new Pen(active ? Ink : Color.White, 7f * z) { StartCap = LineCap.Round, EndCap = LineCap.Round })
            {
                g.DrawArc(pen, c.X - 32 * z, c.Y - 32 * z, 64 * z, 64 * z, -60, 300);
                g.DrawLine(pen, c.X, c.Y - 40 * z, c.X, c.Y - 6 * z);
            }
            using (var f = Pt(fHead, 13f * z))
            using (var b = new SolidBrush(active ? Ink : Soft))
            {
                string t = active ? "ВКЛ" : "ВЫКЛ";
                var sz = g.MeasureString(t, f);
                g.DrawString(t, f, b, c.X - sz.Width / 2, r.Y + r.Height - 62 * z);
            }
        }

        static void Glow(Graphics g, RectangleF r, Color c)
        {
            using (var path = new GraphicsPath())
            {
                path.AddEllipse(r);
                using (var pb = new PathGradientBrush(path))
                {
                    pb.CenterColor = c;
                    pb.SurroundColors = new[] { Color.FromArgb(0, c) };
                    g.FillEllipse(pb, r);
                }
            }
        }

        void Centered(Graphics g, string s, Font f, Brush b, float y, float maxW = 0)
        {
            float w = maxW > 0 ? maxW : LW;
            using (var sf = new StringFormat { Alignment = StringAlignment.Center })
                g.DrawString(s, f, b, new RectangleF((LW - w) / 2, y, w, 40), sf);
        }

        void OnDown(object s, MouseEventArgs e)
        {
            dragging = false;
            if (e.Button != MouseButtons.Left) return;
            var lp = ToLogical(e.Location);
            if (rClose.Contains(lp)) { Close(); return; }
            if (rMin.Contains(lp)) { WindowState = FormWindowState.Minimized; return; }
            if (rGroup.Contains(lp)) { Open("https://vk.com/neiroseti_ai"); return; }
            if (rSite.Contains(lp)) { Open(Dns.Url[dnsSet]); return; }
            if (rVk.Contains(lp) && update != null) { Open(Updates.Page); return; }
            if (rBrand.Contains(lp) || rVk.Contains(lp)) { Open("https://vk.com/neiroseti_ai"); return; }
            if (InToggle(lp)) { Toggle(); return; }
            for (int k = 0; k < Dns.Count; k++)
                if (rSeg[k].Contains(lp)) { PickSet(k); return; }
            if (rCheck.Contains(lp)) { RunCheck(dnsSet); return; }
            if (rBest.Contains(lp)) { RunBest(); return; }
            dragging = true;
            dragFrom = e.Location;
        }

        void OnMove(object s, MouseEventArgs e)
        {
            Cursor = OverControl(ToLogical(e.Location)) && !busy && !dragging ? Cursors.Hand : Cursors.Default;
            if (dragging && e.Button == MouseButtons.Left)
                Location = new Point(Location.X + e.X - dragFrom.X, Location.Y + e.Y - dragFrom.Y);
        }

        bool InToggle(Point lp)
        {
            var c = new Point(rToggle.X + rToggle.Width / 2, rToggle.Y + rToggle.Height / 2);
            double dx = lp.X - c.X, dy = lp.Y - c.Y;
            return dx * dx + dy * dy <= rToggle.Width * rToggle.Width / 4.0;
        }

        bool OverControl(Point lp)
        {
            return InToggle(lp) || rSeg.Any(r => r.Contains(lp))
                || new[] { rClose, rMin, rGroup, rSite, rBrand, rVk, rCheck, rBest }.Any(r => r.Contains(lp));
        }

        // через проводник: браузер запустится с правами пользователя, а не администратора, как сама программа
        static void Open(string url) { try { Process.Start("explorer.exe", "\"" + url + "\""); } catch { } }

        // смена набора: если DNS уже включён, сразу переключаем адреса
        void PickSet(int k)
        {
            if (busy || k == dnsSet) return;
            dnsSet = k;
            if (active) Apply(true); else Invalidate();
        }

        void Toggle()
        {
            if (busy) return;
            Apply(!active);
        }

        // проверить выбранный сервис: DNS сервиса → прокси → сайт
        void RunCheck(int set)
        {
            if (checking) return;
            checking = true; checkSet = set; check = null; bestNote = null; Invalidate();
            ThreadPool.QueueUserWorkItem(_ =>
            {
                string[] res = null;
                try { res = Probe.Service(set); }
                catch (Exception) { }   // сбой внутри проверки: карточка остаётся пустой, программа работает дальше
                Ui(() =>
                {
                    checking = false; check = res; checkSet = set;
                    if (res == null) bestNote = "Проверка не удалась, попробуйте ещё раз";
                    Invalidate();
                });
            });
        }

        // перебрать все сервисы для нейросетей и выбрать тот, где открывается больше всего
        void RunBest()
        {
            if (checking) return;
            checking = true; checkSet = -2; check = null; bestNote = null; Invalidate();
            int current = dnsSet;
            bool wasActive = active;
            ThreadPool.QueueUserWorkItem(_ =>
            {
                var all = new string[Dns.Count][];
                var real = Probe.Once(Probe.Real);
                var sets = Enumerable.Range(0, Dns.Count).Where(k => k != Dns.XboxSet).ToArray();
                // сбой внутри проверки одного сервиса: он остаётся непроверенным и лучшим не станет
                try { Probe.Together(sets.Length, n => all[sets[n]] = Probe.Service(sets[n], real)); }
                catch (Exception) { }
                int top = Probe.Best(all, -1);
                Ui(() =>
                {
                    // Пока шёл поиск, человек мог сменить сервис, включить или выключить DNS. Тогда DNS не трогаем,
                    // в карточке оставляем выбранный сервис и просто называем лучший.
                    bool moved = busy || dnsSet != current || active != wasActive;
                    // включённый сервис из-за одного сайта не меняем: см. Probe.Best
                    int best = moved ? top : Probe.Best(all, current, active ? 2 : 1);
                    int show = moved ? dnsSet : best;
                    checking = false; check = all[show]; checkSet = show;
                    string note = Probe.BestNote(all, best, top);
                    // если не открывает ни один — DNS не трогаем
                    if (!moved && Probe.Good(all[best]) > 0 && best != dnsSet)
                    {
                        dnsSet = best;
                        if (active) { Apply(true, note); return; }
                    }
                    bestNote = note;
                    Invalidate();
                });
            });
        }

        // note — подпись, которую показать вместо обычной (её ставит «Найти лучший», он же уже всё проверил)
        void Apply(bool turnOn, string note = null)
        {
            busy = true; error = null; bestNote = note; Invalidate();
            int set = dnsSet;
            ThreadPool.QueueUserWorkItem(_ =>
            {
                string err;
                try { err = turnOn ? Dns.Enable(set) : Dns.Disable(); }
                catch (Exception ex) { err = ex.Message; }
                int now = WaitFor(turnOn, set);
                bool done = Reached(turnOn, set, now);
                string msg = Outcome(turnOn, done, err, Dns.IsAdmin());
                Ui(() =>
                {
                    busy = false;
                    active = now >= 0;
                    stale = !active && Dns.StaleActive();
                    if (active) dnsSet = now;
                    error = msg;
                    Invalidate();
                    if (done && turnOn && note == null) RunCheck(set);
                });
            });
        }

        // Windows обновляет список DNS у подключения не мгновенно — ждём до трёх секунд
        static int WaitFor(bool turnOn, int set)
        {
            int now = -1;
            for (int i = 0; i < 5 && !Reached(turnOn, set, now); i++) { Thread.Sleep(600); now = Dns.ActiveSet(); }
            return now;
        }

        // встал ли нужный сервис (или, при выключении, никакой)
        internal static bool Reached(bool turnOn, int set, int now) { return turnOn ? now == set : now < 0; }

        // что написать после включения или выключения; null — всё хорошо.
        // Сбой при смене сервиса на включённом DNS тоже виден: «встал» сверяется с нужным сервисом, а не с «включён/выключен».
        internal static string Outcome(bool turnOn, bool done, string err, bool admin)
        {
            if (done) return err == null ? null : (turnOn ? "DNS включён, но: " : "DNS выключен, но: ") + FirstLine(err);
            if (!admin) return "Не получилось: запустите от имени администратора";
            return err != null ? "Не получилось поменять DNS: " + FirstLine(err) : "Не получилось поменять DNS, попробуйте ещё раз";
        }

        static string FirstLine(string s)
        {
            s = s.Split('\n')[0].Trim();
            return s.Length > 70 ? s.Substring(0, 70) + "…" : s;
        }

        // Фоновые потоки возвращают результат в окно. Если окно уже закрыли, BeginInvoke бросает исключение
        // в потоке пула, и программа падает с отчётом об ошибке — поэтому проверяем и глушим именно этот случай.
        void Ui(Action a)
        {
            try { if (IsHandleCreated && !IsDisposed) BeginInvoke(a); }
            catch (InvalidOperationException) { }
        }
    }

    // Новая версия: GitHub отвечает на /releases/latest переадресацией на /releases/tag/vX.YY — из неё берём номер.
    // Без API и без ключей, один запрос при запуске; не получилось — молчим.
    static class Updates
    {
        public const string Page = "https://github.com/neiroseti-ai/hb-ai-xbox-dns/releases/latest";

        // номер версии из адреса переадресации; null — адрес не про релиз
        public static string TagOf(string location)
        {
            if (location == null) return null;
            int i = location.LastIndexOf("/tag/v", StringComparison.Ordinal);
            return i < 0 ? null : location.Substring(i + 6).Trim();
        }

        // новее ли версия: номера сравниваются как десятичные дроби (1.21 < 1.22 < 1.3), как их и выпускаем
        public static bool IsNewer(string latest, string current)
        {
            decimal a, b;
            var ci = System.Globalization.CultureInfo.InvariantCulture;
            return decimal.TryParse(latest, System.Globalization.NumberStyles.AllowDecimalPoint, ci, out a)
                && decimal.TryParse(current, System.Globalization.NumberStyles.AllowDecimalPoint, ci, out b) && a > b;
        }

        // номер новой версии или null
        public static string Newer(string current)
        {
            try
            {
                System.Net.ServicePointManager.SecurityProtocol |= System.Net.SecurityProtocolType.Tls12;
                var rq = (System.Net.HttpWebRequest)System.Net.WebRequest.Create(Page);
                rq.Method = "HEAD"; rq.AllowAutoRedirect = false; rq.Timeout = 8000; rq.UserAgent = "HB-AI-Smart-DNS/" + MainForm.Version;
                using (var rs = (System.Net.HttpWebResponse)rq.GetResponse())
                {
                    string v = TagOf(rs.Headers["Location"]);
                    return v != null && IsNewer(v, current) ? v : null;
                }
            }
            catch { return null; }
        }
    }

    static class Program
    {
        [STAThread]
        static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            // проверка разметки при другом масштабе экрана: --shot 1.5 out.png (DNS не трогает)
            if (args.Length == 3 && args[0] == "--shot")
            {
                MainForm.ForceScale = float.Parse(args[1], System.Globalization.CultureInfo.InvariantCulture);
                using (var f = new MainForm())
                using (var bmp = f.Snapshot())
                    bmp.Save(args[2], System.Drawing.Imaging.ImageFormat.Png);
                return;
            }
            Application.Run(new MainForm());
        }
    }
}
