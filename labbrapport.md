# Labbrapport: praktisk laboration

*Kunskapskontroll 2, IT-säkerhet för utvecklare. Fyll i mallen och lämna in som PDF tillsammans med länken till ditt repo. Riktlängd två till tre sidor.*

**Namn:** Hamze Osman
**Datum:** 2026-08-27
**Repo (länk till din fork):** https://github.com/Hamzeosman/SakerLabb/tree/losning-hamze
**Applikation som analyserades:** SakerLabb.Web – en medvetet sårbar ärendehanteringsapplikation (Blazor Server, .NET 10)

---

## 1. Kort om applikationen och analysen

SakerLabb.Web är en medvetet sårbar webbapplikation byggd i Blazor Server (.NET 10) som simulerar ett enkelt ärendehanteringssystem med inloggning, ärenden, filbilagor, import och administrationsfunktioner. Applikationen analyserades på två sätt: statiskt med CodeQL (GitHub Advanced Security, default setup, språk C#) mot huvudgrenen (`main`), och dynamiskt med OWASP ZAP 2.17 (Automated Scan: spider följt av aktiv skanning, "Dev Standard"-policy) mot en lokal instans som kördes med `dotnet run` på `http://localhost:5080`. CodeQL-skanningen gav 36 öppna larm; ZAP:s automatiserade skanning gav 17 unika larmtyper.

---

## 2. Fem fynd

Fyll i tabellen. Minst ett fynd ska komma från statisk analys (CodeQL) och minst ett från dynamisk analys (ZAP). Spara bevis i form av skärmbild eller rapportutdrag och hänvisa till det per fynd.

| Nr | Källa (CodeQL/ZAP) | Regel-id eller alert | Allvarlighet (+ confidence för ZAP) | Fil och rad eller URL | Verkligt eller falskt positivt | Motivering (2–4 meningar) |
|----|--------------------|----------------------|-------------------------------------|-----------------------|--------------------------------|---------------------------|
| 1 | CodeQL | SQL query built from user-controlled sources | High | `SakerLabb.Web/Data/UserRepository.cs:62` | Verkligt | Frågan byggs via strängsammanslagning av `username` utan parametrisering. Bekräftas dynamiskt via en manuell ZAP-testrequest: en `'` i `username`-fältet mot `/account/reset/start` utlöste en `SqliteException` med fullständig stacktrace som pekar på samma metod (`UserRepository.StartPasswordReset`, rad 63). |
| 2 | CodeQL | Untrusted XML read insecurely (XXE) | Critical | `SakerLabb.Web/Services/ImportService.cs:27` | Verkligt | XML-parsern läser extern/DTD-innehåll okontrollerat, vilket möjliggör XXE (t.ex. läsning av lokala filer eller SSRF via externa entiteter). |
| 3 | ZAP | Remote OS Command Injection (CWE-78) | High (Confidence: Medium) | `http://localhost:5080/diagnostik/ping?host=...` | Verkligt | Parametern `host` skickas okontrollerat till ett OS-kommando. Payload `localhost&type %SYSTEMROOT%\win.ini` fick servern att returnera innehållet i `win.ini` — definitivt bevis på kommandoinjektion. |
| 4 | ZAP | Cross Site Scripting (Reflected) (CWE-79) | High (Confidence: Medium) | `http://localhost:5080/account/login` | Verkligt | `username`-parametern reflekteras oencodat i felmeddelandet. Payload `</div><scrIpt>alert(1);</scRipt><div>` syns rått i svaret. Motsvarar CodeQL-fyndet i `Login.razor:10`. |
| 5 | ZAP | Content Security Policy (CSP) Header Not Set (Systemic) (CWE-693) | Medium (Confidence: High) | `http://localhost:5080/` (systemomfattande) | Verkligt | Ingen CSP-header sätts någonstans i appen, vilket försvagar skyddet mot XSS/data-injektion om andra kontroller kringgås. |

Bevis (skärmbilder eller utdrag), numrerade efter fyndet ovan:

1. Skärmbild av CodeQL-larmet `SQL query built from user-controlled sources` (alert #8, `UserRepository.cs:62`) från Security → Code scanning, **plus** skärmbild av ZAP:s "SQL Injection"-larm (URL, Risk, Confidence, Evidence-panelen med SqliteException-stacktracen mot `/account/reset/start`).
2. Skärmbild av CodeQL-larmet `Untrusted XML is read insecurely` (alert #20, `ImportService.cs:27`).
3. Skärmbild av ZAP:s "Remote OS Command Injection"-larm inkl. Request/Response-panelen som visar `win.ini`-innehållet i svaret.
4. Skärmbild av ZAP:s "Cross Site Scripting (Reflected)"-larm inkl. Response-panelen där payloaden syns i felmeddelandet, **plus** ev. skärmbild av CodeQL-larmet i `Login.razor:10`.
5. Skärmbild av ZAP:s "Content Security Policy (CSP) Header Not Set"-larm (detaljpanelen).

---

## 3. Prioritering

Fynden rangordnas efter en kombination av allvarlighetsgrad, exponering (kräver autentisering eller ej) och hur lätt de faktiskt är att utnyttja i praktiken:

1. **Remote OS Command Injection (fynd 3)** — Rankas högst trots att den formella allvarlighetsgraden (High) är lägre än XXE-fyndets. Ändpunkten `/diagnostik/ping` nås utan autentisering, och ZAP bevisade konkret, direkt utnyttjbarhet genom att läsa ut innehållet i `win.ini` från servern. Exponering och bevisad utnyttjbarhet väger tyngre här än severity-etiketten.
2. **Untrusted XML is read insecurely / XXE (fynd 2)** — Critical allvarlighetsgrad; kan leda till läsning av godtyckliga filer på servern eller SSRF via externa XML-entiteter. Kräver sannolikt en inloggad session mot importfunktionen, vilket sänker exponeringen något jämfört med fynd 3 — men den potentiella skadan vid lyckat utnyttjande är störst av alla fem fynd.
3. **SQL Injection (fynd 1)** — Nås utan autentisering via lösenordsåterställningsflödet (`/account/reset/start`) och är bevisat utnyttjningsbar (databasfel med fullständig stacktrace läcker till klienten). Risk för dataexfiltrering eller kontokapning.
4. **Cross-Site Scripting, reflected (fynd 4)** — Kräver att en användare luras att klicka en preparerad länk (socialt ingenjörskap), vilket gör den svårare att utnyttja i praktiken än fynd 1–3, trots samma severity-etikett (High).
5. **CSP-header saknas (fynd 5)** — Medium allvarlighetsgrad och inte självständigt utnyttjningsbar. En försvar-på-djupet-kontroll som gör andra attacker (t.ex. XSS) svårare att genomföra om de ändå lyckas.

Jag åtgärdar fynd 3, 2 och 1 i den ordningen i avsnitt 4, eftersom de representerar den högsta kombinationen av allvarlighetsgrad och exponering. Fynd 4 och 5 lämnas som bortval med kompenserande kontroller (se avsnitt 5).

---

## 4. Åtgärder (minst tre)

Använd mönstret nedan per åtgärdat fynd. Varje åtgärd ska gå att spåra tillbaka till ett fynd i tabellen ovan, och beviset efter ska vara en **ny körning av verktyget**, inte din egen kod.

### Åtgärd 1

```
Fynd:        3 – Remote OS Command Injection (ZAP, CWE-78)
Plats:       SakerLabb.Web/Services/ImportService.cs, Ping-metoden (tidigare rad 57); http://localhost:5080/diagnostik/ping
Bevis före:  ZAP-larm "Remote OS Command Injection", Risk: High, Confidence: Medium. Payload localhost&type %SYSTEMROOT%\win.ini gav [fonts]/[extensions]/... (innehållet i win.ini) i svaret. Se skärmbild, fynd 3.
Bedömning:   Verkligt (se motivering i tabellen ovan).
Åtgärd:      Bytte bort cmd.exe /c-skalanropet mot direkt anrop av ping.exe med ProcessStartInfo.ArgumentList (ingen skalparsning av &, |, etc.), samt lade till en allowlist-regex (^[a-zA-Z0-9.-]{1,253}$) för host-parametern. Commit: 30f131d.
Bevis efter: Samma request (GET /diagnostik/ping?host=localhost&type=%SYSTEMROOT%\win.ini) återskickad i ZAP:s Requester mot den ombyggda appen ger nu HTTP 500 med System.ArgumentException: "Ogiltigt värde för host." (Parameter 'host') från ImportService.Ping, rad 54 — payloaden avvisas av allowlist-kontrollen i stället för att läcka win.ini-innehåll. CodeQL-alert #14 ("Uncontrolled command line", samma rad) bekräftar detta ytterligare. Se skärmbild.
```

### Åtgärd 2

```
Fynd:        2 – Untrusted XML is read insecurely / XXE (CodeQL #20, Critical)
Plats:       SakerLabb.Web/Services/ImportService.cs, ImportXml-metoden (tidigare rad 27)
Bevis före:  CodeQL-larm #20 "Untrusted XML is read insecurely", Critical, ImportService.cs:27. Se skärmbild, fynd 2.
Bedömning:   Verkligt.
Åtgärd:      DtdProcessing.Parse → DtdProcessing.Prohibit, samt XmlResolver satt till null i både XmlReaderSettings och XmlDocument (i stället för new XmlUrlResolver()), vilket blockerar upplösning av externa entiteter/DTD:er. Commit: 30f131d.
Bevis efter: CodeQL-alert #20 (https://github.com/Hamzeosman/SakerLabb/security/code-scanning/20) visar nu statusen Fixed på branch main, "Fixed 8 minuter sedan via pull request #3" (merge-commit 323d212). Se skärmbild.
```

### Åtgärd 3

```
Fynd:        1 – SQL query built from user-controlled sources (CodeQL #8, High)
Plats:       SakerLabb.Web/Data/UserRepository.cs, StartPasswordReset-metoden (tidigare rad 62 och 72)
Bevis före:  CodeQL-larm #8, High, UserRepository.cs:62. Bekräftat dynamiskt av ZAP: en ' i username-fältet mot /account/reset/start gav en SqliteException med fullständig stacktrace. Se skärmbild, fynd 1.
Bedömning:   Verkligt.
Åtgärd:      Bytte de strängsammanslagna frågorna mot parametriserade frågor (@Username, @Token) via SqliteCommand.Parameters.AddWithValue. Commit: b783e17.
Bevis efter: CodeQL-alert #8 (https://github.com/Hamzeosman/SakerLabb/security/code-scanning/8) visar nu statusen Fixed på branch main, "Fixed 8 minuter sedan via pull request #3" (merge-commit 323d212). Se skärmbild. Dynamisk bekräftelse med ZAP (samma request som i "bevis före") görs som komplement.
```

---

## 5. Eventuella bortval

**Fynd 4 – Cross-Site Scripting (Reflected), Login.razor**
- Risk: En angripare kan lura en användare att klicka en preparerad länk och därmed köra JavaScript i offrets webbläsarkontext (t.ex. sessionskapning eller phishing).
- Motiv: Prioriterades ner eftersom den kräver socialt ingenjörskap (offret måste aktivt klicka en länk), till skillnad från fynd 1–3 som kan utnyttjas direkt mot servern utan medverkan från ett offer.
- Kompenserande kontroll: Ingen CSP-header är på plats ännu (se fynd 5), men manuell kodgranskning har bekräftat att det är just `@((MarkupString)(Username ?? ""))` i `Login.razor` som orsakar problemet — en enkel engångsåtgärd (ta bort `MarkupString`-castet) planeras.
- Omprövningsdatum: 2026-09-10.

**Fynd 5 – Content Security Policy (CSP) Header Not Set (Systemic)**
- Risk: Utan CSP får andra sårbarheter (t.ex. fynd 4) större genomslag om de ändå utnyttjas, eftersom webbläsaren inte har något extra skyddslager mot inline-skript eller okända skriptkällor.
- Motiv: Medium allvarlighetsgrad, inte självständigt utnyttjningsbar, och kräver en bredare middleware-ändring som påverkar hela applikationens resursladdning (risk för regressioner) — prioriterades därför ner till efter de tre högre fynden.
- Kompenserande kontroll: Ingen CSP är implementerad än. Tills dess granskas manuellt var i koden användarinmatning renderas oescapead.
- Omprövningsdatum: 2026-09-10.
