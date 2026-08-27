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

Rangordna fynden och motivera ordningen med allvarlighetsgrad, exponering och utnyttjbarhet. Vilket tar du först och varför?

*Skriv här.*

---

## 4. Åtgärder (minst tre)

Använd mönstret nedan per åtgärdat fynd. Varje åtgärd ska gå att spåra tillbaka till ett fynd i tabellen ovan, och beviset efter ska vara en **ny körning av verktyget**, inte din egen kod.

### Åtgärd 1

```
Fynd:        (nr och regel-id/alert från tabellen ovan)
Plats:       (fil och rad, eller URL)
Bevis före:  (skärmbild eller rapportutdrag som visar fyndet)
Bedömning:   (verkligt eller falskt positivt, kort motiverat)
Åtgärd:      (vad du ändrade, med commit-hash)
Bevis efter: (ny körning: CodeQL-alerten står som Fixed, eller ZAP-larmet är borta ur den nya rapporten)
```

### Åtgärd 2

```
Fynd:
Plats:
Bevis före:
Bedömning:
Åtgärd:
Bevis efter:
```

### Åtgärd 3

```
Fynd:
Plats:
Bevis före:
Bedömning:
Åtgärd:
Bevis efter:
```

---

## 5. Eventuella bortval

Om du valt att inte åtgärda ett fynd, skriv ned tre saker per bortval: risken, motivet och den kompenserande kontrollen. Sätt gärna ett datum för omprövning.

*Skriv här, eller skriv "inga bortval".*
